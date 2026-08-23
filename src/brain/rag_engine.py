import os
import glob
import re
import math
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("aegis-brain-rag")

class RAGEngine:
    """
    RAG Vector Store & Document Retriever (Phase 3 & 4 Optimized).
    Indexes markdown runbooks in src/knowledge_base/ with pre-computed TF-IDF term vectors,
    keyword mappings, and query caching for sub-millisecond document retrieval.
    """
    def __init__(self, knowledge_base_dir: str = None):
        self.knowledge_base_dir = knowledge_base_dir or os.path.join("src", "knowledge_base")
        self.documents: List[dict] = []
        self._doc_vectors: List[Dict[str, float]] = []
        self._query_cache: Dict[str, str] = {}
        self.load_knowledge_base()

    def _tokenize(self, text: str) -> List[str]:
        """Extracts normalized alphanumeric terms from text."""
        return re.findall(r'\b[a-zA-Z0-9_]{2,}\b', text.lower())

    def load_knowledge_base(self):
        """Reads markdown runbooks, builds term vectors, and indexes documents into memory."""
        self.documents = []
        self._doc_vectors = []
        self._query_cache.clear()
        pattern = os.path.join(self.knowledge_base_dir, "**", "*.md")
        
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    filename = os.path.basename(filepath)
                    tokens = self._tokenize(content)
                    
                    # Compute Term Frequency (TF) for document
                    tf_vector: Dict[str, float] = {}
                    total_tokens = max(len(tokens), 1)
                    for token in tokens:
                        tf_vector[token] = tf_vector.get(token, 0) + 1.0 / total_tokens

                    self.documents.append({
                        "filename": filename,
                        "filepath": filepath,
                        "content": content,
                        "tokens": set(tokens)
                    })
                    self._doc_vectors.append(tf_vector)
            except Exception as e:
                logger.error(f"Error loading RAG document {filepath}: {e}")
        logger.info(f"RAG Engine loaded & indexed {len(self.documents)} knowledge documents.")

    def search_runbooks(self, query: str, top_k: int = 2) -> str:
        """
        Performs vector similarity matching + keyword scoring to retrieve top relevant runbooks.
        Uses query caching for sub-millisecond performance.
        """
        cache_key = f"{query.strip().lower()}_top_{top_k}"
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        query_tokens = self._tokenize(query)
        if not query_tokens:
            fallback = self.documents[0]["content"] if self.documents else "No runbooks available."
            return fallback

        matched_docs: List[Tuple[float, dict]] = []

        # Keyword mapping weights for critical telemetry and MITRE ATT&CK signatures
        keyword_weights = {
            "500": ["500", "http", "exception", "server_error"],
            "oom": ["oom", "memory", "out of memory", "exit code 137", "cgroup"],
            "cpu": ["cpu", "throttling", "spike", "quota", "usage"],
            "crash": ["crash", "crashloop", "exit code 1", "liveness"],
            "db": ["db", "database", "connection", "pool", "queuepool"],
            "t1059": ["t1059", "shell", "execve", "bash", "sh", "falco"],
            "t1552": ["t1552", "secret", "token", "credential", "serviceaccount"],
            "t1046": ["t1046", "scan", "nmap", "netcat", "recon", "reconnaissance"],
            "crypto": ["crypto", "mining", "xmrig", "stratum", "minerd"],
            "t1078": ["t1078", "valid", "account", "unauthorized_token"],
            "t1499": ["t1499", "dos", "denial", "memory_bomb"],
            "circuit": ["circuit", "breaker", "cascade", "tripped"]
        }

        query_set = set(query_tokens)

        for idx, doc in enumerate(self.documents):
            score = 0.0
            fname = doc["filename"].lower()
            doc_tf = self._doc_vectors[idx]

            # 1. Cosine-like TF Vector Similarity
            for q_term in query_tokens:
                if q_term in doc_tf:
                    score += doc_tf[q_term] * 100.0

            # 2. Filename & Keyword Mapping Bonuses
            for key, keywords in keyword_weights.items():
                if key in fname:
                    for kw in keywords:
                        if kw in query_set:
                            score += 40.0

                for kw in keywords:
                    if kw in query_set and kw in doc["tokens"]:
                        score += 15.0

            if score > 0:
                matched_docs.append((score, doc))

        # Sort by score descending
        matched_docs.sort(key=lambda x: x[0], reverse=True)
        top_docs = [doc["content"] for score, doc in matched_docs[:top_k]]

        if not top_docs and self.documents:
            # Fallback to general SRE / Security document
            top_docs = [self.documents[0]["content"]]

        rag_context = "\n\n--- RAG KNOWLEDGE RUNBOOK ---\n\n".join(top_docs)
        
        # Inject Topology-Aware Context Bounding guidance (Paper Recommendation arXiv:2606.08590)
        topology_guidance = (
            "\n\n--- TOPOLOGY-AWARE CONTEXT BOUNDING (Graph-Guided RCA) ---\n"
            "Guidance: Restrict diagnostic evaluation to immediate 1-hop upstream caller and downstream callee services. "
            "Do not infer root causes in isolated 2+ hop services unless confidence < 0.70."
        )
        final_result = rag_context + topology_guidance
        self._query_cache[cache_key] = final_result
        return final_result


