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
        """Reads markdown runbooks, builds TF-IDF term vectors, and indexes documents into memory."""
        self.documents = []
        self._doc_vectors = []
        self._idf_vector: Dict[str, float] = {}
        self._query_cache.clear()
        pattern = os.path.join(self.knowledge_base_dir, "**", "*.md")
        
        raw_docs = []
        doc_freq: Dict[str, int] = {}
        
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    filename = os.path.basename(filepath)
                    tokens = self._tokenize(content)
                    unique_tokens = set(tokens)
                    for token in unique_tokens:
                        doc_freq[token] = doc_freq.get(token, 0) + 1

                    raw_docs.append({
                        "filename": filename,
                        "filepath": filepath,
                        "content": content,
                        "tokens": tokens,
                        "unique_tokens": unique_tokens
                    })
            except Exception as e:
                logger.error(f"Error loading RAG document {filepath}: {e}")

        total_docs = len(raw_docs)
        if total_docs == 0:
            logger.warning("No knowledge documents found in knowledge base directory.")
            return

        # Compute IDF values: idf(t) = log(N / (df(t) + 1)) + 1
        for term, df in doc_freq.items():
            self._idf_vector[term] = math.log(total_docs / float(df + 1)) + 1.0

        # Compute normalized TF-IDF vector for each document
        for doc in raw_docs:
            tokens = doc["tokens"]
            total_tokens = max(len(tokens), 1)
            tf_counts: Dict[str, float] = {}
            for token in tokens:
                tf_counts[token] = tf_counts.get(token, 0.0) + 1.0

            tfidf_vec: Dict[str, float] = {}
            vector_length_sq = 0.0
            for term, count in tf_counts.items():
                tf = count / total_tokens
                idf = self._idf_vector.get(term, 1.0)
                tfidf_val = tf * idf
                tfidf_vec[term] = tfidf_val
                vector_length_sq += tfidf_val * tfidf_val

            # L2 Normalize vector
            norm = math.sqrt(vector_length_sq) or 1.0
            norm_vec = {k: v / norm for k, v in tfidf_vec.items()}

            self.documents.append({
                "filename": doc["filename"],
                "filepath": doc["filepath"],
                "content": doc["content"],
                "tokens": doc["unique_tokens"]
            })
            self._doc_vectors.append(norm_vec)

        logger.info(f"RAG Engine indexed {len(self.documents)} knowledge documents with mathematical TF-IDF term vectors.")

    def search_runbooks(self, query: str, top_k: int = 2) -> str:
        """
        Performs mathematical TF-IDF vector cosine similarity search + domain keyword scoring.
        Uses query caching for sub-millisecond document retrieval.
        """
        cache_key = f"{query.strip().lower()}_top_{top_k}"
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        query_tokens = self._tokenize(query)
        if not query_tokens or not self.documents:
            fallback = self.documents[0]["content"] if self.documents else "No runbooks available."
            return fallback

        # Compute normalized query TF-IDF vector
        total_q = len(query_tokens)
        q_tf: Dict[str, float] = {}
        for token in query_tokens:
            q_tf[token] = q_tf.get(token, 0.0) + 1.0

        q_vec: Dict[str, float] = {}
        q_len_sq = 0.0
        for term, count in q_tf.items():
            tf = count / total_q
            idf = self._idf_vector.get(term, 1.0)
            val = tf * idf
            q_vec[term] = val
            q_len_sq += val * val

        q_norm = math.sqrt(q_len_sq) or 1.0
        q_norm_vec = {k: v / q_norm for k, v in q_vec.items()}

        matched_docs: List[Tuple[float, dict]] = []

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
            doc_vec = self._doc_vectors[idx]
            
            # Compute Cosine Similarity dot product between query and document vectors
            cosine_similarity = sum(q_norm_vec[term] * doc_vec[term] for term in q_norm_vec if term in doc_vec)
            score = cosine_similarity * 100.0

            fname = doc["filename"].lower()

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

        matched_docs.sort(key=lambda x: x[0], reverse=True)
        top_docs = [doc["content"] for score, doc in matched_docs[:top_k]]

        if not top_docs and self.documents:
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


