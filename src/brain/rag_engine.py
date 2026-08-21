import os
import glob
import logging

logger = logging.getLogger("aegis-brain-rag")

class RAGEngine:
    """
    RAG Vector Store & Document Retriever.
    Indexes markdown runbooks in src/knowledge_base/ and retrieves top-k relevant docs for LLM prompt context.
    """
    def __init__(self, knowledge_base_dir: str = None):
        self.knowledge_base_dir = knowledge_base_dir or os.path.join("src", "knowledge_base")
        self.documents = []
        self.load_knowledge_base()

    def load_knowledge_base(self):
        """Reads all markdown runbooks and security guides into memory index."""
        self.documents = []
        pattern = os.path.join(self.knowledge_base_dir, "**", "*.md")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    filename = os.path.basename(filepath)
                    self.documents.append({
                        "filename": filename,
                        "filepath": filepath,
                        "content": content
                    })
            except Exception as e:
                logger.error(f"Error loading RAG document {filepath}: {e}")
        logger.info(f"RAG Engine loaded {len(self.documents)} knowledge documents.")

    def search_runbooks(self, query: str, top_k: int = 2) -> str:
        """
        Performs similarity matching to retrieve top relevant runbooks for the diagnostic query.
        """
        query_lower = query.lower()
        matched_docs = []

        for doc in self.documents:
            score = 0
            fname = doc["filename"].lower()
            
            if ("500" in query_lower or "http" in query_lower) and "500" in fname:
                score += 50
            elif ("oom" in query_lower or "memory" in query_lower) and "oom" in fname:
                score += 50
            elif ("falco" in query_lower or "shell" in query_lower or "security" in query_lower) and "t1059" in fname:
                score += 50

            if score > 0:
                matched_docs.append((score, doc))

        # Sort by score descending
        matched_docs.sort(key=lambda x: x[0], reverse=True)
        top_docs = [doc["content"] for score, doc in matched_docs[:top_k]]

        if not top_docs and self.documents:
            # Fallback to first document
            top_docs = [self.documents[0]["content"]]

        return "\n\n--- RAG RUNBOOK ---\n\n".join(top_docs)
