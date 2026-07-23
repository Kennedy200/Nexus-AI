"""
Nexus AI — Vector Database Layer
ChromaDB with persistent storage for semantic log search.
"""
import chromadb
from chromadb.config import Settings as ChromaSettings
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Optional
import os
import hashlib
from config import settings


class VectorStore:
    """Production vector store for log semantic search."""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if VectorStore._initialized:
            return

        self.db_path = os.path.abspath(settings.chroma_db_path)
        os.makedirs(self.db_path, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=self.db_path,
            settings=ChromaSettings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

        self.collection = self.client.get_or_create_collection(
            name="security_logs",
            metadata={"hnsw:space": "cosine"}
        )

        self.embedding_model = SentenceTransformer(settings.embedding_model)
        self.embedding_dim = self.embedding_model.get_sentence_embedding_dimension()

        VectorStore._initialized = True
        print(f"[VectorStore] Initialized | Collection: security_logs | Dim: {self.embedding_dim}")

    def _generate_id(self, content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()

    def _chunk_text(self, text: str, chunk_size: int = 512, overlap: int = 128) -> List[str]:
        lines = text.split('\n')
        chunks = []
        current_chunk = []
        current_len = 0

        for line in lines:
            line_len = len(line)
            if current_len + line_len > chunk_size and current_chunk:
                chunks.append('\n'.join(current_chunk))
                overlap_lines = current_chunk[-overlap//50:] if overlap > 0 else []
                current_chunk = overlap_lines + [line]
                current_len = sum(len(l) for l in current_chunk)
            else:
                current_chunk.append(line)
                current_len += line_len

        if current_chunk:
            chunks.append('\n'.join(current_chunk))

        return chunks if chunks else [text[:chunk_size]]

    def add_log(self, log_content: str, metadata: Optional[Dict] = None) -> List[str]:
        chunks = self._chunk_text(log_content)
        doc_ids = []
        documents = []
        metadatas = []

        for i, chunk in enumerate(chunks):
            doc_id = f"{self._generate_id(chunk)}_{i}"
            doc_ids.append(doc_id)
            documents.append(chunk)

            meta = metadata.copy() if metadata else {}
            meta["chunk_index"] = i
            meta["total_chunks"] = len(chunks)
            meta["char_count"] = len(chunk)
            metadatas.append(meta)

        embeddings = self.embedding_model.encode(
            documents,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        ).tolist()

        self.collection.upsert(
            ids=doc_ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )

        return doc_ids

    def search(self, query: str, top_k: int = 5,
               filter_dict: Optional[Dict] = None) -> List[Dict]:
        query_embedding = self.embedding_model.encode(
            query,
            convert_to_numpy=True,
            normalize_embeddings=True
        ).tolist()

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=filter_dict,
            include=["documents", "metadatas", "distances"]
        )

        formatted = []
        if results["ids"] and results["ids"][0]:
            for i in range(len(results["ids"][0])):
                formatted.append({
                    "id": results["ids"][0][i],
                    "content": results["documents"][0][i],
                    "distance": float(results["distances"][0][i]),
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {}
                })

        return formatted

    def get_stats(self) -> Dict:
        count = self.collection.count()
        return {
            "total_documents": count,
            "embedding_model": settings.embedding_model,
            "embedding_dimension": self.embedding_dim,
            "db_path": self.db_path,
            "collection_name": "security_logs"
        }

    def delete_all(self):
        self.client.delete_collection("security_logs")
        self.collection = self.client.get_or_create_collection(
            name="security_logs",
            metadata={"hnsw:space": "cosine"}
        )

    def get_by_id(self, doc_id: str) -> Optional[Dict]:
        try:
            result = self.collection.get(ids=[doc_id], include=["documents", "metadatas"])
            if result["ids"]:
                return {
                    "id": result["ids"][0],
                    "content": result["documents"][0],
                    "metadata": result["metadatas"][0] if result["metadatas"] else {}
                }
        except Exception:
            pass
        return None


vector_store = VectorStore()
