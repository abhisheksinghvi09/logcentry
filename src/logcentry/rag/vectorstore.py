"""
LogCentry RAG - Vector Store

ChromaDB-based vector database for storing and retrieving embeddings.
"""

from pathlib import Path
from typing import Any

from logcentry.config import get_cached_settings
from logcentry.core.models import RAGDocument
from logcentry.utils import get_logger

logger = get_logger(__name__)


class VectorStore:
    """
    ChromaDB-based vector store for RAG retrieval.
    
    Provides:
    - Document storage with embeddings
    - Semantic similarity search
    - Collection management
    """
    
    def __init__(
        self,
        collection_name: str = "logcentry_knowledge",
        persist_directory: str | Path | None = None,
    ):
        """
        Initialize the vector store.
        
        Args:
            collection_name: Name of the ChromaDB collection
            persist_directory: Path to persist the database (None for in-memory)
        """
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
        except ImportError:
            raise RuntimeError(
                "chromadb is required for RAG. Install with: pip install chromadb"
            )
        
        settings = get_cached_settings()
        
        if persist_directory is None:
            persist_directory = settings.vector_db_path
        
        persist_path = Path(persist_directory)
        persist_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("initializing_vector_store", path=str(persist_path))
        
        # Initialize ChromaDB client
        self._client = chromadb.PersistentClient(
            path=str(persist_path),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        
        # Get or create collection
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "LogCentry knowledge base"},
        )
        
        logger.info(
            "vector_store_ready",
            collection=collection_name,
            document_count=self._collection.count(),
        )
    
    def add_document(
        self,
        doc_id: str,
        content: str,
        embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Add a single document to the store.
        
        Args:
            doc_id: Unique document identifier
            content: Document text content
            embedding: Pre-computed embedding vector
            metadata: Optional metadata dictionary
        """
        self._collection.add(
            ids=[doc_id],
            documents=[content],
            embeddings=[embedding],
            metadatas=[metadata or {}],
        )
    
    def add_documents(
        self,
        documents: list[RAGDocument],
    ) -> None:
        """
        Add multiple documents to the store.
        
        Args:
            documents: List of RAGDocument objects (must have embeddings)
        """
        if not documents:
            return
        
        ids = []
        contents = []
        embeddings = []
        metadatas = []
        
        for doc in documents:
            if doc.embedding is None:
                logger.warning("document_missing_embedding", doc_id=doc.id)
                continue
            
            ids.append(doc.id)
            contents.append(doc.content)
            embeddings.append(doc.embedding)
            metadatas.append(doc.metadata)
        
        if ids:
            self._collection.add(
                ids=ids,
                documents=contents,
                embeddings=embeddings,
                metadatas=metadatas,
            )
            logger.info("documents_added", count=len(ids))
    
    def search(
        self,
        query_embedding: list[float],
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for similar documents.
        
        Args:
            query_embedding: Query embedding vector
            n_results: Number of results to return
            where: Optional filter conditions
            
        Returns:
            List of result dicts with 'content', 'metadata', 'distance'
        """
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
        
        # Flatten results (query returns lists of lists)
        output = []
        
        if results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                output.append({
                    "content": doc,
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0,
                })
        
        return output
    
    def search_by_text(
        self,
        query_text: str,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search using text query (embedding generated automatically).
        
        Args:
            query_text: Query text
            n_results: Number of results
            where: Optional filters
            
        Returns:
            List of similar documents
        """
        from logcentry.rag.embeddings import embed_text
        
        query_embedding = embed_text(query_text)
        return self.search(query_embedding, n_results, where)
    
    def delete_document(self, doc_id: str) -> None:
        """Delete a document by ID."""
        self._collection.delete(ids=[doc_id])
    
    def clear(self) -> None:
        """Clear all documents from the collection."""
        # ChromaDB doesn't have a clear method, so we delete and recreate
        collection_name = self._collection.name
        self._client.delete_collection(collection_name)
        self._collection = self._client.create_collection(
            name=collection_name,
            metadata={"description": "LogCentry knowledge base"},
        )
        logger.info("collection_cleared", name=collection_name)
    
    @property
    def count(self) -> int:
        """Get the number of documents in the store."""
        return self._collection.count()
