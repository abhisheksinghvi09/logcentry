"""
LogCentry SDK - Retrievers

RAG retrieval implementations: Vector DB, Hybrid Search, and Local/Offline.
"""

import asyncio
from typing import Any, Optional

from logcentry.sdk.plugins import BaseRetriever


class VectorRetriever(BaseRetriever):
    """
    ChromaDB-based vector retriever.
    
    Uses semantic similarity search over embedded documents.
    """
    
    def __init__(
        self,
        collection_name: str = "logcentry_knowledge",
        persist_directory: Optional[str] = None,
        score_threshold: float = 0.0,
    ):
        """
        Initialize vector retriever.
        
        Args:
            collection_name: ChromaDB collection name
            persist_directory: Path to persist DB (None for default)
            score_threshold: Minimum similarity score to include
        """
        self._collection_name = collection_name
        self._persist_directory = persist_directory
        self._score_threshold = score_threshold
        self._vector_store = None
    
    @property
    def name(self) -> str:
        return "vector_retriever"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["vector", "semantic"]
    
    @property
    def description(self) -> str:
        return "ChromaDB-based semantic similarity retrieval"
    
    def _ensure_store(self) -> None:
        """Lazy-load the vector store."""
        if self._vector_store is None:
            from logcentry.rag.vectorstore import VectorStore
            self._vector_store = VectorStore(
                collection_name=self._collection_name,
                persist_directory=self._persist_directory,
            )
    
    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Retrieve documents by semantic similarity.
        
        Args:
            query: Search query text
            top_k: Number of results to return
            source_filter: Filter by source (e.g., "mitre_attack")
            
        Returns:
            List of documents with content, metadata, and scores
        """
        self._ensure_store()
        
        where = None
        if source_filter:
            where = {"source": source_filter}
        
        # Run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            lambda: self._vector_store.search_by_text(query, top_k, where)
        )
        
        # Filter by score threshold and normalize output
        filtered = []
        for result in results:
            # Convert distance to similarity score (1 - distance for cosine)
            distance = result.get("distance", 1.0)
            score = 1.0 - min(distance, 1.0)
            
            if score >= self._score_threshold:
                filtered.append({
                    "content": result.get("content", ""),
                    "source": result.get("metadata", {}).get("source", "unknown"),
                    "score": round(score, 4),
                    "metadata": result.get("metadata", {}),
                })
        
        return filtered


class HybridRetriever(BaseRetriever):
    """
    Hybrid retriever combining vector search with keyword matching.
    
    Merges results from semantic and lexical search for better coverage.
    """
    
    def __init__(
        self,
        vector_weight: float = 0.7,
        keyword_weight: float = 0.3,
        collection_name: str = "logcentry_knowledge",
    ):
        """
        Initialize hybrid retriever.
        
        Args:
            vector_weight: Weight for vector search scores (0-1)
            keyword_weight: Weight for keyword search scores (0-1)
            collection_name: ChromaDB collection name
        """
        self._vector_weight = vector_weight
        self._keyword_weight = keyword_weight
        self._collection_name = collection_name
        self._vector_retriever = VectorRetriever(collection_name=collection_name)
    
    @property
    def name(self) -> str:
        return "hybrid_retriever"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["hybrid", "combined"]
    
    @property
    def description(self) -> str:
        return "Hybrid retrieval combining semantic and keyword search"
    
    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Retrieve using hybrid approach.
        
        Args:
            query: Search query
            top_k: Number of results
            
        Returns:
            Merged and re-ranked results
        """
        # Get vector results
        vector_results = await self._vector_retriever.retrieve(query, top_k * 2)
        
        # Perform keyword matching on vector results
        query_terms = set(query.lower().split())
        
        scored_results = []
        for result in vector_results:
            content_lower = result.get("content", "").lower()
            
            # Calculate keyword overlap score
            content_terms = set(content_lower.split())
            overlap = len(query_terms & content_terms)
            keyword_score = overlap / max(len(query_terms), 1)
            
            # Combine scores
            vector_score = result.get("score", 0)
            combined_score = (
                self._vector_weight * vector_score +
                self._keyword_weight * keyword_score
            )
            
            scored_results.append({
                **result,
                "score": round(combined_score, 4),
                "vector_score": vector_score,
                "keyword_score": keyword_score,
            })
        
        # Sort by combined score and take top_k
        scored_results.sort(key=lambda x: x["score"], reverse=True)
        return scored_results[:top_k]


class LocalRetriever(BaseRetriever):
    """
    Offline retriever using local document store.
    
    For air-gapped systems without external dependencies.
    """
    
    def __init__(
        self,
        documents_path: Optional[str] = None,
    ):
        """
        Initialize local retriever.
        
        Args:
            documents_path: Path to local documents directory
        """
        self._documents_path = documents_path
        self._documents: list[dict[str, Any]] = []
        self._loaded = False
    
    @property
    def name(self) -> str:
        return "local_retriever"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["local", "offline"]
    
    @property
    def description(self) -> str:
        return "Local document retrieval for offline/air-gapped systems"
    
    def load_documents(self, documents: list[dict[str, Any]]) -> None:
        """
        Load documents into memory.
        
        Args:
            documents: List of document dicts with 'content' and optional 'metadata'
        """
        self._documents = documents
        self._loaded = True
    
    def load_from_file(self, filepath: str) -> int:
        """
        Load documents from JSON file.
        
        Args:
            filepath: Path to JSON file with document array
            
        Returns:
            Number of documents loaded
        """
        import json
        from pathlib import Path
        
        path = Path(filepath)
        if not path.exists():
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            self._documents = json.load(f)
        
        self._loaded = True
        return len(self._documents)
    
    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Retrieve using TF-IDF style keyword matching.
        
        Args:
            query: Search query
            top_k: Number of results
            
        Returns:
            Matched documents scored by relevance
        """
        if not self._documents:
            return []
        
        query_terms = set(query.lower().split())
        
        scored = []
        for doc in self._documents:
            content = doc.get("content", "").lower()
            content_terms = set(content.split())
            
            # Simple overlap scoring
            overlap = len(query_terms & content_terms)
            if overlap > 0:
                score = overlap / len(query_terms)
                scored.append({
                    "content": doc.get("content", ""),
                    "source": doc.get("source", "local"),
                    "score": round(score, 4),
                    "metadata": doc.get("metadata", {}),
                })
        
        # Sort and return top_k
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]


class ExplainableRetriever(BaseRetriever):
    """
    Wrapper retriever that adds explainability data.
    
    Shows which chunks were retrieved and why.
    """
    
    def __init__(
        self,
        base_retriever: BaseRetriever,
        include_chunks: bool = True,
        include_scores: bool = True,
    ):
        """
        Initialize explainable retriever.
        
        Args:
            base_retriever: Underlying retriever to wrap
            include_chunks: Include full chunk content
            include_scores: Include relevance scores
        """
        self._base = base_retriever
        self._include_chunks = include_chunks
        self._include_scores = include_scores
    
    @property
    def name(self) -> str:
        return f"explainable_{self._base.name}"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["explainable"]
    
    @property
    def description(self) -> str:
        return f"Explainable wrapper for {self._base.name}"
    
    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Retrieve with explainability data.
        
        Returns:
            Results with explanation metadata
        """
        results = await self._base.retrieve(query, top_k, **kwargs)
        
        explained = []
        for i, result in enumerate(results):
            explanation = {
                "rank": i + 1,
                "source": result.get("source", "unknown"),
            }
            
            if self._include_scores:
                explanation["relevance_score"] = result.get("score", 0)
                explanation["score_explanation"] = self._explain_score(result.get("score", 0))
            
            if self._include_chunks:
                content = result.get("content", "")
                explanation["chunk_preview"] = content[:200] + "..." if len(content) > 200 else content
                explanation["chunk_length"] = len(content)
            
            explained.append({
                **result,
                "explanation": explanation,
            })
        
        return explained
    
    def _explain_score(self, score: float) -> str:
        """Generate human-readable score explanation."""
        if score >= 0.9:
            return "Very high relevance - strong semantic match"
        elif score >= 0.7:
            return "High relevance - good contextual match"
        elif score >= 0.5:
            return "Moderate relevance - partial match"
        elif score >= 0.3:
            return "Low relevance - weak match"
        else:
            return "Very low relevance - minimal match"


def get_builtin_retrievers() -> list[BaseRetriever]:
    """Get instances of all built-in retrievers."""
    return [
        VectorRetriever(),
        HybridRetriever(),
        LocalRetriever(),
    ]
