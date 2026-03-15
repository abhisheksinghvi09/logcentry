"""
LogCentry RAG - Retriever

Context retrieval for RAG-enhanced LLM prompts.
Combines semantic search with intelligent context selection.
"""

from typing import Any

from logcentry.config import get_cached_settings
from logcentry.core.models import LogBatch
from logcentry.rag.embeddings import embed_text
from logcentry.rag.knowledge import KnowledgeBase
from logcentry.rag.vectorstore import VectorStore
from logcentry.utils import get_logger

logger = get_logger(__name__)


def _load_cross_encoder(model_name: str):
    """Load CrossEncoder lazily to keep startup lightweight and support graceful fallback."""
    from sentence_transformers import CrossEncoder
    return CrossEncoder(model_name)


class ContextRetriever:
    """
    Retrieves relevant context from the knowledge base for RAG.
    
    Features:
    - Semantic search based on log content
    - Source-aware filtering (MITRE, CVE, custom)
    - Deduplication and ranking
    - Context size management
    """
    
    def __init__(
        self,
        knowledge_base: KnowledgeBase | None = None,
        vector_store: VectorStore | None = None,
    ):
        """
        Initialize the retriever.
        
        Args:
            knowledge_base: Optional pre-configured KnowledgeBase
            vector_store: Optional VectorStore (used if knowledge_base not provided)
        """
        if knowledge_base:
            self.knowledge_base = knowledge_base
            self.vector_store = knowledge_base.vector_store
        elif vector_store:
            self.vector_store = vector_store
            self.knowledge_base = None
        else:
            self.vector_store = VectorStore()
            self.knowledge_base = KnowledgeBase(vector_store=self.vector_store)
        
        settings = get_cached_settings()
        self.top_k = settings.retrieval_top_k
        self.reranker_enabled = settings.rag_reranker_enabled
        self.reranker_model = settings.rag_reranker_model
        self.reranker_candidate_multiplier = settings.rag_reranker_candidate_multiplier
        self.reranker_max_candidates = settings.rag_reranker_max_candidates
        
        self.cross_encoder = None

    def _ensure_reranker(self) -> bool:
        """Ensure reranker is loaded if enabled; disable safely on failure."""
        if not self.reranker_enabled:
            return False

        if self.cross_encoder is not None:
            return True

        logger.info("loading_reranker", model=self.reranker_model)
        try:
            self.cross_encoder = _load_cross_encoder(self.reranker_model)
            logger.info("reranker_loaded", model=self.reranker_model)
            return True
        except Exception as e:
            logger.error("reranker_load_failed", error=str(e), model=self.reranker_model)
            self.cross_encoder = None
            self.reranker_enabled = False
            return False
    
    def retrieve(
        self,
        query: str,
        top_k: int | None = None,
        sources: list[str] | None = None,
    ) -> list[str]:
        """
        Retrieve relevant context for a query.
        
        Args:
            query: Query text (usually log content or summary)
            top_k: Number of results to return (default from settings)
            sources: Optional list of sources to filter by
            
        Returns:
            List of relevant context strings
        """
        k = top_k or self.top_k
        
        # Build filter if sources specified
        where = None
        if sources:
            where = {"source": {"$in": sources}}

        reranker_active = self._ensure_reranker()
        
        # If reranking, initially fetch a broader candidate pool (e.g., 3x)
        if reranker_active:
            fetch_k = min(
                max(k * self.reranker_candidate_multiplier, k),
                self.reranker_max_candidates,
            )
        else:
            fetch_k = k
        
        # Search
        results = self.vector_store.search_by_text(query, n_results=fetch_k, where=where)
        
        # Extract and deduplicate content
        contexts = []
        seen = set()
        
        for result in results:
            content = result["content"]
            content_key = content[:100]  # Use first 100 chars for dedup
            
            if content_key not in seen:
                seen.add(content_key)
                contexts.append(content)
                
        # Re-rank candidates using the CrossEncoder
        if reranker_active and self.cross_encoder and contexts:
            pairs = [(query, ctx) for ctx in contexts]
            scores = self.cross_encoder.predict(pairs)
            
            # Combine contexts with their scores
            scored_contexts = list(zip(contexts, scores))
            # Sort by score descending
            scored_contexts.sort(key=lambda x: x[1], reverse=True)
            
            # Take exactly top_k after sorting
            contexts = [ctx for ctx, score in scored_contexts[:k]]
        else:
            # Drop extras if no re-ranking
            contexts = contexts[:k]
        
        logger.info(
            "context_retrieved",
            query_length=len(query),
            candidates=fetch_k,
            results=len(contexts),
            reranked=bool(reranker_active and self.cross_encoder),
        )
        
        return contexts
    
    def retrieve_for_logs(
        self,
        log_batch: LogBatch,
        top_k: int | None = None,
    ) -> list[str]:
        """
        Retrieve context relevant to a batch of logs.
        
        Creates a semantic query from the log content.
        
        Args:
            log_batch: Batch of log entries
            top_k: Number of results
            
        Returns:
            List of relevant context strings
        """
        # Create a representative query from the logs
        # Use message content from first N logs + any unique sources
        sample_messages = []
        sources = set()
        
        for entry in log_batch.entries[:10]:  # Sample first 10
            sample_messages.append(entry.message[:200])
            sources.add(entry.source)
        
        query = (
            f"Security logs from: {', '.join(sorted(sources))}\n"
            f"Sample events:\n" + "\n".join(sample_messages)
        )
        
        return self.retrieve(query, top_k=top_k)
    
    def retrieve_for_keywords(
        self,
        keywords: list[str],
        top_k: int | None = None,
    ) -> list[str]:
        """
        Retrieve context based on extracted keywords.
        
        Useful when specific terms like IPs, ports, or attack names are known.
        
        Args:
            keywords: List of keywords to search for
            top_k: Number of results
            
        Returns:
            List of relevant context strings
        """
        query = " ".join(keywords)
        return self.retrieve(query, top_k=top_k)
    
    def get_mitre_context(
        self,
        log_batch: LogBatch,
        top_k: int = 3,
    ) -> list[str]:
        """
        Get MITRE ATT&CK specific context.
        
        Args:
            log_batch: Logs to analyze
            top_k: Number of techniques to retrieve
            
        Returns:
            List of relevant MITRE techniques
        """
        return self.retrieve_for_logs(log_batch, top_k=top_k)
    
    def get_combined_context(
        self,
        log_batch: LogBatch,
        include_mitre: bool = True,
        include_cve: bool = True,
        include_historical: bool = True,
        max_total: int = 5,
    ) -> list[str]:
        """
        Get combined context from multiple sources.
        
        Balances context from different sources for comprehensive analysis.
        
        Args:
            log_batch: Logs to analyze
            include_mitre: Include MITRE ATT&CK techniques
            include_cve: Include CVE descriptions
            include_historical: Include past analyses
            max_total: Maximum total context items
            
        Returns:
            Combined list of context strings
        """
        sources = []
        if include_mitre:
            sources.append("mitre_attack")
        if include_cve:
            sources.append("cve")
        if include_historical:
            sources.append("historical")
        
        # Get context filtered by sources
        if sources:
            # Do a general search without source filter to get best matches
            contexts = self.retrieve_for_logs(log_batch, top_k=max_total)
        else:
            contexts = []
        
        return contexts[:max_total]


def create_rag_pipeline(
    initialize_knowledge: bool = False,
) -> ContextRetriever:
    """
    Factory function to create a fully configured RAG pipeline.
    
    Args:
        initialize_knowledge: If True, load knowledge base files
        
    Returns:
        Configured ContextRetriever
    """
    vector_store = VectorStore()
    knowledge_base = KnowledgeBase(vector_store=vector_store)
    
    if initialize_knowledge:
        knowledge_base.load_all()
    
    retriever = ContextRetriever(knowledge_base=knowledge_base)
    
    logger.info("rag_pipeline_created", document_count=vector_store.count)
    
    return retriever
