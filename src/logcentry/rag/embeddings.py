"""
LogCentry RAG - Embeddings Module

Text embedding generation using sentence-transformers for semantic search.
"""

from typing import Any

from logcentry.config import get_cached_settings
from logcentry.utils import get_logger

logger = get_logger(__name__)

# Optional import - will be loaded on first use
_model = None


def get_embedding_model():
    """Get or initialize the embedding model (lazy loading)."""
    global _model
    
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            
            settings = get_cached_settings()
            model_name = settings.embedding_model
            
            logger.info("loading_embedding_model", model=model_name)
            _model = SentenceTransformer(model_name)
            logger.info("embedding_model_loaded", model=model_name)
            
        except ImportError:
            raise RuntimeError(
                "sentence-transformers is required for RAG. "
                "Install with: pip install sentence-transformers"
            )
    
    return _model


def embed_text(text: str) -> list[float]:
    """
    Generate embedding for a single text.
    
    Args:
        text: Text to embed
        
    Returns:
        Embedding vector as list of floats
    """
    model = get_embedding_model()
    embedding = model.encode(text, convert_to_numpy=True)
    return embedding.tolist()


def embed_texts(texts: list[str], batch_size: int = 32) -> list[list[float]]:
    """
    Generate embeddings for multiple texts.
    
    Args:
        texts: List of texts to embed
        batch_size: Batch size for encoding
        
    Returns:
        List of embedding vectors
    """
    if not texts:
        return []
    
    model = get_embedding_model()
    
    logger.info("embedding_texts", count=len(texts), batch_size=batch_size)
    
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        convert_to_numpy=True,
        show_progress_bar=len(texts) > 100,
    )
    
    return embeddings.tolist()


def embed_log_entry(entry: Any) -> list[float]:
    """
    Generate embedding for a log entry.
    
    Creates a semantic representation combining timestamp, source, and message.
    """
    # Create a structured text representation
    text = f"[{entry.source}] {entry.message}"
    return embed_text(text)


def compute_similarity(embedding1: list[float], embedding2: list[float]) -> float:
    """
    Compute cosine similarity between two embeddings.
    
    Args:
        embedding1: First embedding vector
        embedding2: Second embedding vector
        
    Returns:
        Similarity score (0-1)
    """
    import numpy as np
    
    a = np.array(embedding1)
    b = np.array(embedding2)
    
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))
