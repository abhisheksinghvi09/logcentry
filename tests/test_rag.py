import pytest
from unittest.mock import MagicMock, patch

from logcentry.core.models import LogEntry, LogBatch
from logcentry.rag.retriever import ContextRetriever
from logcentry.config import get_cached_settings


@pytest.fixture
def mock_settings():
    """Mock the application settings for testing RAG retriever."""
    with patch("logcentry.rag.retriever.get_cached_settings") as mock_get_settings:
        settings = MagicMock()
        settings.retrieval_top_k = 2
        settings.rag_reranker_enabled = False
        settings.rag_reranker_model = "fake-model"
        settings.rag_reranker_candidate_multiplier = 3
        settings.rag_reranker_max_candidates = 30
        mock_get_settings.return_value = settings
        yield settings


@pytest.fixture
def mock_vector_store():
    """Mock vector store returning ordered dummy results."""
    mock_vs = MagicMock()
    # Provide 6 results, we will verify reranking shuffles them
    mock_vs.search_by_text.return_value = [
        {"content": "Result A (lowest relevance)", "metadata": {"source": "mitre_attack"}, "distance": 0.1},
        {"content": "Result B (medium relevance)", "metadata": {"source": "cve"}, "distance": 0.2},
        {"content": "Result C (high relevance)", "metadata": {"source": "mitre_attack"}, "distance": 0.3},
        {"content": "Result D", "metadata": {"source": "cve"}, "distance": 0.4},
        {"content": "Result E", "metadata": {"source": "mitre_attack"}, "distance": 0.5},
        {"content": "Result F", "metadata": {"source": "mitre_attack"}, "distance": 0.6},
    ]
    return mock_vs


@pytest.fixture
def mock_cross_encoder():
    """Mock the CrossEncoder to test reranking logic."""
    with patch("logcentry.rag.retriever._load_cross_encoder") as mock_ce_loader:
        mock_instance = MagicMock()
        # Mock predict to return specific scores.
        # It's called with a list of (query, content) pairs.
        def sorted_mock_predict(pairs):
            scores = []
            for query, content in pairs:
                # Assign scores based on content strings to enforce an order
                if "Result A" in content:
                    scores.append(0.1)
                elif "Result B" in content:
                    scores.append(0.5)
                elif "Result C" in content:
                    scores.append(0.9) # Give C the highest score
                else:
                    scores.append(0.2)
            return scores
            
        mock_instance.predict.side_effect = sorted_mock_predict
        mock_ce_loader.return_value = mock_instance
        yield mock_ce_loader


def test_retriever_no_reranker(mock_settings, mock_vector_store):
    """Test standard retrieval without the cross-encoder re-ranker."""
    retriever = ContextRetriever(vector_store=mock_vector_store)
    
    assert retriever.reranker_enabled is False
    
    # Should only ask for top_k (2) and return top 2
    results = retriever.retrieve("suspicious login")
    
    assert len(results) == 2
    assert results[0] == "Result A (lowest relevance)"
    assert results[1] == "Result B (medium relevance)"
    
    mock_vector_store.search_by_text.assert_called_once_with(
        "suspicious login", n_results=2, where=None
    )


def test_retriever_with_reranker(mock_settings, mock_vector_store, mock_cross_encoder):
    """Test retrieval with the cross-encoder re-ranker modifying order."""
    mock_settings.rag_reranker_enabled = True
    
    retriever = ContextRetriever(vector_store=mock_vector_store)
    
    assert retriever.reranker_enabled is True
    assert retriever.cross_encoder is None
    
    # Reranking is enabled, so fetch_k should be top_k * 3 (2 * 3 = 6)
    results = retriever.retrieve("suspicious login")

    # Loader is lazy; only called on first retrieve
    mock_cross_encoder.assert_called_once_with("fake-model")
    
    mock_vector_store.search_by_text.assert_called_once_with(
        "suspicious login", n_results=6, where=None
    )
    
    # Because of mock_cross_encoder logic: C gets 0.9, B gets 0.5, rest get lower
    # Results should be sorted C first, then B (top_k is 2)
    assert len(results) == 2
    assert results[0] == "Result C (high relevance)"
    assert results[1] == "Result B (medium relevance)"


def test_retriever_reranker_fallback(mock_settings, mock_vector_store):
    """Test fallback when CrossEncoder fails to load."""
    mock_settings.rag_reranker_enabled = True
    
    with patch("logcentry.rag.retriever._load_cross_encoder", side_effect=Exception("Model load failed")):
        retriever = ContextRetriever(vector_store=mock_vector_store)
        
        # It should initially be enabled, then disable after failed lazy load
        assert retriever.reranker_enabled is True
        assert retriever.cross_encoder is None
        
        # Retrieval falls back to standard behavior
        results = retriever.retrieve("test")
        assert len(results) == 2
        assert retriever.reranker_enabled is False


def test_retriever_candidate_pool_capped(mock_settings, mock_vector_store, mock_cross_encoder):
    """Test reranker candidate pool is capped by max_candidates."""
    mock_settings.rag_reranker_enabled = True
    mock_settings.rag_reranker_candidate_multiplier = 5
    mock_settings.rag_reranker_max_candidates = 4

    retriever = ContextRetriever(vector_store=mock_vector_store)
    retriever.retrieve("suspicious login")

    mock_vector_store.search_by_text.assert_called_once_with(
        "suspicious login", n_results=4, where=None
    )
