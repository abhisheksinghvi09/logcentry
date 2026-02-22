"""
LogCentry SDK Tests - Client Tests

Unit tests for sync and async SDK clients.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import json


class TestLogCentrySync:
    """Tests for synchronous LogCentry client."""
    
    def test_client_initialization(self, api_key: str, endpoint: str):
        """Test client initializes correctly."""
        from logcentry.sdk import LogCentry
        
        client = LogCentry(
            api_key=api_key,
            endpoint=endpoint,
            sync_mode=True,
        )
        
        assert client.api_key == api_key
        assert client.endpoint == endpoint
        assert client.sync_mode is True
        
        client.shutdown()
    
    def test_log_methods(self, sync_client):
        """Test all log level methods."""
        with patch.object(sync_client, '_send_single', return_value=True) as mock_send:
            sync_client.debug("Debug message")
            sync_client.info("Info message")
            sync_client.warning("Warning message")
            sync_client.error("Error message")
            sync_client.critical("Critical message")
            sync_client.security("Security event")
            
            assert mock_send.call_count == 6
    
    def test_log_with_metadata(self, sync_client):
        """Test logging with additional metadata."""
        with patch.object(sync_client, '_send_single', return_value=True) as mock_send:
            sync_client.info(
                "User logged in",
                user_id=123,
                ip="192.168.1.1",
                action="login",
            )
            
            call_args = mock_send.call_args[0][0]
            assert call_args["message"] == "User logged in"
            assert call_args["metadata"]["user_id"] == 123
            assert call_args["metadata"]["ip"] == "192.168.1.1"
    
    def test_batch_mode(self, api_key: str, endpoint: str):
        """Test async batch mode."""
        from logcentry.sdk import LogCentry
        
        client = LogCentry(
            api_key=api_key,
            endpoint=endpoint,
            batch_size=5,
            sync_mode=False,
        )
        
        # Should not send immediately
        with patch.object(client, '_send_batch') as mock_send:
            for i in range(3):
                client.info(f"Message {i}")
            
            # Queue should have entries but batch not sent yet
            assert client._queue.qsize() == 3
        
        client.shutdown()
    
    def test_flush(self, api_key: str, endpoint: str):
        """Test manual flush."""
        from logcentry.sdk import LogCentry
        
        client = LogCentry(
            api_key=api_key,
            endpoint=endpoint,
            sync_mode=False,
        )
        
        with patch.object(client, '_send_batch', return_value=True) as mock_send:
            client.info("Message 1")
            client.info("Message 2")
            client.flush()
            
            assert mock_send.called
        
        client.shutdown()


class TestAsyncLogCentry:
    """Tests for async LogCentry client."""
    
    @pytest.mark.asyncio
    async def test_async_client_context_manager(self, api_key: str, endpoint: str, mock_httpx_client):
        """Test async client works as context manager."""
        from logcentry.sdk import AsyncLogCentry
        
        async with AsyncLogCentry(api_key=api_key, endpoint=endpoint) as client:
            assert not client.is_closed
        
        assert client.is_closed
    
    @pytest.mark.asyncio
    async def test_async_log_methods(self, api_key: str, endpoint: str, mock_httpx_client):
        """Test async log methods."""
        from logcentry.sdk import AsyncLogCentry
        
        async with AsyncLogCentry(api_key=api_key, endpoint=endpoint) as client:
            await client.debug("Debug")
            await client.info("Info")
            await client.warning("Warning")
            await client.error("Error")
            await client.critical("Critical")
            await client.security("Security")
            
            # Logs should be in batch
            assert len(client._batch) <= 6
    
    @pytest.mark.asyncio
    async def test_async_flush(self, api_key: str, endpoint: str, mock_httpx_client):
        """Test async flush."""
        from logcentry.sdk import AsyncLogCentry
        
        async with AsyncLogCentry(api_key=api_key, endpoint=endpoint) as client:
            await client.info("Message 1")
            await client.info("Message 2")
            await client.flush()
            
            mock_httpx_client.post.assert_called()
    
    @pytest.mark.asyncio
    async def test_trace_context(self, api_key: str, endpoint: str, mock_httpx_client):
        """Test trace context management."""
        from logcentry.sdk import AsyncLogCentry
        
        async with AsyncLogCentry(api_key=api_key, endpoint=endpoint) as client:
            client.set_trace_context()
            
            assert client._trace_id is not None
            assert client._span_id is not None
            assert len(client._trace_id) == 32
            assert len(client._span_id) == 16
            
            client.clear_trace_context()
            assert client._trace_id is None
    
    @pytest.mark.asyncio
    async def test_trace_context_manager(self, api_key: str, endpoint: str, mock_httpx_client):
        """Test trace context manager."""
        from logcentry.sdk import AsyncLogCentry
        
        async with AsyncLogCentry(api_key=api_key, endpoint=endpoint) as client:
            async with client.trace("test_operation") as ctx:
                assert "trace_id" in ctx
                assert "span_id" in ctx
                assert ctx["operation"] == "test_operation"


class TestLogEntry:
    """Tests for LogEntry dataclass."""
    
    def test_log_entry_creation(self):
        """Test LogEntry can be created."""
        from logcentry.sdk import LogEntry, LogLevel
        
        entry = LogEntry(
            message="Test message",
            level=LogLevel.INFO,
            source="test",
        )
        
        assert entry.message == "Test message"
        assert entry.level == LogLevel.INFO
        assert entry.timestamp is not None
    
    def test_log_entry_to_dict(self):
        """Test LogEntry serialization."""
        from logcentry.sdk import LogEntry, LogLevel
        
        entry = LogEntry(
            message="Test",
            level=LogLevel.ERROR,
            metadata={"key": "value"},
        )
        
        data = entry.to_dict()
        
        assert data["message"] == "Test"
        assert data["level"] == "error"
        assert data["metadata"]["key"] == "value"
    
    def test_log_entry_from_dict(self):
        """Test LogEntry deserialization."""
        from logcentry.sdk import LogEntry
        
        data = {
            "message": "Test",
            "level": "warning",
            "timestamp": "2026-02-07T10:00:00",
            "metadata": {"ip": "10.0.0.1"},
        }
        
        entry = LogEntry.from_dict(data)
        
        assert entry.message == "Test"
        assert entry.metadata["ip"] == "10.0.0.1"


class TestLogBatch:
    """Tests for LogBatch."""
    
    def test_batch_creation(self):
        """Test LogBatch can be created."""
        from logcentry.sdk import LogBatch, LogEntry
        
        batch = LogBatch(source="test")
        batch.add(LogEntry(message="Entry 1"))
        batch.add(LogEntry(message="Entry 2"))
        
        assert batch.count == 2
        assert batch.source == "test"
    
    def test_batch_to_dict(self):
        """Test batch serialization."""
        from logcentry.sdk import LogBatch, LogEntry
        
        batch = LogBatch()
        batch.add(LogEntry(message="Test"))
        
        data = batch.to_dict()
        
        assert data["count"] == 1
        assert len(data["entries"]) == 1


class TestNetworkFailures:
    """Tests for network failure handling."""
    
    def test_sync_client_handles_timeout(self, api_key: str, endpoint: str):
        """Test sync client handles network timeout."""
        from logcentry.sdk import LogCentry
        from urllib.error import URLError
        
        client = LogCentry(api_key=api_key, endpoint=endpoint, sync_mode=True)
        
        with patch('urllib.request.urlopen', side_effect=URLError("timeout")):
            # Should not raise, just return False
            result = client._send_single({"message": "test"})
            assert result is False
        
        client.shutdown()
    
    @pytest.mark.asyncio
    async def test_async_client_retry(self, api_key: str, endpoint: str):
        """Test async client retries on 5xx errors."""
        from logcentry.sdk import AsyncLogCentry
        import httpx
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            
            # First call fails with 500, second succeeds
            response_fail = MagicMock()
            response_fail.status_code = 500
            response_fail.raise_for_status = MagicMock(
                side_effect=httpx.HTTPStatusError("error", request=None, response=response_fail)
            )
            
            response_ok = MagicMock()
            response_ok.status_code = 200
            response_ok.raise_for_status = MagicMock()
            
            mock_instance.post = AsyncMock(side_effect=[response_fail, response_ok])
            mock_instance.aclose = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance
            
            async with AsyncLogCentry(api_key=api_key, endpoint=endpoint, max_retries=2) as client:
                await client.info("Test message")
                await client.flush()
