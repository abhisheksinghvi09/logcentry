"""
LogCentry SDK - Async Client

Async/await based client for non-blocking log ingestion and RAG queries.
Uses httpx for async HTTP operations with connection pooling.
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Optional

try:
    import httpx
except ImportError:
    raise RuntimeError(
        "httpx is required for async client. Install with: pip install httpx"
    )

from logcentry.sdk.models import (
    AnalysisRequest,
    AnalysisResult,
    LogBatch,
    LogEntry,
    LogLevel,
    SDKConfig,
    SeverityLevel,
)


class AsyncLogCentry:
    """
    Async LogCentry SDK client for non-blocking operations.
    
    Features:
    - Async/await for log ingestion and RAG queries
    - Connection pooling for performance
    - Automatic batching with background flush
    - Retry with exponential backoff
    - Context manager support
    
    Usage:
        async with AsyncLogCentry(api_key="lc_xxx") as client:
            await client.info("Hello async!")
            result = await client.analyze_logs(logs)
    """
    
    def __init__(
        self,
        api_key: str,
        endpoint: str = "http://localhost:8000",
        batch_size: int = 10,
        flush_interval: float = 5.0,
        timeout: float = 30.0,
        max_retries: int = 3,
        enable_tracing: bool = False,
        verify_ssl: bool = True,
        **kwargs,
    ):
        """
        Initialize the async client.
        
        Args:
            api_key: Your LogCentry API key
            endpoint: API endpoint URL
            batch_size: Number of logs to batch before sending
            flush_interval: Seconds between auto-flushes
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts on failure
            enable_tracing: Enable OpenTelemetry tracing
            verify_ssl: Verify TLS certificates
        """
        self.config = SDKConfig(
            api_key=api_key,
            endpoint=endpoint.rstrip("/"),
            batch_size=batch_size,
            flush_interval=flush_interval,
            timeout=timeout,
            max_retries=max_retries,
            enable_tracing=enable_tracing,
            verify_ssl=verify_ssl,
            **kwargs,
        )
        
        self._batch: list[dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._closed = False
        
        # Tracing context
        self._trace_id: Optional[str] = None
        self._span_id: Optional[str] = None
    
    async def __aenter__(self) -> "AsyncLogCentry":
        """Async context manager entry."""
        await self._ensure_client()
        self._start_flush_task()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit with graceful shutdown."""
        await self.shutdown()
    
    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.endpoint,
                timeout=httpx.Timeout(self.config.timeout),
                verify=self.config.verify_ssl,
                headers={
                    "X-API-Key": self.config.api_key,
                    "Content-Type": "application/json",
                },
            )
    
    def _start_flush_task(self) -> None:
        """Start background flush task."""
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_loop())
    
    async def _flush_loop(self) -> None:
        """Background loop to periodically flush logs."""
        while not self._closed:
            try:
                await asyncio.sleep(self.config.flush_interval)
                await self.flush()
            except asyncio.CancelledError:
                break
            except Exception:
                # Don't crash the loop on flush errors
                pass
    
    async def _log(
        self,
        level: LogLevel,
        message: str,
        source: Optional[str] = None,
        **metadata,
    ) -> None:
        """
        Internal log method.
        
        Args:
            level: Log level
            message: Log message
            source: Log source identifier
            **metadata: Additional metadata key-values
        """
        entry = {
            "level": level.value,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "metadata": metadata,
            "trace_id": self._trace_id,
            "span_id": self._span_id,
            "request_id": metadata.pop("request_id", None),
        }
        
        async with self._batch_lock:
            self._batch.append(entry)
            
            if len(self._batch) >= self.config.batch_size:
                await self._send_batch()
    
    async def _send_batch(self) -> bool:
        """
        Send the current batch to the API.
        
        Returns:
            True if successful, False otherwise.
        """
        if not self._batch:
            return True
        
        # Initialize circuit breaker if needed (lazy init for async context safety?)
        # Better to init in __init__, but let's check if we have it.
        # We need to add it to __init__ first.
        if not hasattr(self, "_circuit_breaker"):
            from logcentry.sdk.circuit_breaker import CircuitBreaker
            self._circuit_breaker = CircuitBreaker()

        if not self._circuit_breaker.allow_request():
            return False

        batch_to_send = self._batch.copy()
        self._batch.clear()
        
        await self._ensure_client()
        
        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.post(
                    "/api/v1/logs/batch",
                    json={"logs": batch_to_send},
                )
                response.raise_for_status()
                self._circuit_breaker.record_success()
                return True
                
            except httpx.HTTPStatusError as e:
                self._circuit_breaker.record_failure()
                if e.response.status_code >= 500:
                    # Retry on server errors
                    if attempt < self.config.max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                        continue
                # Don't retry on client errors
                return False
                
            except (httpx.RequestError, httpx.TimeoutException):
                # Only record failure on network errors if final attempt? 
                # Or distinct logic? Circuit breaker usually counts network errors.
                if attempt == self.config.max_retries - 1:
                     self._circuit_breaker.record_failure()
                
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
        
        return False
    
    # ==================== Public Logging API ====================
    
    async def debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        await self._log(LogLevel.DEBUG, message, **kwargs)
    
    async def info(self, message: str, **kwargs) -> None:
        """Log an info message."""
        await self._log(LogLevel.INFO, message, **kwargs)
    
    async def warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        await self._log(LogLevel.WARNING, message, **kwargs)
    
    async def error(self, message: str, **kwargs) -> None:
        """Log an error message."""
        await self._log(LogLevel.ERROR, message, **kwargs)
    
    async def critical(self, message: str, **kwargs) -> None:
        """Log a critical message."""
        await self._log(LogLevel.CRITICAL, message, **kwargs)
    
    async def security(self, message: str, **kwargs) -> None:
        """Log a security event."""
        await self._log(LogLevel.SECURITY, message, **kwargs)
    
    async def log(self, level: str, message: str, **kwargs) -> None:
        """Log with custom level."""
        log_level = LogLevel(level.lower())
        await self._log(log_level, message, **kwargs)
    
    # ==================== RAG / Analysis API ====================
    
    async def analyze_logs(
        self,
        logs: LogBatch,
        include_rag: bool = True,
        top_k: int = 5,
        score_threshold: float = 0.5,
        explain: bool = False,
    ) -> AnalysisResult:
        """
        Analyze logs for security threats with optional RAG enrichment.
        
        Args:
            logs: Batch of logs to analyze
            include_rag: Whether to use RAG context
            top_k: Number of context documents to retrieve
            score_threshold: Minimum relevance score
            explain: Include explainability data (retrieved chunks)
            
        Returns:
            Complete analysis result with threat assessment
        """
        await self._ensure_client()
        
        request = AnalysisRequest(
            logs=logs,
            include_rag=include_rag,
            top_k=top_k,
            score_threshold=score_threshold,
            explain=explain,
        )
        
        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.post(
                    "/api/v1/analyze",
                    json=request.to_dict(),
                )
                response.raise_for_status()
                data = response.json()
                
                return AnalysisResult(
                    severity_score=data.get("severity_score", 0),
                    severity_level=SeverityLevel(
                        data.get("severity_level", "none")
                    ),
                    threat_assessment=data.get("threat_assessment", ""),
                    detailed_explanation=data.get("detailed_explanation", ""),
                    trace_id=self._trace_id,
                )
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
                
            except (httpx.RequestError, httpx.TimeoutException):
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
    
    async def analyze_text(
        self,
        text: str,
        source: Optional[str] = None,
        **kwargs,
    ) -> AnalysisResult:
        """
        Convenience method to analyze raw text.
        
        Args:
            text: Raw log text to analyze
            source: Source identifier
            **kwargs: Additional analysis options
            
        Returns:
            Analysis result
        """
        lines = text.strip().split("\n")
        batch = LogBatch(source=source)
        
        for line in lines:
            if line.strip():
                batch.add(LogEntry(message=line))
        
        return await self.analyze_logs(batch, **kwargs)
    
    async def query_knowledge(
        self,
        query: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Query the security knowledge base.
        
        Args:
            query: Search query
            top_k: Number of results to return
            source_filter: Filter by source (e.g., "mitre_attack", "cve")
            
        Returns:
            List of relevant knowledge items with scores
        """
        await self._ensure_client()
        
        params = {"q": query, "top_k": top_k}
        if source_filter:
            params["source"] = source_filter
        
        response = await self._client.get("/api/v1/knowledge/search", params=params)
        response.raise_for_status()
        
        return response.json().get("results", [])
    
    # ==================== Tracing API ====================
    
    def set_trace_context(
        self,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> None:
        """
        Set trace context for distributed tracing.
        
        Args:
            trace_id: W3C Trace Context trace ID
            span_id: Current span ID
        """
        self._trace_id = trace_id or str(uuid.uuid4()).replace("-", "")
        self._span_id = span_id or str(uuid.uuid4()).replace("-", "")[:16]
    
    def clear_trace_context(self) -> None:
        """Clear any set trace context."""
        self._trace_id = None
        self._span_id = None
    
    @asynccontextmanager
    async def trace(
        self,
        operation_name: str,
    ) -> AsyncIterator[dict[str, str]]:
        """
        Context manager for tracing operations.
        
        Usage:
            async with client.trace("analyze_request") as ctx:
                result = await client.analyze_logs(logs)
                # ctx contains trace_id, span_id
        
        Args:
            operation_name: Name of the operation being traced
            
        Yields:
            Dictionary with trace_id and span_id
        """
        previous_trace = self._trace_id
        previous_span = self._span_id
        
        self.set_trace_context()
        
        try:
            yield {
                "trace_id": self._trace_id,
                "span_id": self._span_id,
                "operation": operation_name,
            }
        finally:
            self._trace_id = previous_trace
            self._span_id = previous_span
    
    # ==================== Lifecycle ====================
    
    async def flush(self) -> None:
        """Flush any pending logs immediately."""
        async with self._batch_lock:
            await self._send_batch()
    
    async def shutdown(self) -> None:
        """Gracefully shutdown the client."""
        self._closed = True
        
        # Cancel flush task
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining logs
        await self.flush()
        
        # Close HTTP client
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @property
    def is_closed(self) -> bool:
        """Check if client is closed."""
        return self._closed


# Convenience function for quick usage
async def quick_log(
    api_key: str,
    message: str,
    level: str = "info",
    **kwargs,
) -> None:
    """
    Quick one-shot logging without client management.
    
    Usage:
        await quick_log("lc_xxx", "Quick message!")
    """
    async with AsyncLogCentry(api_key=api_key) as client:
        await client.log(level, message, **kwargs)
