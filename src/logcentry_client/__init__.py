"""
LogCentry Client SDK - Lightweight Edition

A minimal, zero-dependency* SDK for sending logs to LogCentry.
All heavy processing (ML, RAG, analysis) happens on the LogCentry backend.

*Only uses Python stdlib. Optional httpx for async support.

Installation:
    pip install logcentry-client  # ~50KB, no heavy deps

Compare to full SDK:
    pip install logcentry         # ~500MB with ML deps

Usage:
    from logcentry_client import LogCentry
    
    logger = LogCentry(api_key="lc_xxx")
    logger.info("User logged in", user_id=123)
    logger.security("Attack detected", ip="10.0.0.1")
"""

from __future__ import annotations

import json
import os
import queue
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
from uuid import uuid4


__version__ = "1.0.0"
__all__ = ["LogCentry", "LogLevel", "Config"]


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


@dataclass
class Config:
    """
    SDK configuration with sensible defaults.
    
    Attributes:
        api_key: LogCentry API key (required)
        endpoint: LogCentry API endpoint
        batch_size: Max logs per batch
        flush_interval: Seconds between auto-flushes
        timeout: HTTP request timeout
        verify_ssl: Verify TLS certificates
        sync_mode: Send logs synchronously (blocks)
        max_retries: Max retry attempts on failure
        on_error: Callback for send errors
    """
    api_key: str
    endpoint: str = "http://localhost:8000"
    batch_size: int = 50
    flush_interval: float = 5.0
    timeout: int = 10
    verify_ssl: bool = True
    sync_mode: bool = False
    max_retries: int = 3
    on_error: Optional[Callable[[Exception, list], None]] = None


class LogCentry:
    """
    Lightweight LogCentry client.
    
    Zero heavy dependencies - uses only Python stdlib.
    All ML/RAG processing happens on the backend.
    
    Usage:
        logger = LogCentry(api_key="lc_xxx")
        logger.info("Hello world")
        logger.security("Attack detected", ip="10.0.0.1")
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = "http://localhost:8000",
        *,
        batch_size: int = 50,
        flush_interval: float = 5.0,
        timeout: int = 10,
        verify_ssl: bool = True,
        sync_mode: bool = False,
        max_retries: int = 3,
        on_error: Optional[Callable[[Exception, list], None]] = None,
    ):
        """
        Initialize the LogCentry client.
        
        Args:
            api_key: Your LogCentry API key. If None, reads from 
                     LOGCENTRY_API_KEY environment variable.
            endpoint: LogCentry API endpoint URL.
            batch_size: Max number of logs to batch before sending.
            flush_interval: Seconds between automatic batch flushes.
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify TLS certificates.
            sync_mode: If True, sends logs synchronously (blocks).
            max_retries: Max retry attempts on network failure.
            on_error: Optional callback(exception, failed_logs) on errors.
        """
        # Get API key from env if not provided
        resolved_key = api_key or os.getenv("LOGCENTRY_API_KEY", "")
        if not resolved_key:
            raise ValueError(
                "API key required. Pass api_key= or set LOGCENTRY_API_KEY env var."
            )
        
        self.config = Config(
            api_key=resolved_key,
            endpoint=endpoint.rstrip("/"),
            batch_size=batch_size,
            flush_interval=flush_interval,
            timeout=timeout,
            verify_ssl=verify_ssl,
            sync_mode=sync_mode,
            max_retries=max_retries,
            on_error=on_error,
        )
        
        # State
        self._queue: queue.Queue[dict] = queue.Queue()
        self._running = True
        self._flush_thread: Optional[threading.Thread] = None
        
        # Context for tracing
        self._trace_id: Optional[str] = None
        self._request_id: Optional[str] = None
        
        # Start background flush thread if async mode
        if not sync_mode:
            self._start_flush_thread()
    
    # ==================== Public Logging Methods ====================
    
    def debug(self, message: str, **metadata) -> None:
        """Log a debug message."""
        self._log(LogLevel.DEBUG, message, metadata)
    
    def info(self, message: str, **metadata) -> None:
        """Log an info message."""
        self._log(LogLevel.INFO, message, metadata)
    
    def warning(self, message: str, **metadata) -> None:
        """Log a warning message."""
        self._log(LogLevel.WARNING, message, metadata)
    
    def error(self, message: str, **metadata) -> None:
        """Log an error message."""
        self._log(LogLevel.ERROR, message, metadata)
    
    def critical(self, message: str, **metadata) -> None:
        """Log a critical message."""
        self._log(LogLevel.CRITICAL, message, metadata)
    
    def security(self, message: str, **metadata) -> None:
        """Log a security event."""
        self._log(LogLevel.SECURITY, message, metadata)
    
    def log(
        self,
        level: str | LogLevel,
        message: str,
        **metadata,
    ) -> None:
        """Log with custom level."""
        if isinstance(level, str):
            level = LogLevel(level.lower())
        self._log(level, message, metadata)
    
    # ==================== Context Management ====================
    
    def set_context(
        self,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """
        Set context for all subsequent logs.
        
        Args:
            trace_id: Distributed trace ID
            request_id: Request correlation ID
        """
        self._trace_id = trace_id
        self._request_id = request_id
    
    def clear_context(self) -> None:
        """Clear logging context."""
        self._trace_id = None
        self._request_id = None
    
    # ==================== Lifecycle ====================
    
    def flush(self) -> None:
        """Force send all queued logs immediately."""
        logs = []
        while not self._queue.empty():
            try:
                logs.append(self._queue.get_nowait())
            except queue.Empty:
                break
        
        if logs:
            self._send_batch(logs)
    
    def shutdown(self, timeout: float = 5.0) -> None:
        """
        Gracefully shutdown the client.
        
        Flushes remaining logs and stops background thread.
        
        Args:
            timeout: Max seconds to wait for flush
        """
        self._running = False
        self.flush()
        
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=timeout)
    
    def __enter__(self) -> "LogCentry":
        """Context manager entry."""
        return self
    
    def __exit__(self, *args) -> None:
        """Context manager exit - flushes logs."""
        self.shutdown()
    
    # ==================== Analysis (calls backend) ====================
    
    def analyze(
        self,
        logs: Optional[list[dict]] = None,
        use_rag: bool = True,
    ) -> dict:
        """
        Request AI-powered threat analysis from backend.
        
        All heavy processing (ML, RAG) happens server-side.
        
        Args:
            logs: Logs to analyze. If None, uses recent logs.
            use_rag: Whether to use RAG context for analysis.
            
        Returns:
            Analysis result with severity, threats, recommendations.
        """
        url = f"{self.config.endpoint}/api/v1/analyze"
        
        payload = {
            "logs": logs or [],
            "use_rag": use_rag,
        }
        
        response = self._http_request("POST", url, payload)
        return response
    
    # ==================== Internal Methods ====================
    
    def _log(
        self,
        level: LogLevel,
        message: str,
        metadata: dict,
    ) -> None:
        """Internal log handler."""
        entry = {
            "message": message,
            "level": level.value,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata,
        }
        
        # Add context if set
        if self._trace_id:
            entry["trace_id"] = self._trace_id
        if self._request_id:
            entry["request_id"] = self._request_id
        
        if self.config.sync_mode:
            self._send_single(entry)
        else:
            self._queue.put(entry)
            
            # Auto-flush if batch is full
            if self._queue.qsize() >= self.config.batch_size:
                self.flush()
    
    def _send_single(self, entry: dict) -> bool:
        """Send a single log entry synchronously."""
        return self._send_batch([entry])
    
    def _send_batch(self, logs: list[dict]) -> bool:
        """Send a batch of logs to the API."""
        if not logs:
            return True
        
        url = f"{self.config.endpoint}/api/v1/logs/batch"
        payload = {"logs": logs}
        
        for attempt in range(self.config.max_retries):
            try:
                self._http_request("POST", url, payload)
                return True
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    if self.config.on_error:
                        self.config.on_error(e, logs)
                    return False
                time.sleep(0.5 * (2 ** attempt))  # Exponential backoff
        
        return False
    
    def _http_request(
        self,
        method: str,
        url: str,
        data: Optional[dict] = None,
    ) -> dict:
        """Make HTTP request using stdlib urllib."""
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key,
            "User-Agent": f"LogCentry-Client/{__version__}",
        }
        
        body = json.dumps(data).encode() if data else None
        
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )
        
        # SSL context
        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
            if not self.config.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.timeout,
                context=context,
            ) as response:
                response_body = response.read().decode()
                if response_body:
                    return json.loads(response_body)
                return {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise Exception(f"HTTP {e.code}: {error_body}") from e
        except urllib.error.URLError as e:
            raise Exception(f"Network error: {e.reason}") from e
    
    def _start_flush_thread(self) -> None:
        """Start background thread for periodic flushing."""
        def flush_loop():
            while self._running:
                time.sleep(self.config.flush_interval)
                if self._running:
                    self.flush()
        
        self._flush_thread = threading.Thread(
            target=flush_loop,
            daemon=True,
            name="logcentry-flush",
        )
        self._flush_thread.start()


# ==================== Convenience Functions ====================

def quick_log(
    message: str,
    level: str = "info",
    api_key: Optional[str] = None,
    **metadata,
) -> None:
    """
    Quick one-off log without client setup.
    
    Usage:
        quick_log("Something happened", level="error", user=123)
    """
    client = LogCentry(api_key=api_key, sync_mode=True)
    client.log(level, message, **metadata)


# ==================== Decorator (minimal) ====================

def log_errors(
    client: Optional[LogCentry] = None,
    reraise: bool = True,
):
    """
    Decorator to automatically log exceptions.
    
    Usage:
        @log_errors()
        def risky_operation():
            ...
    """
    import functools
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_client = client or LogCentry(sync_mode=True)
                log_client.error(
                    f"Exception in {func.__name__}: {e}",
                    function=func.__name__,
                    error_type=type(e).__name__,
                )
                if reraise:
                    raise
        return wrapper
    return decorator


# Async client for when httpx is available
try:
    import httpx
    
    class AsyncLogCentry:
        """
        Async version using httpx (optional dependency).
        
        Install: pip install httpx
        """
        
        def __init__(
            self,
            api_key: Optional[str] = None,
            endpoint: str = "http://localhost:8000",
            **kwargs,
        ):
            resolved_key = api_key or os.getenv("LOGCENTRY_API_KEY", "")
            if not resolved_key:
                raise ValueError("API key required")
            
            self.api_key = resolved_key
            self.endpoint = endpoint.rstrip("/")
            self._client: Optional[httpx.AsyncClient] = None
            self._batch: list[dict] = []
        
        async def __aenter__(self) -> "AsyncLogCentry":
            self._client = httpx.AsyncClient(
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                }
            )
            return self
        
        async def __aexit__(self, *args) -> None:
            await self.flush()
            if self._client:
                await self._client.aclose()
        
        async def info(self, message: str, **metadata) -> None:
            await self._log("info", message, metadata)
        
        async def error(self, message: str, **metadata) -> None:
            await self._log("error", message, metadata)
        
        async def security(self, message: str, **metadata) -> None:
            await self._log("security", message, metadata)
        
        async def _log(self, level: str, message: str, metadata: dict) -> None:
            self._batch.append({
                "message": message,
                "level": level,
                "timestamp": datetime.now().isoformat(),
                "metadata": metadata,
            })
            if len(self._batch) >= 50:
                await self.flush()
        
        async def flush(self) -> None:
            if not self._batch or not self._client:
                return
            logs, self._batch = self._batch, []
            await self._client.post(
                f"{self.endpoint}/api/v1/logs/batch",
                json={"logs": logs},
            )
    
    __all__.append("AsyncLogCentry")

except ImportError:
    # httpx not installed - async client not available
    pass
