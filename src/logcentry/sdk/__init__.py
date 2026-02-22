"""
LogCentry SDK

Professional Python SDK for security log ingestion and RAG-powered analysis.

Quick Start:
    import logcentry.sdk as logcentry

    # 1. Initialize
    logcentry.init(api_key="lc_xxx")

    # 2. Log
    logcentry.info("User logged in", user_id=123)
    logcentry.security("Attack detected", ip="10.0.0.1")

Features:
    - Singleton Agent
    - Facade API
    - Circuit Breaker Resilience
    - Decorators, Plugins, and Middleware
"""

from typing import Optional, Any

# Core
from logcentry.sdk.client import LogCentryAgent, LogCentry
from logcentry.sdk.async_client import AsyncLogCentry, quick_log
from logcentry.sdk.models import (
    LogEntry, LogBatch, LogLevel, SeverityLevel, EventType,
    AnalysisRequest, AnalysisResult, RetrievalResult,
    PatchSuggestion, SDKConfig
)
from logcentry.sdk.decorators import (
    log_capture, rag_query, trace_operation
)
from logcentry.sdk.integrations import flask_middleware, django_middleware

# ==================== Singleton Management ====================

_agent: Optional[LogCentryAgent] = None

def init(
    api_key: str,
    endpoint: str = "http://localhost:8000",
    project: Optional[str] = None,
    batch_size: int = 10,
    flush_interval: float = 5.0,
    sync_mode: bool = False,
    **kwargs,
) -> LogCentryAgent:
    """
    Initialize the global LogCentry agent.
    
    Args:
        api_key: Organization API Key
        endpoint: LogCentry API URL
        project: Project name (optional)
        batch_size: Batch size before sending
        flush_interval: Seconds between batch sends
        sync_mode: If True, send logs synchronously (blocking)
        
    Returns:
        The initialized agent instance
    """
    global _agent
    if _agent is None:
        _agent = LogCentryAgent(
            api_key=api_key,
            endpoint=endpoint,
            project=project,
            batch_size=batch_size,
            flush_interval=flush_interval,
            sync_mode=sync_mode,
            **kwargs,
        )
    return _agent

def get_agent() -> Optional[LogCentryAgent]:
    """Get the global agent instance."""
    return _agent

def shutdown() -> None:
    """Shutdown the global agent."""
    global _agent
    if _agent:
        _agent.shutdown()
        _agent = None

# ==================== Facade API ====================

def debug(message: str, **kwargs) -> None:
    """Log a debug message via global agent."""
    if _agent: _agent.debug(message, **kwargs)

def info(message: str, **kwargs) -> None:
    """Log an info message via global agent."""
    if _agent: _agent.info(message, **kwargs)

def warning(message: str, **kwargs) -> None:
    """Log a warning message via global agent."""
    if _agent: _agent.warning(message, **kwargs)

def error(message: str, **kwargs) -> None:
    """Log an error message via global agent."""
    if _agent: _agent.error(message, **kwargs)

def critical(message: str, **kwargs) -> None:
    """Log a critical message via global agent."""
    if _agent: _agent.critical(message, **kwargs)

def security(message: str, **kwargs) -> None:
    """Log a security event via global agent."""
    if _agent: _agent.security(message, **kwargs)

def log(level: str, message: str, **kwargs) -> None:
    """Log with custom level via global agent."""
    if _agent: _agent.log(level, message, **kwargs)

__all__ = [
    # Facade
    "init", "shutdown", "get_agent",
    "debug", "info", "warning", "error", "critical", "security", "log",
    
    # Classes
    "LogCentry", "LogCentryAgent", "AsyncLogCentry",
    "LogEntry", "LogBatch", "LogLevel", "SeverityLevel", "SDKConfig",
    
    # Decorators
    "log_capture", "rag_query", "trace_operation",
    
    # Integrations
    "flask_middleware", "django_middleware",
]

__version__ = "2.0.0"
