"""
LogCentry SDK - Decorators

Decorators for common SDK workflows: log capture, RAG queries, and tracing.
Provides Pythonic patterns for seamless integration.
"""

import asyncio
import functools
import time
import uuid
from typing import Any, Callable, Optional, TypeVar, Union

F = TypeVar("F", bound=Callable[..., Any])


def log_capture(
    client: Optional[Any] = None,
    level: str = "info",
    include_args: bool = True,
    include_result: bool = False,
    include_timing: bool = True,
) -> Callable[[F], F]:
    """
    Decorator to automatically capture function calls as log entries.
    
    Captures function name, arguments, execution time, and optionally results.
    Works with both sync and async functions.
    
    Args:
        client: LogCentry client instance (None for deferred binding)
        level: Log level for captured entries
        include_args: Whether to log function arguments
        include_result: Whether to log return value
        include_timing: Whether to log execution time
        
    Returns:
        Decorated function
        
    Usage:
        @log_capture(level="debug")
        def process_data(data):
            return transform(data)
            
        # Or with explicit client:
        @log_capture(client=my_client, include_result=True)
        async def fetch_user(user_id):
            return await db.get_user(user_id)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            start_time = time.perf_counter()
            request_id = str(uuid.uuid4())[:8]
            
            # Build log metadata
            metadata: dict[str, Any] = {
                "function": func.__name__,
                "module": func.__module__,
                "request_id": request_id,
            }
            
            if include_args:
                # Safely capture args (avoid large objects)
                metadata["args"] = _safe_repr(args)
                metadata["kwargs"] = _safe_repr(kwargs)
            
            try:
                result = await func(*args, **kwargs)
                
                if include_timing:
                    metadata["duration_ms"] = round(
                        (time.perf_counter() - start_time) * 1000, 2
                    )
                
                if include_result:
                    metadata["result"] = _safe_repr(result)
                
                metadata["status"] = "success"
                
                # Log if client available
                target_client = client
                if target_client is None:
                    try:
                        from logcentry.sdk import get_agent
                        target_client = get_agent()
                    except ImportError:
                        pass

                if target_client:
                    log_method = getattr(target_client, level, target_client.info)
                    if asyncio.iscoroutinefunction(log_method):
                        await log_method(
                            f"Function {func.__name__} completed",
                            **metadata,
                        )
                    else:
                        log_method(f"Function {func.__name__} completed", **metadata, source=f"{func.__module__}:{func.__name__}")
                
                return result
                
            except Exception as e:
                if include_timing:
                    metadata["duration_ms"] = round(
                        (time.perf_counter() - start_time) * 1000, 2
                    )
                
                metadata["status"] = "error"
                metadata["error_type"] = type(e).__name__
                metadata["error_message"] = str(e)[:500]
                
                target_client = client
                if target_client is None:
                    try:
                        from logcentry.sdk import get_agent
                        target_client = get_agent()
                    except ImportError:
                        pass

                if target_client:
                    error_method = getattr(target_client, "error", None) or getattr(target_client, "log", None)
                    if error_method:
                        if asyncio.iscoroutinefunction(error_method):
                            await error_method(
                                f"Function {func.__name__} failed: {e}",
                                **metadata,
                            )
                        else:
                            error_method(f"Function {func.__name__} failed: {e}", **metadata, source=f"{func.__module__}:{func.__name__}")
                
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            start_time = time.perf_counter()
            request_id = str(uuid.uuid4())[:8]
            
            metadata: dict[str, Any] = {
                "function": func.__name__,
                "module": func.__module__,
                "request_id": request_id,
            }
            
            if include_args:
                metadata["args"] = _safe_repr(args)
                metadata["kwargs"] = _safe_repr(kwargs)
            
            try:
                result = func(*args, **kwargs)
                
                if include_timing:
                    metadata["duration_ms"] = round(
                        (time.perf_counter() - start_time) * 1000, 2
                    )
                
                if include_result:
                    metadata["result"] = _safe_repr(result)
                
                metadata["status"] = "success"
                
                target_client = client
                if target_client is None:
                    try:
                        from logcentry.sdk import get_agent
                        target_client = get_agent()
                    except ImportError:
                        pass

                if target_client:
                    log_method = getattr(target_client, level, target_client.info)
                    log_method(f"Function {func.__name__} completed", **metadata, source=f"{func.__module__}:{func.__name__}")
                
                return result
                
            except Exception as e:
                if include_timing:
                    metadata["duration_ms"] = round(
                        (time.perf_counter() - start_time) * 1000, 2
                    )
                
                metadata["status"] = "error"
                metadata["error_type"] = type(e).__name__
                metadata["error_message"] = str(e)[:500]
                
                target_client = client
                if target_client is None:
                    try:
                        from logcentry.sdk import get_agent
                        target_client = get_agent()
                    except ImportError:
                        pass

                if target_client:
                    error_method = getattr(target_client, "error", None) or getattr(target_client, "log", None)
                    if error_method:
                        error_method(f"Function {func.__name__} failed: {e}", **metadata, source=f"{func.__module__}:{func.__name__}")
                
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore
    
    return decorator


def rag_query(
    client: Optional[Any] = None,
    top_k: int = 5,
    score_threshold: float = 0.5,
    include_context: bool = True,
) -> Callable[[F], F]:
    """
    Decorator to wrap functions with RAG query capabilities.
    
    Automatically fetches relevant context before function execution
    and passes it as a keyword argument.
    
    Args:
        client: LogCentry client with RAG capabilities
        top_k: Number of context documents to retrieve
        score_threshold: Minimum relevance score
        include_context: Whether to pass context to function
        
    Returns:
        Decorated function
        
    Usage:
        @rag_query(top_k=3)
        async def analyze_threat(logs, rag_context=None):
            # rag_context is automatically populated
            return process_with_context(logs, rag_context)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            # Extract query from first argument or kwargs
            query = kwargs.get("query") or (args[0] if args else None)
            
            target_client = client
            if target_client is None:
                try:
                    from logcentry.sdk import get_agent
                    target_client = get_agent()
                except ImportError:
                    pass

            context = None
            if include_context and target_client and query:
                try:
                    # Attempt to fetch RAG context
                    if hasattr(target_client, "query_knowledge"):
                        context = await target_client.query_knowledge(
                            query=str(query),
                            top_k=top_k,
                        )
                        # Filter by score threshold
                        context = [
                            c for c in context
                            if c.get("score", 0) >= score_threshold
                        ]
                except Exception:
                    # Don't fail the function if RAG fails
                    context = []
            
            # Inject context if function accepts it
            if "rag_context" not in kwargs:
                kwargs["rag_context"] = context
            
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            # For sync functions, we can't await RAG, but maybe we should support synchronous RAG? 
            # The original code only supported async for RAG.
            # If we want to support sync, we need a sync client method.
            # For now, keep as is but try to inject agent if we could.
            # Since RAG is async properly, sync wrapper just passes None usually unless we block.
            # Let's just keep original behavior for sync wrapper regarding context (it was just setting None).
            
            if "rag_context" not in kwargs:
                kwargs["rag_context"] = None
            return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore
    
    return decorator


def trace_operation(
    operation_name: Optional[str] = None,
    include_args: bool = False,
) -> Callable[[F], F]:
    """
    Decorator to trace function execution with distributed tracing.
    
    Creates a span for the operation with timing and metadata.
    Works with OpenTelemetry when available, falls back to basic tracing.
    
    Args:
        operation_name: Custom name for the span (defaults to function name)
        include_args: Whether to include function arguments as span attributes
        
    Returns:
        Decorated function
        
    Usage:
        @trace_operation("database_query")
        async def fetch_user(user_id):
            return await db.get(user_id)
    """
    def decorator(func: F) -> F:
        span_name = operation_name or func.__name__
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            trace_id = str(uuid.uuid4()).replace("-", "")
            span_id = str(uuid.uuid4()).replace("-", "")[:16]
            start_time = time.perf_counter()
            
            # Try to use OpenTelemetry if available
            tracer = _get_tracer()
            
            if tracer:
                with tracer.start_as_current_span(span_name) as span:
                    if include_args:
                        span.set_attribute("args", _safe_repr(args))
                        span.set_attribute("kwargs", _safe_repr(kwargs))
                    
                    try:
                        result = await func(*args, **kwargs)
                        span.set_attribute("status", "ok")
                        return result
                    except Exception as e:
                        span.set_attribute("status", "error")
                        span.set_attribute("error.type", type(e).__name__)
                        span.set_attribute("error.message", str(e)[:500])
                        raise
            else:
                # Fallback: basic tracing without OpenTelemetry
                try:
                    result = await func(*args, **kwargs)
                    _log_trace(span_name, trace_id, span_id, start_time, "ok")
                    return result
                except Exception as e:
                    _log_trace(span_name, trace_id, span_id, start_time, "error", e)
                    raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            trace_id = str(uuid.uuid4()).replace("-", "")
            span_id = str(uuid.uuid4()).replace("-", "")[:16]
            start_time = time.perf_counter()
            
            tracer = _get_tracer()
            
            if tracer:
                with tracer.start_as_current_span(span_name) as span:
                    if include_args:
                        span.set_attribute("args", _safe_repr(args))
                        span.set_attribute("kwargs", _safe_repr(kwargs))
                    
                    try:
                        result = func(*args, **kwargs)
                        span.set_attribute("status", "ok")
                        return result
                    except Exception as e:
                        span.set_attribute("status", "error")
                        span.set_attribute("error.type", type(e).__name__)
                        span.set_attribute("error.message", str(e)[:500])
                        raise
            else:
                try:
                    result = func(*args, **kwargs)
                    _log_trace(span_name, trace_id, span_id, start_time, "ok")
                    return result
                except Exception as e:
                    _log_trace(span_name, trace_id, span_id, start_time, "error", e)
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore
    
    return decorator


# ==================== Helper Functions ====================


def _safe_repr(obj: Any, max_length: int = 200) -> str:
    """Safely create a string representation of an object."""
    try:
        result = repr(obj)
        if len(result) > max_length:
            return result[:max_length] + "..."
        return result
    except Exception:
        return "<non-representable>"


def _get_tracer() -> Optional[Any]:
    """Get OpenTelemetry tracer if available."""
    try:
        from opentelemetry import trace
        return trace.get_tracer("logcentry.sdk")
    except ImportError:
        return None


def _log_trace(
    operation: str,
    trace_id: str,
    span_id: str,
    start_time: float,
    status: str,
    error: Optional[Exception] = None,
) -> None:
    """Log basic trace information when OpenTelemetry is not available."""
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    
    # Import here to avoid circular imports
    try:
        from logcentry.utils import get_logger
        logger = get_logger("logcentry.sdk.tracing")
        
        log_data = {
            "operation": operation,
            "trace_id": trace_id,
            "span_id": span_id,
            "duration_ms": duration_ms,
            "status": status,
        }
        
        if error:
            log_data["error_type"] = type(error).__name__
            log_data["error_message"] = str(error)[:500]
            logger.warning("trace_error", **log_data)
        else:
            logger.debug("trace_complete", **log_data)
            
    except ImportError:
        # Silently skip if logger not available
        pass
