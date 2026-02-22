"""
LogCentry SDK - Middleware

Middleware hooks for auth, rate limiting, error handling, and request logging.
Provides extensible pipeline for request/response processing.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


@dataclass
class RequestContext:
    """
    Context passed through middleware pipeline.
    
    Attributes:
        method: HTTP method or operation name
        path: Request path or resource
        headers: Request headers
        body: Request body
        metadata: Additional context data
        start_time: Request start time
        request_id: Unique request identifier
    """
    
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    request_id: Optional[str] = None
    
    @property
    def duration_ms(self) -> float:
        """Get request duration in milliseconds."""
        return (time.time() - self.start_time) * 1000


@dataclass
class ResponseContext:
    """
    Response context from middleware pipeline.
    
    Attributes:
        status: Response status code
        headers: Response headers
        body: Response body
        error: Error if request failed
    """
    
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    error: Optional[Exception] = None


class BaseMiddleware(ABC):
    """
    Abstract base class for middleware.
    
    Middleware can intercept and modify requests/responses.
    """
    
    @property
    def name(self) -> str:
        """Middleware name for logging."""
        return self.__class__.__name__
    
    @abstractmethod
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """
        Process request and call next middleware.
        
        Args:
            context: Request context
            next: Next middleware in chain
            
        Returns:
            Response context
        """
        pass


class AuthMiddleware(BaseMiddleware):
    """
    Authentication middleware.
    
    Validates API keys and adds auth context.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        header_name: str = "X-API-Key",
        on_auth_failure: Optional[Callable[[RequestContext], None]] = None,
    ):
        """
        Initialize auth middleware.
        
        Args:
            api_key: Expected API key (if None, only validates format)
            header_name: Header containing API key
            on_auth_failure: Callback on auth failure
        """
        self.api_key = api_key
        self.header_name = header_name
        self.on_auth_failure = on_auth_failure
    
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """Validate authentication."""
        provided_key = context.headers.get(self.header_name)
        
        if not provided_key:
            if self.on_auth_failure:
                self.on_auth_failure(context)
            return ResponseContext(
                status=401,
                error=Exception("Missing API key"),
            )
        
        if self.api_key and provided_key != self.api_key:
            if self.on_auth_failure:
                self.on_auth_failure(context)
            return ResponseContext(
                status=401,
                error=Exception("Invalid API key"),
            )
        
        # Add auth info to context
        context.metadata["authenticated"] = True
        context.metadata["api_key_prefix"] = provided_key[:8] + "..."
        
        return await next(context)


class RateLimitMiddleware(BaseMiddleware):
    """
    Rate limiting middleware.
    
    Implements token bucket algorithm for rate limiting.
    """
    
    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: int = 50,
        key_func: Optional[Callable[[RequestContext], str]] = None,
    ):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Sustained request rate
            burst_size: Maximum burst size
            key_func: Function to extract rate limit key from context
        """
        self.rate = requests_per_second
        self.burst = burst_size
        self.key_func = key_func or (lambda ctx: ctx.headers.get("X-API-Key", "default"))
        
        self._buckets: dict[str, dict] = defaultdict(
            lambda: {"tokens": burst_size, "last_update": time.time()}
        )
    
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """Apply rate limiting."""
        key = self.key_func(context)
        bucket = self._buckets[key]
        
        now = time.time()
        elapsed = now - bucket["last_update"]
        
        # Refill tokens
        bucket["tokens"] = min(
            self.burst,
            bucket["tokens"] + elapsed * self.rate
        )
        bucket["last_update"] = now
        
        if bucket["tokens"] < 1:
            retry_after = (1 - bucket["tokens"]) / self.rate
            return ResponseContext(
                status=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
                error=Exception(f"Rate limit exceeded. Retry after {retry_after:.1f}s"),
            )
        
        bucket["tokens"] -= 1
        context.metadata["rate_limit_remaining"] = int(bucket["tokens"])
        
        return await next(context)


class ErrorHandlingMiddleware(BaseMiddleware):
    """
    Error handling middleware.
    
    Catches exceptions and returns appropriate responses.
    """
    
    def __init__(
        self,
        on_error: Optional[Callable[[Exception, RequestContext], None]] = None,
        include_stack_trace: bool = False,
    ):
        """
        Initialize error handler.
        
        Args:
            on_error: Callback on error
            include_stack_trace: Include stack trace in response
        """
        self.on_error = on_error
        self.include_stack_trace = include_stack_trace
    
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """Handle errors in pipeline."""
        try:
            return await next(context)
        except Exception as e:
            if self.on_error:
                self.on_error(e, context)
            
            error_response = {
                "error": str(e),
                "type": type(e).__name__,
            }
            
            if self.include_stack_trace:
                import traceback
                error_response["stack_trace"] = traceback.format_exc()
            
            return ResponseContext(
                status=500,
                body=error_response,
                error=e,
            )


class LoggingMiddleware(BaseMiddleware):
    """
    Request/response logging middleware.
    
    Logs all requests with timing and status.
    """
    
    def __init__(
        self,
        logger: Optional[Any] = None,
        log_body: bool = False,
        max_body_length: int = 1000,
    ):
        """
        Initialize logging middleware.
        
        Args:
            logger: Logger instance (uses structlog if None)
            log_body: Whether to log request/response bodies
            max_body_length: Max body length to log
        """
        self.log_body = log_body
        self.max_body_length = max_body_length
        
        if logger is None:
            try:
                from logcentry.utils import get_logger
                self.logger = get_logger("logcentry.middleware")
            except ImportError:
                self.logger = None
        else:
            self.logger = logger
    
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """Log request and response."""
        # Log request
        log_data = {
            "method": context.method,
            "path": context.path,
            "request_id": context.request_id,
        }
        
        if self.log_body and context.body:
            body_str = str(context.body)[:self.max_body_length]
            log_data["request_body"] = body_str
        
        if self.logger:
            self.logger.info("request_started", **log_data)
        
        # Process request
        response = await next(context)
        
        # Log response
        log_data.update({
            "status": response.status,
            "duration_ms": round(context.duration_ms, 2),
        })
        
        if response.error:
            log_data["error"] = str(response.error)
        
        if self.logger:
            if response.status >= 400:
                self.logger.warning("request_completed", **log_data)
            else:
                self.logger.info("request_completed", **log_data)
        
        return response


class RetryMiddleware(BaseMiddleware):
    """
    Retry middleware with exponential backoff.
    
    Automatically retries failed requests.
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        retry_on: Optional[set[int]] = None,
    ):
        """
        Initialize retry middleware.
        
        Args:
            max_retries: Maximum retry attempts
            base_delay: Base delay between retries (seconds)
            max_delay: Maximum delay between retries
            retry_on: Status codes to retry on
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.retry_on = retry_on or {500, 502, 503, 504, 429}
    
    async def process_request(
        self,
        context: RequestContext,
        next: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """Retry on failure."""
        last_response = None
        
        for attempt in range(self.max_retries + 1):
            response = await next(context)
            last_response = response
            
            if response.status not in self.retry_on:
                return response
            
            if attempt < self.max_retries:
                delay = min(
                    self.base_delay * (2 ** attempt),
                    self.max_delay
                )
                
                # Check Retry-After header
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                
                await asyncio.sleep(delay)
        
        return last_response


class MiddlewarePipeline:
    """
    Middleware pipeline manager.
    
    Chains middleware in order and processes requests.
    """
    
    def __init__(self):
        """Initialize empty pipeline."""
        self._middleware: list[BaseMiddleware] = []
    
    def add(self, middleware: BaseMiddleware) -> "MiddlewarePipeline":
        """
        Add middleware to pipeline.
        
        Args:
            middleware: Middleware to add
            
        Returns:
            Self for chaining
        """
        self._middleware.append(middleware)
        return self
    
    def remove(self, middleware_class: type) -> bool:
        """
        Remove middleware by class.
        
        Args:
            middleware_class: Class to remove
            
        Returns:
            True if removed
        """
        for i, mw in enumerate(self._middleware):
            if isinstance(mw, middleware_class):
                self._middleware.pop(i)
                return True
        return False
    
    async def process(
        self,
        context: RequestContext,
        handler: Callable[[RequestContext], Awaitable[ResponseContext]],
    ) -> ResponseContext:
        """
        Process request through pipeline.
        
        Args:
            context: Request context
            handler: Final request handler
            
        Returns:
            Response context
        """
        async def chain(
            middleware_list: list[BaseMiddleware],
            ctx: RequestContext,
        ) -> ResponseContext:
            if not middleware_list:
                return await handler(ctx)
            
            current = middleware_list[0]
            remaining = middleware_list[1:]
            
            return await current.process_request(
                ctx,
                lambda c: chain(remaining, c)
            )
        
        return await chain(self._middleware, context)


def default_pipeline(
    api_key: Optional[str] = None,
    rate_limit: float = 10.0,
) -> MiddlewarePipeline:
    """
    Create a default middleware pipeline.
    
    Args:
        api_key: API key for auth
        rate_limit: Requests per second
        
    Returns:
        Configured pipeline
    """
    return (
        MiddlewarePipeline()
        .add(ErrorHandlingMiddleware())
        .add(LoggingMiddleware())
        .add(RateLimitMiddleware(requests_per_second=rate_limit))
        .add(AuthMiddleware(api_key=api_key))
        .add(RetryMiddleware())
    )
