"""
LogCentry SDK - OpenTelemetry Tracing

Distributed tracing integration with OpenTelemetry.
Supports W3C Trace Context for cross-service correlation.
"""

import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Optional

# Type stubs for when OpenTelemetry is not installed
Tracer = Any
Span = Any


@dataclass
class TraceConfig:
    """
    Tracing configuration.
    
    Attributes:
        service_name: Name of the service for tracing
        exporter_type: Type of span exporter ("console", "otlp", "jaeger", "none")
        otlp_endpoint: OTLP exporter endpoint
        sample_rate: Sampling rate (0.0 to 1.0)
        enable_w3c_context: Enable W3C Trace Context propagation
    """
    
    service_name: str = "logcentry-sdk"
    exporter_type: str = "none"
    otlp_endpoint: str = "http://localhost:4317"
    sample_rate: float = 1.0
    enable_w3c_context: bool = True


class TracingManager:
    """
    Manages OpenTelemetry tracing setup and span creation.
    
    Falls back to no-op tracing if OpenTelemetry is not installed.
    
    Usage:
        tracing = TracingManager(TraceConfig(service_name="my-service"))
        with tracing.span("operation") as span:
            span.set_attribute("key", "value")
            # ... do work
    """
    
    def __init__(self, config: Optional[TraceConfig] = None):
        """
        Initialize tracing manager.
        
        Args:
            config: Tracing configuration
        """
        self.config = config or TraceConfig()
        self._tracer: Optional[Tracer] = None
        self._enabled = False
        
        self._setup_tracing()
    
    def _setup_tracing(self) -> None:
        """Set up OpenTelemetry tracing."""
        if self.config.exporter_type == "none":
            return
        
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource, SERVICE_NAME
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
            
            # Create tracer provider with sampling
            resource = Resource.create({SERVICE_NAME: self.config.service_name})
            sampler = TraceIdRatioBased(self.config.sample_rate)
            provider = TracerProvider(resource=resource, sampler=sampler)
            
            # Add exporter based on config
            self._add_exporter(provider)
            
            # Set as global tracer provider
            trace.set_tracer_provider(provider)
            
            # Get tracer
            self._tracer = trace.get_tracer("logcentry.sdk")
            self._enabled = True
            
        except ImportError:
            # OpenTelemetry not installed
            self._enabled = False
    
    def _add_exporter(self, provider) -> None:
        """Add span exporter to provider."""
        try:
            from opentelemetry.sdk.trace.export import (
                BatchSpanProcessor,
                ConsoleSpanExporter,
            )
            
            if self.config.exporter_type == "console":
                exporter = ConsoleSpanExporter()
                provider.add_span_processor(BatchSpanProcessor(exporter))
                
            elif self.config.exporter_type == "otlp":
                try:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )
                    exporter = OTLPSpanExporter(endpoint=self.config.otlp_endpoint)
                    provider.add_span_processor(BatchSpanProcessor(exporter))
                except ImportError:
                    pass
                    
            elif self.config.exporter_type == "jaeger":
                try:
                    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
                    exporter = JaegerExporter()
                    provider.add_span_processor(BatchSpanProcessor(exporter))
                except ImportError:
                    pass
                    
        except ImportError:
            pass
    
    @property
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self._enabled
    
    @contextmanager
    def span(
        self,
        name: str,
        attributes: Optional[dict[str, Any]] = None,
    ):
        """
        Create a tracing span.
        
        Args:
            name: Span name
            attributes: Optional span attributes
            
        Yields:
            Span object (or NoOpSpan if tracing disabled)
        """
        if self._enabled and self._tracer:
            with self._tracer.start_as_current_span(name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, str(value))
                yield span
        else:
            yield NoOpSpan()
    
    def create_trace_context(self) -> dict[str, str]:
        """
        Create a new trace context for propagation.
        
        Returns:
            Dictionary with trace_id, span_id, and traceparent header
        """
        trace_id = str(uuid.uuid4()).replace("-", "")
        span_id = str(uuid.uuid4()).replace("-", "")[:16]
        
        # W3C Trace Context format
        # https://www.w3.org/TR/trace-context/
        traceparent = f"00-{trace_id}-{span_id}-01"
        
        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "traceparent": traceparent,
        }
    
    def parse_traceparent(self, traceparent: str) -> Optional[dict[str, str]]:
        """
        Parse W3C traceparent header.
        
        Args:
            traceparent: W3C traceparent header value
            
        Returns:
            Parsed context or None if invalid
        """
        if not traceparent:
            return None
        
        try:
            parts = traceparent.split("-")
            if len(parts) != 4:
                return None
            
            version, trace_id, span_id, flags = parts
            
            if version != "00":
                return None
            
            if len(trace_id) != 32 or len(span_id) != 16:
                return None
            
            return {
                "trace_id": trace_id,
                "span_id": span_id,
                "sampled": flags == "01",
            }
            
        except Exception:
            return None
    
    def inject_context(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Inject trace context into HTTP headers.
        
        Args:
            headers: Existing headers dict
            
        Returns:
            Headers with trace context added
        """
        if self._enabled:
            try:
                from opentelemetry import trace
                from opentelemetry.propagate import inject
                
                inject(headers)
                return headers
                
            except ImportError:
                pass
        
        # Fallback: generate new context
        context = self.create_trace_context()
        headers["traceparent"] = context["traceparent"]
        return headers
    
    def extract_context(self, headers: dict[str, str]) -> Optional[dict[str, str]]:
        """
        Extract trace context from HTTP headers.
        
        Args:
            headers: Request headers
            
        Returns:
            Extracted context or None
        """
        traceparent = headers.get("traceparent")
        if traceparent:
            return self.parse_traceparent(traceparent)
        return None


class NoOpSpan:
    """No-operation span for when tracing is disabled."""
    
    def set_attribute(self, key: str, value: Any) -> None:
        """No-op."""
        pass
    
    def add_event(self, name: str, attributes: Optional[dict] = None) -> None:
        """No-op."""
        pass
    
    def record_exception(self, exception: Exception) -> None:
        """No-op."""
        pass
    
    def set_status(self, status) -> None:
        """No-op."""
        pass


# Global tracer instance
_global_tracer: Optional[TracingManager] = None


def get_tracer(config: Optional[TraceConfig] = None) -> TracingManager:
    """
    Get or create global tracer instance.
    
    Args:
        config: Optional config (only used on first call)
        
    Returns:
        TracingManager instance
    """
    global _global_tracer
    
    if _global_tracer is None:
        _global_tracer = TracingManager(config)
    
    return _global_tracer


def trace_function(
    name: Optional[str] = None,
    include_args: bool = False,
) -> Callable:
    """
    Decorator to trace a function.
    
    Args:
        name: Custom span name (defaults to function name)
        include_args: Include function arguments as attributes
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        import asyncio
        import functools
        
        span_name = name or func.__name__
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            
            attributes = {"function": func.__name__, "module": func.__module__}
            if include_args:
                attributes["args"] = str(args)[:200]
                attributes["kwargs"] = str(kwargs)[:200]
            
            with tracer.span(span_name, attributes) as span:
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("status", "ok")
                    return result
                except Exception as e:
                    span.set_attribute("status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e)[:500])
                    span.record_exception(e)
                    raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            
            attributes = {"function": func.__name__, "module": func.__module__}
            if include_args:
                attributes["args"] = str(args)[:200]
                attributes["kwargs"] = str(kwargs)[:200]
            
            with tracer.span(span_name, attributes) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("status", "ok")
                    return result
                except Exception as e:
                    span.set_attribute("status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e)[:500])
                    span.record_exception(e)
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator
