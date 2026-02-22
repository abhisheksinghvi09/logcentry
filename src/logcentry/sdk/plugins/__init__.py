"""
LogCentry SDK - Plugin Architecture

Extensible plugin system with event hooks and custom handler registration.
Supports community-contributed parsers, retrievers, and alert handlers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Type, TypeVar

T = TypeVar("T")


class EventType(Enum):
    """Lifecycle events for plugin hooks."""
    
    ON_LOG_INGEST = "on_log_ingest"
    ON_RAG_QUERY = "on_rag_query"
    ON_ALERT_TRIGGER = "on_alert_trigger"
    ON_ANALYSIS_START = "on_analysis_start"
    ON_ANALYSIS_COMPLETE = "on_analysis_complete"
    ON_BATCH_SEND = "on_batch_send"
    ON_ERROR = "on_error"


@dataclass
class EventContext:
    """
    Context passed to event hooks.
    
    Attributes:
        event_type: Type of event triggered
        data: Event-specific data
        metadata: Additional context metadata
        trace_id: Distributed trace ID
    """
    
    event_type: EventType
    data: Any
    metadata: dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None


class BasePlugin(ABC):
    """
    Base class for all plugins.
    
    Subclass this to create custom plugins with lifecycle hooks.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier."""
        pass
    
    @property
    def version(self) -> str:
        """Plugin version string."""
        return "1.0.0"
    
    @property
    def description(self) -> str:
        """Human-readable plugin description."""
        return ""
    
    def on_register(self, registry: "PluginRegistry") -> None:
        """Called when plugin is registered."""
        pass
    
    def on_unregister(self, registry: "PluginRegistry") -> None:
        """Called when plugin is unregistered."""
        pass


class BaseParser(BasePlugin):
    """
    Abstract base class for log parsers.
    
    Implement this to add support for custom log formats.
    """
    
    @property
    @abstractmethod
    def supported_formats(self) -> list[str]:
        """List of format identifiers this parser handles."""
        pass
    
    @abstractmethod
    def parse(self, raw_log: str) -> dict[str, Any]:
        """
        Parse a raw log line into structured data.
        
        Args:
            raw_log: Raw log string
            
        Returns:
            Parsed log as dictionary
        """
        pass
    
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if this parser can handle the log format.
        
        Args:
            raw_log: Raw log string
            
        Returns:
            True if parser can handle this format
        """
        return True


class BaseRetriever(BasePlugin):
    """
    Abstract base class for RAG retrievers.
    
    Implement this to add custom retrieval strategies.
    """
    
    @abstractmethod
    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Retrieve relevant documents for a query.
        
        Args:
            query: Search query
            top_k: Number of results to return
            **kwargs: Additional retrieval options
            
        Returns:
            List of relevant documents with scores
        """
        pass
    
    def retrieve_sync(
        self,
        query: str,
        top_k: int = 5,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """
        Synchronous version of retrieve.
        
        Override for sync-only retrievers.
        """
        import asyncio
        return asyncio.get_event_loop().run_until_complete(
            self.retrieve(query, top_k, **kwargs)
        )


class BaseAlertHandler(BasePlugin):
    """
    Abstract base class for alert handlers.
    
    Implement this to add custom alert destinations.
    """
    
    @abstractmethod
    async def send_alert(
        self,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> bool:
        """
        Send an alert notification.
        
        Args:
            severity: Alert severity level
            title: Alert title
            message: Alert message body
            metadata: Additional alert data
            
        Returns:
            True if alert was sent successfully
        """
        pass


# Type alias for event handlers
EventHandler = Callable[[EventContext], Optional[Any]]


class PluginRegistry:
    """
    Central registry for plugins and event hooks.
    
    Manages plugin lifecycle and event dispatch.
    
    Usage:
        registry = PluginRegistry()
        registry.register_plugin(MyParser())
        registry.add_hook(EventType.ON_LOG_INGEST, my_handler)
    """
    
    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: dict[str, BasePlugin] = {}
        self._parsers: dict[str, BaseParser] = {}
        self._retrievers: dict[str, BaseRetriever] = {}
        self._alert_handlers: dict[str, BaseAlertHandler] = {}
        self._hooks: dict[EventType, list[EventHandler]] = {
            event: [] for event in EventType
        }
    
    # ==================== Plugin Management ====================
    
    def register_plugin(self, plugin: BasePlugin) -> None:
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance to register
            
        Raises:
            ValueError: If plugin with same name already registered
        """
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' already registered")
        
        self._plugins[plugin.name] = plugin
        
        # Auto-register specialized plugins
        if isinstance(plugin, BaseParser):
            self._parsers[plugin.name] = plugin
        if isinstance(plugin, BaseRetriever):
            self._retrievers[plugin.name] = plugin
        if isinstance(plugin, BaseAlertHandler):
            self._alert_handlers[plugin.name] = plugin
        
        plugin.on_register(self)
    
    def unregister_plugin(self, name: str) -> bool:
        """
        Unregister a plugin by name.
        
        Args:
            name: Plugin name to remove
            
        Returns:
            True if plugin was removed, False if not found
        """
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            return False
        
        # Remove from specialized registries
        self._parsers.pop(name, None)
        self._retrievers.pop(name, None)
        self._alert_handlers.pop(name, None)
        
        plugin.on_unregister(self)
        return True
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)
    
    def list_plugins(self) -> list[dict[str, str]]:
        """List all registered plugins."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "type": type(p).__name__,
            }
            for p in self._plugins.values()
        ]
    
    # ==================== Specialized Registries ====================
    
    def get_parser(self, name: str) -> Optional[BaseParser]:
        """Get a parser by name."""
        return self._parsers.get(name)
    
    def get_retriever(self, name: str) -> Optional[BaseRetriever]:
        """Get a retriever by name."""
        return self._retrievers.get(name)
    
    def get_alert_handler(self, name: str) -> Optional[BaseAlertHandler]:
        """Get an alert handler by name."""
        return self._alert_handlers.get(name)
    
    def find_parser_for(self, raw_log: str) -> Optional[BaseParser]:
        """
        Find a parser that can handle the given log.
        
        Args:
            raw_log: Raw log string
            
        Returns:
            First matching parser or None
        """
        for parser in self._parsers.values():
            if parser.can_parse(raw_log):
                return parser
        return None
    
    # ==================== Event Hook System ====================
    
    def add_hook(
        self,
        event_type: EventType,
        handler: EventHandler,
    ) -> None:
        """
        Add an event hook handler.
        
        Args:
            event_type: Event to hook into
            handler: Callable to invoke on event
        """
        self._hooks[event_type].append(handler)
    
    def remove_hook(
        self,
        event_type: EventType,
        handler: EventHandler,
    ) -> bool:
        """
        Remove an event hook handler.
        
        Args:
            event_type: Event type
            handler: Handler to remove
            
        Returns:
            True if handler was removed
        """
        try:
            self._hooks[event_type].remove(handler)
            return True
        except ValueError:
            return False
    
    async def emit(
        self,
        event_type: EventType,
        data: Any,
        metadata: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> list[Any]:
        """
        Emit an event to all registered hooks.
        
        Args:
            event_type: Type of event
            data: Event data
            metadata: Additional metadata
            trace_id: Trace ID for correlation
            
        Returns:
            List of results from handlers
        """
        import asyncio
        
        context = EventContext(
            event_type=event_type,
            data=data,
            metadata=metadata or {},
            trace_id=trace_id,
        )
        
        results = []
        for handler in self._hooks[event_type]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(context)
                else:
                    result = handler(context)
                results.append(result)
            except Exception as e:
                # Emit error event (avoid recursion)
                if event_type != EventType.ON_ERROR:
                    await self.emit(
                        EventType.ON_ERROR,
                        {"handler": handler.__name__, "error": str(e)},
                    )
        
        return results
    
    def emit_sync(
        self,
        event_type: EventType,
        data: Any,
        metadata: Optional[dict[str, Any]] = None,
    ) -> list[Any]:
        """
        Synchronous event emission for non-async contexts.
        
        Args:
            event_type: Type of event
            data: Event data
            metadata: Additional metadata
            
        Returns:
            List of results from handlers
        """
        context = EventContext(
            event_type=event_type,
            data=data,
            metadata=metadata or {},
        )
        
        results = []
        for handler in self._hooks[event_type]:
            try:
                result = handler(context)
                results.append(result)
            except Exception:
                pass
        
        return results


# ==================== Decorator Helpers ====================


def register_parser(registry: PluginRegistry):
    """
    Decorator to register a parser class.
    
    Usage:
        @register_parser(my_registry)
        class NginxParser(BaseParser):
            ...
    """
    def decorator(cls: Type[BaseParser]) -> Type[BaseParser]:
        registry.register_plugin(cls())
        return cls
    return decorator


def register_retriever(registry: PluginRegistry):
    """Decorator to register a retriever class."""
    def decorator(cls: Type[BaseRetriever]) -> Type[BaseRetriever]:
        registry.register_plugin(cls())
        return cls
    return decorator


def register_alert_handler(registry: PluginRegistry):
    """Decorator to register an alert handler class."""
    def decorator(cls: Type[BaseAlertHandler]) -> Type[BaseAlertHandler]:
        registry.register_plugin(cls())
        return cls
    return decorator


def on_event(registry: PluginRegistry, event_type: EventType):
    """
    Decorator to register a function as an event hook.
    
    Usage:
        @on_event(registry, EventType.ON_LOG_INGEST)
        def log_handler(ctx):
            print(f"Log received: {ctx.data}")
    """
    def decorator(func: EventHandler) -> EventHandler:
        registry.add_hook(event_type, func)
        return func
    return decorator


# Global default registry
_default_registry: Optional[PluginRegistry] = None


def get_default_registry() -> PluginRegistry:
    """Get or create the default plugin registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = PluginRegistry()
    return _default_registry
