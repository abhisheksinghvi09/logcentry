"""
LogCentry SDK - Data Models

Type-safe dataclasses for log representation, analysis requests, and results.
Follows PEP8/PEP257 with comprehensive type hints.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class LogLevel(Enum):
    """Log severity levels following standard conventions."""
    
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


class SeverityLevel(Enum):
    """Threat severity classification for analysis results."""
    
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_score(cls, score: int) -> "SeverityLevel":
        """Convert numeric score (0-10) to severity level."""
        if score <= 0:
            return cls.NONE
        elif score <= 3:
            return cls.LOW
        elif score <= 5:
            return cls.MEDIUM
        elif score <= 7:
            return cls.HIGH
        else:
            return cls.CRITICAL


class EventType(Enum):
    """Types of security events detected."""
    
    INJECTION = "injection"
    AUTH_FAILURE = "auth_failure"
    EXPOSURE = "exposure"
    DOS = "dos"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    RECONNAISSANCE = "reconnaissance"
    BRUTE_FORCE = "brute_force"
    OTHER = "other"


@dataclass
class LogEntry:
    """
    Single log entry with structured data.
    
    Attributes:
        message: The log message content
        level: Log severity level
        timestamp: When the log was generated
        source: Origin of the log (e.g., "nginx", "auth-service")
        metadata: Additional key-value data attached to the log
        trace_id: Optional distributed trace ID for correlation
        span_id: Optional span ID within the trace
        request_id: Optional unique request identifier
    """
    
    message: str
    level: LogLevel = LogLevel.INFO
    timestamp: Optional[datetime] = None
    source: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> dict[str, Any]:
        """
        Serialize log entry to dictionary.
        
        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "message": self.message,
            "level": self.level.value,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "metadata": self.metadata,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "request_id": self.request_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogEntry":
        """
        Create LogEntry from dictionary.
        
        Args:
            data: Dictionary with log entry fields
            
        Returns:
            New LogEntry instance
        """
        level = data.get("level", "info")
        if isinstance(level, str):
            level = LogLevel(level.lower())
        
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        return cls(
            message=data.get("message", ""),
            level=level,
            timestamp=timestamp,
            source=data.get("source"),
            metadata=data.get("metadata", {}),
            trace_id=data.get("trace_id"),
            span_id=data.get("span_id"),
            request_id=data.get("request_id"),
        )


@dataclass
class LogBatch:
    """
    Collection of log entries for batch processing.
    
    Attributes:
        entries: List of log entries in the batch
        source: Common source for all entries (if applicable)
        batch_id: Unique identifier for this batch
    """
    
    entries: list[LogEntry] = field(default_factory=list)
    source: Optional[str] = None
    batch_id: Optional[str] = None
    
    @property
    def count(self) -> int:
        """Get the number of entries in the batch."""
        return len(self.entries)
    
    def add(self, entry: LogEntry) -> None:
        """
        Add an entry to the batch.
        
        Args:
            entry: Log entry to add
        """
        self.entries.append(entry)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize batch to dictionary."""
        return {
            "entries": [e.to_dict() for e in self.entries],
            "source": self.source,
            "batch_id": self.batch_id,
            "count": self.count,
        }


@dataclass
class RetrievalResult:
    """
    Result from RAG retrieval with explainability data.
    
    Attributes:
        content: Retrieved document content
        source: Document source (e.g., "mitre_attack", "cve")
        relevance_score: Similarity/relevance score (0-1)
        metadata: Additional document metadata
        chunk_id: ID of the specific chunk retrieved
    """
    
    content: str
    source: str
    relevance_score: float
    metadata: dict[str, Any] = field(default_factory=dict)
    chunk_id: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "content": self.content,
            "source": self.source,
            "relevance_score": self.relevance_score,
            "metadata": self.metadata,
            "chunk_id": self.chunk_id,
        }


@dataclass
class AnalysisRequest:
    """
    Request for security analysis.
    
    Attributes:
        logs: Log batch to analyze
        include_rag: Whether to use RAG context enrichment
        top_k: Number of context documents to retrieve
        score_threshold: Minimum relevance score for retrieval
        explain: Whether to include explainability data
    """
    
    logs: LogBatch
    include_rag: bool = True
    top_k: int = 5
    score_threshold: float = 0.5
    explain: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "logs": self.logs.to_dict(),
            "include_rag": self.include_rag,
            "top_k": self.top_k,
            "score_threshold": self.score_threshold,
            "explain": self.explain,
        }


@dataclass
class PatchSuggestion:
    """
    Structured patch/remediation suggestion.
    
    Attributes:
        category: Vulnerability category
        title: Short descriptive title
        description: What to patch and why
        priority: Remediation priority
        commands: Specific commands to run
    """
    
    category: EventType
    title: str
    description: str
    priority: str = "medium"
    commands: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "commands": self.commands,
        }


@dataclass
class AnalysisResult:
    """
    Complete security analysis result.
    
    Attributes:
        severity_score: Numeric severity (0-10)
        severity_level: Categorical severity
        threat_assessment: Brief analysis summary
        detailed_explanation: Full analysis reasoning
        vulnerability_categories: Detected vulnerability types
        countermeasures: Immediate actions to take
        patch_suggestions: Structured remediation steps
        retrieved_context: RAG context used (if explain=True)
        trace_id: Distributed trace ID for this analysis
        timestamp: When analysis was performed
    """
    
    severity_score: int
    severity_level: SeverityLevel
    threat_assessment: str
    detailed_explanation: str
    vulnerability_categories: list[EventType] = field(default_factory=list)
    countermeasures: list[str] = field(default_factory=list)
    patch_suggestions: list[PatchSuggestion] = field(default_factory=list)
    retrieved_context: list[RetrievalResult] = field(default_factory=list)
    trace_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "severity_score": self.severity_score,
            "severity_level": self.severity_level.value,
            "threat_assessment": self.threat_assessment,
            "detailed_explanation": self.detailed_explanation,
            "vulnerability_categories": [c.value for c in self.vulnerability_categories],
            "countermeasures": self.countermeasures,
            "patch_suggestions": [p.to_dict() for p in self.patch_suggestions],
            "retrieved_context": [r.to_dict() for r in self.retrieved_context],
            "trace_id": self.trace_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class SDKConfig:
    """
    SDK configuration with sensible defaults.
    
    Supports progressive disclosure - basic config works out of the box,
    advanced options available when needed.
    
    Attributes:
        api_key: LogCentry API key
        endpoint: API endpoint URL
        batch_size: Logs to batch before sending
        flush_interval: Seconds between auto-flushes
        timeout: Request timeout in seconds
        max_retries: Maximum retry attempts
        enable_tracing: Enable OpenTelemetry tracing
        log_level: SDK internal log level
        verify_ssl: Verify TLS certificates
    """
    
    api_key: str
    endpoint: str = "http://localhost:8000"
    batch_size: int = 10
    flush_interval: float = 5.0
    timeout: float = 30.0
    max_retries: int = 3
    enable_tracing: bool = False
    log_level: str = "INFO"
    verify_ssl: bool = True
    
    # RAG configuration (progressive disclosure)
    rag_top_k: int = 5
    rag_score_threshold: float = 0.5
    rag_chunk_size: int = 512
    rag_chunk_overlap: int = 50
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "api_key": "[REDACTED]",  # Never expose API key
            "endpoint": self.endpoint,
            "batch_size": self.batch_size,
            "flush_interval": self.flush_interval,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "enable_tracing": self.enable_tracing,
            "log_level": self.log_level,
            "verify_ssl": self.verify_ssl,
            "rag_top_k": self.rag_top_k,
            "rag_score_threshold": self.rag_score_threshold,
            "rag_chunk_size": self.rag_chunk_size,
            "rag_chunk_overlap": self.rag_chunk_overlap,
        }
