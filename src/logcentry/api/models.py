"""
LogCentry API - Request/Response Models

Pydantic models for API endpoints.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class LogRequest(BaseModel):
    """Single log entry from client SDK."""
    
    level: str = Field(
        default="info",
        description="Log level: debug, info, warning, error, critical, security",
    )
    message: str = Field(
        ...,
        description="Log message content",
        max_length=10000,
    )
    timestamp: datetime | None = Field(
        default=None,
        description="Timestamp (defaults to server time)",
    )
    source: str | None = Field(
        default=None,
        description="Source identifier (e.g., 'api', 'auth', 'db')",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (user_id, request_id, etc.)",
    )


class LogBatchRequest(BaseModel):
    """Batch of log entries."""
    
    logs: list[LogRequest] = Field(
        ...,
        description="List of log entries",
        max_length=1000,
    )


class AnalyzeRequest(BaseModel):
    """Request to analyze recent logs."""
    
    log_ids: list[str] | None = Field(
        default=None,
        description="Specific log IDs to analyze (None = last N logs)",
    )
    count: int = Field(
        default=100,
        description="Number of recent logs to analyze",
        ge=1,
        le=1000,
    )
    use_rag: bool = Field(
        default=True,
        description="Use RAG for context-enhanced analysis",
    )


class LogResponse(BaseModel):
    """Response for single log submission."""
    
    id: str
    status: str = "received"
    timestamp: datetime


class BatchLogResponse(BaseModel):
    """Response for batch log submission."""
    
    received: int
    log_ids: list[str]
    status: str = "received"


class PatchSuggestionResponse(BaseModel):
    """Patch suggestion in API response."""
    
    category: str
    title: str
    description: str
    priority: str = "medium"
    commands: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Response from AI analysis."""
    
    analysis_id: str
    severity: int
    severity_label: str
    threat_assessment: str
    countermeasures: list[str]
    mitre_techniques: list[str]
    cves: list[str]
    patch_suggestions: list[PatchSuggestionResponse] = Field(default_factory=list)
    vulnerability_categories: list[str] = Field(default_factory=list)
    analyzed_count: int
    timestamp: datetime


class ProjectInfo(BaseModel):
    """Project/application information."""
    
    project_id: str
    name: str
    api_key_prefix: str
    created_at: datetime
    log_count: int
    last_log_at: datetime | None


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = "healthy"
    version: str
    uptime_seconds: float
    log_count: int
