"""
LogCentry Configuration Module

Centralized configuration management using Pydantic Settings for type-safe,
validated configuration with environment variable support.
"""

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings with validation and secure defaults.
    
    Settings are loaded from environment variables with LOGCENTRY_ prefix,
    or from a .env file in the project root.
    """
    
    model_config = SettingsConfigDict(
        env_prefix="LOGCENTRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # === API Configuration ===
    # At least one of these API keys should be set
    gemini_api_key: SecretStr | None = Field(
        default=None,
        description="Google Gemini API key (optional if using OpenAI)",
        alias="GEMINI_API_KEY",
    )
    openai_api_key: SecretStr | None = Field(
        default=None,
        description="OpenAI API key (optional if using Gemini)",
        alias="OPENAI_API_KEY",
    )
    model: str = Field(
        default="gemini-2.0-flash",
        description="Model to use for analysis",
    )
    max_retries: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum API retry attempts",
    )
    
    # === Paths ===
    base_dir: Path = Field(
        default_factory=lambda: Path.cwd(),
        description="Base directory for the application",
    )
    reports_dir: Path = Field(
        default=Path("reports"),
        description="Directory for generated reports",
    )
    logs_dir: Path = Field(
        default=Path("logs"),
        description="Directory for application logs",
    )
    data_dir: Path = Field(
        default=Path("data"),
        description="Directory for data files",
    )
    
    # === RAG Configuration ===
    vector_db_path: Path = Field(
        default=Path("data/vectordb"),
        description="Path to ChromaDB vector database",
    )
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2",
        description="Sentence transformer model for embeddings",
    )
    knowledge_base_path: Path = Field(
        default=Path("knowledge_base"),
        description="Path to knowledge base files",
    )
    retrieval_top_k: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of documents to retrieve for RAG context",
    )
    
    # === Dashboard ===
    dashboard_host: str = Field(
        default="127.0.0.1",
        description="Dashboard server host",
    )
    dashboard_port: int = Field(
        default=8080,
        ge=1024,
        le=65535,
        description="Dashboard server port",
    )
    
    # === Analysis Settings ===
    analysis_window_seconds: int = Field(
        default=60,
        ge=10,
        le=600,
        description="Time window for sliding analysis (seconds)",
    )
    analysis_buffer_size: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Maximum events to buffer before analysis",
    )
    
    # === Logging ===
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Application log level",
    )
    log_file: Path | None = Field(
        default=None,
        description="Optional log file path",
    )
    
    @field_validator("reports_dir", "logs_dir", "data_dir", "vector_db_path", mode="after")
    @classmethod
    def ensure_directory_exists(cls, v: Path) -> Path:
        """Create directories if they don't exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @property
    def api_key(self) -> str:
        """Get the Gemini API key as a plain string (for passing to SDK)."""
        if self.gemini_api_key:
            return self.gemini_api_key.get_secret_value()
        return ""
    
    @property
    def openai_key(self) -> str:
        """Get the OpenAI API key as a plain string."""
        if self.openai_api_key:
            return self.openai_api_key.get_secret_value()
        return ""


def get_settings() -> Settings:
    """
    Get application settings, loading from environment/.env file.
    
    Returns:
        Settings: Validated application settings
        
    Raises:
        ValidationError: If required settings are missing or invalid
    """
    return Settings()


# Global settings instance - lazy loaded on first access
_settings: Settings | None = None


def get_cached_settings() -> Settings:
    """Get cached settings instance (singleton pattern)."""
    global _settings
    if _settings is None:
        _settings = get_settings()
    return _settings


# For convenience, export a settings object that will be initialized on import
# This will raise an error if GEMINI_API_KEY is not set
try:
    settings = get_cached_settings()
except Exception:
    # Allow import without settings for testing/documentation
    settings = None  # type: ignore
