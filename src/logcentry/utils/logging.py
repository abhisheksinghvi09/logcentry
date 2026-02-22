"""
LogCentry Utilities - Structured Logging Module

Provides consistent, structured logging throughout the application using structlog.
Supports both console and file output with proper security considerations.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import structlog


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    json_output: bool = False,
) -> structlog.stdlib.BoundLogger:
    """
    Configure structured logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        json_output: If True, output JSON logs (for machine parsing)
        
    Returns:
        Configured logger instance
    """
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper()),
        stream=sys.stderr,
    )
    
    # Add file handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(getattr(logging, level.upper()))
        logging.getLogger().addHandler(file_handler)
    
    # Configure structlog processors
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if json_output:
        # JSON output for production/parsing
        shared_processors.append(structlog.processors.JSONRenderer())
    else:
        # Pretty console output for development
        shared_processors.append(
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            )
        )
    
    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger()


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a logger instance with optional name binding.
    
    Args:
        name: Optional logger name (e.g., module name)
        
    Returns:
        Bound logger instance
    """
    logger = structlog.get_logger()
    if name:
        logger = logger.bind(component=name)
    return logger


def sanitize_log_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Remove or mask sensitive data from log entries.
    
    Args:
        data: Dictionary of data to log
        
    Returns:
        Sanitized dictionary safe for logging
    """
    sensitive_keys = {
        "api_key", "apikey", "api-key",
        "password", "passwd", "pwd",
        "secret", "token", "auth",
        "credential", "key",
    }
    
    sanitized = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_log_data(value)
        else:
            sanitized[key] = value
    
    return sanitized
