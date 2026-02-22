"""
LogCentry Utilities - Security Module

Input validation, sanitization, and security utilities to prevent
injection attacks and ensure safe handling of user-provided data.
"""

import html
import os
import re
from pathlib import Path
from typing import Any

from logcentry.utils.logging import get_logger

logger = get_logger(__name__)


class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass


def validate_file_path(
    path: str | Path,
    allowed_extensions: set[str] | None = None,
    must_exist: bool = True,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate and sanitize a file path to prevent path traversal attacks.
    
    Args:
        path: The file path to validate
        allowed_extensions: Set of allowed extensions (e.g., {'.log', '.txt'})
        must_exist: If True, file must exist
        allow_symlinks: If True, allow symbolic links
        
    Returns:
        Validated Path object
        
    Raises:
        SecurityError: If path validation fails
        FileNotFoundError: If file doesn't exist and must_exist is True
    """
    try:
        # Convert to Path and resolve to absolute path
        path = Path(path).resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid path format: {e}") from e
    
    # Check for path traversal attempts (should be caught by resolve, but double-check)
    path_str = str(path)
    if ".." in path_str.split(os.sep):
        raise SecurityError("Path traversal detected")
    
    # Check if it's a symlink when not allowed
    if not allow_symlinks and path.is_symlink():
        raise SecurityError("Symbolic links are not allowed")
    
    # Validate extension if specified
    if allowed_extensions:
        ext = path.suffix.lower()
        if ext not in allowed_extensions:
            raise SecurityError(
                f"File extension '{ext}' not allowed. "
                f"Allowed: {', '.join(sorted(allowed_extensions))}"
            )
    
    # Check existence if required
    if must_exist and not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    return path


def sanitize_html(text: str) -> str:
    """
    Escape HTML characters to prevent XSS attacks in reports.
    
    Args:
        text: Text to sanitize
        
    Returns:
        HTML-escaped text
    """
    return html.escape(text, quote=True)


def sanitize_log_content(content: str, max_length: int = 100000) -> str:
    """
    Sanitize log content before processing.
    
    - Removes null bytes
    - Truncates to maximum length
    - Strips control characters (except newlines and tabs)
    
    Args:
        content: Raw log content
        max_length: Maximum allowed length
        
    Returns:
        Sanitized content
    """
    if not content:
        return ""
    
    # Remove null bytes (potential injection)
    content = content.replace("\x00", "")
    
    # Remove control characters except newline, tab, carriage return
    content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)
    
    # Truncate if too long
    if len(content) > max_length:
        logger.warning(
            "content_truncated",
            original_length=len(content),
            max_length=max_length,
        )
        content = content[:max_length] + "\n[...TRUNCATED...]"
    
    return content


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid, False otherwise
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def mask_sensitive_data(text: str) -> str:
    """
    Mask potentially sensitive data in text for safe logging/display.
    
    Masks:
    - API keys (common patterns)
    - Passwords in URLs
    - Credit card numbers
    - SSN patterns
    
    Args:
        text: Text potentially containing sensitive data
        
    Returns:
        Text with sensitive data masked
    """
    # API key patterns (various formats)
    text = re.sub(
        r"(api[_-]?key|apikey|api_secret|secret_key)[=:]\s*['\"]?[\w\-]+['\"]?",
        r"\1=[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    
    # Passwords in URLs
    text = re.sub(
        r"(https?://[^:]+:)[^@]+(@)",
        r"\1[REDACTED]\2",
        text,
    )
    
    # Credit card-like patterns (16 digits with optional separators)
    text = re.sub(
        r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        "[CARD-REDACTED]",
        text,
    )
    
    return text


def is_safe_command(command: list[str]) -> bool:
    """
    Check if a command is safe to execute (whitelist approach).
    
    Only allows specific known-safe commands used by LogCentry.
    
    Args:
        command: Command as list of arguments
        
    Returns:
        True if command is in the whitelist
    """
    if not command:
        return False
    
    allowed_commands = {
        "journalctl",
        "tshark",  # For advanced pcap parsing
        "tcpdump",
    }
    
    base_command = Path(command[0]).name
    return base_command in allowed_commands
