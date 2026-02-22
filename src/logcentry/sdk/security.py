"""
LogCentry SDK - Security & Compliance

Security utilities for SDK operations: TLS validation, auth helpers,
audit logging, and GDPR/DPDP compliance hooks.
"""

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional


@dataclass
class SecurityConfig:
    """
    Security configuration for SDK.
    
    Attributes:
        verify_tls: Verify TLS certificates
        min_tls_version: Minimum TLS version required
        api_key_env_var: Environment variable for API key
        audit_log_enabled: Enable audit logging
        data_retention_days: Data retention period (0 = indefinite)
        anonymize_pii: Automatically anonymize PII in logs
    """
    
    verify_tls: bool = True
    min_tls_version: str = "TLSv1.2"
    api_key_env_var: str = "LOGCENTRY_API_KEY"
    audit_log_enabled: bool = True
    data_retention_days: int = 90
    anonymize_pii: bool = False


@dataclass
class AuditEvent:
    """
    Audit log event for compliance.
    
    Attributes:
        action: Action performed
        actor: Who performed the action
        resource: Resource affected
        timestamp: When the action occurred
        result: Success/failure
        metadata: Additional event data
    """
    
    action: str
    actor: str
    resource: str
    timestamp: datetime = field(default_factory=datetime.now)
    result: str = "success"
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "timestamp": self.timestamp.isoformat(),
            "result": self.result,
            "metadata": self.metadata,
        }


class AuditLogger:
    """
    Audit logging for compliance and security.
    
    Tracks all SDK actions for auditing purposes.
    """
    
    def __init__(
        self,
        enabled: bool = True,
        log_callback: Optional[Callable[[AuditEvent], None]] = None,
    ):
        """
        Initialize audit logger.
        
        Args:
            enabled: Whether audit logging is enabled
            log_callback: Optional callback for each audit event
        """
        self.enabled = enabled
        self.log_callback = log_callback
        self._events: list[AuditEvent] = []
    
    def log(
        self,
        action: str,
        actor: str,
        resource: str,
        result: str = "success",
        **metadata,
    ) -> None:
        """
        Log an audit event.
        
        Args:
            action: Action performed (e.g., "log_ingest", "rag_query")
            actor: Who performed the action (e.g., API key prefix)
            resource: Resource affected
            result: Success or failure
            **metadata: Additional event data
        """
        if not self.enabled:
            return
        
        event = AuditEvent(
            action=action,
            actor=actor,
            resource=resource,
            result=result,
            metadata=metadata,
        )
        
        self._events.append(event)
        
        # Cap in-memory events
        if len(self._events) > 10000:
            self._events = self._events[-5000:]
        
        if self.log_callback:
            try:
                self.log_callback(event)
            except Exception:
                pass
    
    def query(
        self,
        action: Optional[str] = None,
        actor: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Query audit events.
        
        Args:
            action: Filter by action
            actor: Filter by actor
            since: Filter events after this time
            limit: Maximum events to return
            
        Returns:
            Matching audit events
        """
        results = self._events
        
        if action:
            results = [e for e in results if e.action == action]
        if actor:
            results = [e for e in results if e.actor == actor]
        if since:
            results = [e for e in results if e.timestamp >= since]
        
        return results[-limit:]
    
    def export(self) -> list[dict]:
        """Export all events as dictionaries."""
        return [e.to_dict() for e in self._events]


class PIIAnonymizer:
    """
    Anonymize personally identifiable information in logs.
    
    Supports email, IP address, phone number, and SSN patterns.
    """
    
    # PII patterns
    PATTERNS = {
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "ip": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        "phone": re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "ssn": re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
        "credit_card": re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
    }
    
    REPLACEMENTS = {
        "email": "[EMAIL_REDACTED]",
        "ip": "[IP_REDACTED]",
        "phone": "[PHONE_REDACTED]",
        "ssn": "[SSN_REDACTED]",
        "credit_card": "[CC_REDACTED]",
    }
    
    def __init__(
        self,
        patterns: Optional[dict[str, re.Pattern]] = None,
        hash_values: bool = False,
    ):
        """
        Initialize anonymizer.
        
        Args:
            patterns: Custom patterns to match
            hash_values: Hash matched values instead of replacing
        """
        self.patterns = patterns or self.PATTERNS
        self.hash_values = hash_values
    
    def anonymize(self, text: str) -> str:
        """
        Anonymize PII in text.
        
        Args:
            text: Text to anonymize
            
        Returns:
            Anonymized text
        """
        result = text
        
        for name, pattern in self.patterns.items():
            if self.hash_values:
                def hasher(match):
                    h = hashlib.sha256(match.group(0).encode()).hexdigest()[:8]
                    return f"[{name.upper()}_{h}]"
                result = pattern.sub(hasher, result)
            else:
                replacement = self.REPLACEMENTS.get(name, f"[{name.upper()}_REDACTED]")
                result = pattern.sub(replacement, result)
        
        return result
    
    def detect(self, text: str) -> dict[str, list[str]]:
        """
        Detect PII in text without modifying.
        
        Args:
            text: Text to scan
            
        Returns:
            Dictionary of PII type to matched values
        """
        found = {}
        
        for name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                found[name] = matches
        
        return found


class TokenValidator:
    """
    Validate and manage API tokens.
    
    Supports JWT-like token validation and HMAC signatures.
    """
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_expiry: int = 3600,
    ):
        """
        Initialize token validator.
        
        Args:
            secret_key: Secret for token signing (generated if not provided)
            token_expiry: Token expiry in seconds
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expiry = token_expiry
    
    def generate_token(
        self,
        payload: dict[str, Any],
        expiry: Optional[int] = None,
    ) -> str:
        """
        Generate a signed token.
        
        Args:
            payload: Token payload
            expiry: Custom expiry in seconds
            
        Returns:
            Signed token string
        """
        import base64
        import json
        
        # Add expiry
        exp = int(time.time()) + (expiry or self.token_expiry)
        payload_with_exp = {**payload, "exp": exp, "iat": int(time.time())}
        
        # Encode payload
        payload_bytes = json.dumps(payload_with_exp).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()
        
        # Sign
        signature = hmac.new(
            self.secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{payload_b64}.{signature}"
    
    def validate_token(self, token: str) -> Optional[dict[str, Any]]:
        """
        Validate and decode a token.
        
        Args:
            token: Token to validate
            
        Returns:
            Decoded payload or None if invalid
        """
        import base64
        import json
        
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            # Verify signature
            expected_sig = hmac.new(
                self.secret_key.encode(),
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
            
            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)
            
            # Check expiry
            if payload.get("exp", 0) < time.time():
                return None
            
            return payload
            
        except Exception:
            return None
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate API key format.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if valid format
        """
        # Expected format: lc_<32-char-hex>
        if not api_key:
            return False
        
        if api_key.startswith("lc_"):
            key_part = api_key[3:]
            return len(key_part) >= 16 and key_part.isalnum()
        
        # Also accept raw keys
        return len(api_key) >= 16


class DataRetentionManager:
    """
    Manage data retention for GDPR/DPDP compliance.
    
    Provides hooks for data deletion and export.
    """
    
    def __init__(
        self,
        retention_days: int = 90,
        on_delete: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize retention manager.
        
        Args:
            retention_days: Default retention period
            on_delete: Callback when data is deleted
        """
        self.retention_days = retention_days
        self.on_delete = on_delete
        self._deletion_requests: list[dict] = []
    
    def request_deletion(
        self,
        subject_id: str,
        reason: str = "user_request",
    ) -> str:
        """
        Request data deletion (GDPR Right to Erasure).
        
        Args:
            subject_id: Identifier of data subject
            reason: Reason for deletion
            
        Returns:
            Deletion request ID
        """
        request_id = secrets.token_hex(8)
        
        self._deletion_requests.append({
            "id": request_id,
            "subject_id": subject_id,
            "reason": reason,
            "requested_at": datetime.now().isoformat(),
            "status": "pending",
        })
        
        return request_id
    
    def process_deletion(self, request_id: str) -> bool:
        """
        Process a deletion request.
        
        Args:
            request_id: Request to process
            
        Returns:
            True if processed successfully
        """
        for request in self._deletion_requests:
            if request["id"] == request_id:
                if self.on_delete:
                    try:
                        self.on_delete(request["subject_id"])
                        request["status"] = "completed"
                        request["completed_at"] = datetime.now().isoformat()
                        return True
                    except Exception as e:
                        request["status"] = "failed"
                        request["error"] = str(e)
                        return False
        
        return False
    
    def export_data(self, subject_id: str) -> dict[str, Any]:
        """
        Export data for a subject (GDPR Right to Access).
        
        Args:
            subject_id: Subject identifier
            
        Returns:
            Exported data
        """
        # This would typically query the database
        # Here we provide the interface
        return {
            "subject_id": subject_id,
            "export_date": datetime.now().isoformat(),
            "data": {},  # Placeholder for actual data
            "retention_policy": f"{self.retention_days} days",
        }
    
    def calculate_expiry(
        self,
        created_at: datetime,
        custom_retention: Optional[int] = None,
    ) -> datetime:
        """
        Calculate data expiry date.
        
        Args:
            created_at: When data was created
            custom_retention: Custom retention in days
            
        Returns:
            Expiry datetime
        """
        days = custom_retention or self.retention_days
        return created_at + timedelta(days=days)


def get_api_key(
    env_var: str = "LOGCENTRY_API_KEY",
    config_file: Optional[str] = None,
) -> Optional[str]:
    """
    Get API key from environment or config file.
    
    Never hardcode API keys!
    
    Args:
        env_var: Environment variable name
        config_file: Optional path to config file
        
    Returns:
        API key or None if not found
    """
    # First try environment variable
    api_key = os.getenv(env_var)
    if api_key:
        return api_key
    
    # Try config file
    if config_file:
        from pathlib import Path
        path = Path(config_file)
        if path.exists():
            try:
                content = path.read_text().strip()
                if content.startswith("lc_"):
                    return content
            except Exception:
                pass
    
    # Try .env file in current directory
    try:
        from pathlib import Path
        env_file = Path(".env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith(f"{env_var}="):
                    return line.split("=", 1)[1].strip().strip('"\'')
    except Exception:
        pass
    
    return None


def mask_api_key(api_key: str, visible_chars: int = 4) -> str:
    """
    Mask an API key for safe logging.
    
    Args:
        api_key: Key to mask
        visible_chars: Number of characters to keep visible at end
        
    Returns:
        Masked key
    """
    if not api_key:
        return "[NO_KEY]"
    
    if len(api_key) <= visible_chars:
        return "*" * len(api_key)
    
    return "*" * (len(api_key) - visible_chars) + api_key[-visible_chars:]
