"""
LogCentry API - Audit Service

Handles logging of security events (login, signup, failures).
"""

from typing import Optional
from sqlalchemy.orm import Session
from logcentry.api.database import AuditLog

class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def log_event(
        self,
        event: str,
        user_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        """
        Log a security event.
        """
        audit_log = AuditLog(
            user_id=user_id,
            event=event,
            details=details,
            ip_address=ip_address,
        )
        self.db.add(audit_log)
        self.db.commit()
        return audit_log
