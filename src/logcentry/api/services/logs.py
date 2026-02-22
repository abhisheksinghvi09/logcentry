"""
LogCentry API - Log Service

Handles database operations for logs using SQLAlchemy.
Replaces the legacy SQLite storage.
"""

import json
import uuid
from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from logcentry.api.database import Log
from logcentry.core.models import LogEntry


class LogService:
    """Service for handling log operations."""

    def __init__(self, db: Session):
        self.db = db

    def store_log(
        self,
        project_id: str,
        level: str,
        message: str,
        source: str | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Store a single log entry.

        Returns:
            Log ID
        """
        log_id = str(uuid.uuid4())
        now = datetime.utcnow()

        log = Log(
            id=log_id,
            project_id=project_id,
            level=level.lower(),
            message=message,
            source=source,
            timestamp=timestamp or now,
            received_at=now,
            log_metadata=json.dumps(metadata) if metadata else None,
        )

        self.db.add(log)
        self.db.commit()
        return log_id

    def store_batch(
        self,
        project_id: str,
        logs: List[dict],
    ) -> List[str]:
        """
        Store multiple log entries.

        Returns:
            List of log IDs
        """
        log_ids = []
        now = datetime.utcnow()
        db_logs = []

        for log_data in logs:
            log_id = str(uuid.uuid4())
            log_ids.append(log_id)

            db_logs.append(
                Log(
                    id=log_id,
                    project_id=project_id,
                    level=log_data.get("level", "info").lower(),
                    message=log_data.get("message", ""),
                    source=log_data.get("source"),
                    timestamp=log_data.get("timestamp") or now,
                    received_at=now,
                    log_metadata=json.dumps(log_data.get("metadata"))
                    if log_data.get("metadata")
                    else None,
                )
            )

        self.db.add_all(db_logs)
        self.db.commit()
        return log_ids

    def get_logs(
        self,
        project_id: str | None = None,
        level: str | None = None,
        limit: int = 100,
        offset: int = 0,
        since: datetime | None = None,
    ) -> List[dict]:
        """
        Query logs with filters.

        Returns:
            List of log entries as dicts
        """
        query = self.db.query(Log)

        if project_id:
            query = query.filter(Log.project_id == project_id)

        if level:
            query = query.filter(Log.level == level.lower())

        if since:
            query = query.filter(Log.timestamp >= since)

        # Order by timestamp desc
        query = query.order_by(desc(Log.timestamp))
        query = query.limit(limit).offset(offset)

        logs = query.all()
        return [log.to_dict() for log in logs]

    def get_log_entries(
        self,
        project_id: str | None = None,
        limit: int = 100,
    ) -> List[LogEntry]:
        """
        Get logs as LogEntry objects for analysis.

        Returns:
            List of LogEntry objects
        """
        # Reuse get_logs logic but return objects
        # We can implement simpler query here to avoid overhead of to_dict then parsing back
        query = self.db.query(Log)
        
        if project_id:
            query = query.filter(Log.project_id == project_id)
            
        query = query.order_by(desc(Log.timestamp)).limit(limit)
        logs = query.all()

        entries = []
        for log in logs:
            entries.append(
                LogEntry(
                    timestamp=log.timestamp,
                    source=log.source or "api",
                    message=log.message,
                    level=log.level.upper(),
                    raw_content=log.message,
                    metadata=json.loads(log.log_metadata) if log.log_metadata else {},
                )
            )
        return entries

    def get_count(self, project_id: str | None = None) -> int:
        """Get total log count."""
        query = self.db.query(func.count(Log.id))
        
        if project_id:
            query = query.filter(Log.project_id == project_id)
            
        return query.scalar() or 0
