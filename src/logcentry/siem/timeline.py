"""
LogCentry SIEM - Incident Timeline

Builds chronological timelines of events for incident investigation.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from logcentry.utils import get_logger

logger = get_logger(__name__)


@dataclass
class TimelineEvent:
    """A single event in an incident timeline."""
    timestamp: datetime
    event_type: str  # "log", "alert", "anomaly"
    source: str
    message: str
    severity: str = "info"
    entity: str | None = None  # user or IP
    log_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source": self.source,
            "message": self.message,
            "severity": self.severity,
            "entity": self.entity,
            "log_id": self.log_id,
            "metadata": self.metadata,
        }


@dataclass
class IncidentTimeline:
    """Complete incident timeline with analysis."""
    entity: str
    entity_type: str  # "user" or "ip"
    start_time: datetime
    end_time: datetime
    events: list[TimelineEvent] = field(default_factory=list)
    summary: str = ""
    severity: str = "medium"
    attack_chain_stages: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def event_count(self) -> int:
        return len(self.events)
    
    def to_dict(self) -> dict:
        return {
            "entity": self.entity,
            "entity_type": self.entity_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "event_count": self.event_count,
            "events": [e.to_dict() for e in self.events],
            "summary": self.summary,
            "severity": self.severity,
            "attack_chain_stages": self.attack_chain_stages,
            "mitre_techniques": self.mitre_techniques,
        }


class TimelineBuilder:
    """
    Builds incident timelines for investigation.
    
    Combines logs, alerts, and anomalies into a chronological narrative.
    """
    
    # Kill chain stage detection keywords
    KILL_CHAIN_KEYWORDS = {
        "reconnaissance": ["scan", "probe", "enum", "discovery"],
        "initial_access": ["login", "auth", "connect", "access"],
        "execution": ["command", "script", "exec", "shell"],
        "persistence": ["cron", "service", "scheduled", "startup"],
        "privilege_escalation": ["sudo", "root", "admin", "privilege"],
        "credential_access": ["password", "credential", "brute", "hash"],
        "lateral_movement": ["remote", "ssh", "rdp", "smb"],
        "exfiltration": ["upload", "transfer", "exfil", "send"],
    }
    
    def __init__(self):
        pass
    
    def _parse_timestamp(self, value: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                pass
        return None
    
    def _detect_stages(self, logs: list[dict]) -> list[str]:
        """Detect kill chain stages from logs."""
        stages = set()
        
        for log in logs:
            message = log.get("message", "").lower()
            for stage, keywords in self.KILL_CHAIN_KEYWORDS.items():
                if any(kw in message for kw in keywords):
                    stages.add(stage)
        
        # Order by kill chain sequence
        stage_order = list(self.KILL_CHAIN_KEYWORDS.keys())
        return [s for s in stage_order if s in stages]
    
    def _detect_severity(self, logs: list[dict], stages: list[str]) -> str:
        """Calculate overall severity."""
        # More stages = more severe
        if len(stages) >= 4:
            return "critical"
        if len(stages) >= 2:
            return "high"
        
        # Check log levels
        security_count = sum(1 for l in logs if l.get("level", "").lower() in ("security", "critical", "error"))
        if security_count >= 5:
            return "high"
        if security_count >= 2:
            return "medium"
        
        return "low"
    
    def _generate_summary(
        self,
        entity: str,
        entity_type: str,
        events: list[TimelineEvent],
        stages: list[str],
    ) -> str:
        """Generate a narrative summary of the incident."""
        if not events:
            return "No events in timeline."
        
        duration = (events[-1].timestamp - events[0].timestamp).total_seconds()
        duration_str = (
            f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m"
            if duration >= 3600
            else f"{int(duration // 60)} minutes"
        )
        
        # Count by severity
        by_severity = {}
        for e in events:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        
        summary_parts = [
            f"Incident timeline for {entity_type} '{entity}': ",
            f"{len(events)} events over {duration_str}. ",
        ]
        
        if stages:
            summary_parts.append(f"Attack chain: {' → '.join(stages)}. ")
        
        if "critical" in by_severity or "high" in by_severity:
            high_count = by_severity.get("critical", 0) + by_severity.get("high", 0)
            summary_parts.append(f"Contains {high_count} high-severity events.")
        
        return "".join(summary_parts)
    
    def build_timeline(
        self,
        logs: list[dict],
        entity: str,
        entity_type: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> IncidentTimeline:
        """
        Build an incident timeline from logs.
        
        Args:
            logs: Log entries to include
            entity: The user or IP being investigated
            entity_type: "user" or "ip"
            start_time: Optional start time filter
            end_time: Optional end time filter
            
        Returns:
            Built IncidentTimeline
        """
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=24)
        if end_time is None:
            end_time = datetime.utcnow()
        
        # Filter and convert logs to timeline events
        events = []
        for log in logs:
            ts = self._parse_timestamp(log.get("timestamp"))
            if not ts:
                continue
            
            if ts < start_time or ts > end_time:
                continue
            
            # Determine severity from log level
            level = log.get("level", "info").lower()
            if level in ("critical", "security"):
                severity = "critical"
            elif level == "error":
                severity = "high"
            elif level == "warning":
                severity = "medium"
            else:
                severity = "low"
            
            events.append(TimelineEvent(
                timestamp=ts,
                event_type="log",
                source=log.get("source", "unknown"),
                message=log.get("message", ""),
                severity=severity,
                entity=entity,
                log_id=log.get("id"),
                metadata=log.get("metadata", {}),
            ))
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Detect kill chain stages
        stages = self._detect_stages(logs)
        severity = self._detect_severity(logs, stages)
        
        # Map stages to MITRE techniques (basic mapping)
        mitre_map = {
            "reconnaissance": "T1046",
            "initial_access": "T1078",
            "execution": "T1059",
            "persistence": "T1053",
            "privilege_escalation": "T1548",
            "credential_access": "T1110",
            "lateral_movement": "T1021",
            "exfiltration": "T1041",
        }
        mitre_techniques = [mitre_map[s] for s in stages if s in mitre_map]
        
        # Generate summary
        summary = self._generate_summary(entity, entity_type, events, stages)
        
        # Update actual start/end times based on events
        if events:
            start_time = events[0].timestamp
            end_time = events[-1].timestamp
        
        timeline = IncidentTimeline(
            entity=entity,
            entity_type=entity_type,
            start_time=start_time,
            end_time=end_time,
            events=events,
            summary=summary,
            severity=severity,
            attack_chain_stages=stages,
            mitre_techniques=mitre_techniques,
        )
        
        logger.info(
            "timeline_built",
            entity=entity,
            entity_type=entity_type,
            event_count=len(events),
            stages=stages,
        )
        return timeline
    
    def build_timeline_for_correlation(
        self,
        correlated_event: "CorrelatedEvent",  # From correlation.py
        entity_type: str = "ip",
    ) -> IncidentTimeline:
        """
        Build a timeline from a correlated event group.
        
        Args:
            correlated_event: A CorrelatedEvent from the correlation engine
            entity_type: "user" or "ip"
            
        Returns:
            IncidentTimeline
        """
        return self.build_timeline(
            logs=correlated_event.events,
            entity=correlated_event.entity,
            entity_type=entity_type,
            start_time=correlated_event.start_time,
            end_time=correlated_event.end_time,
        )
