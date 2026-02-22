"""
LogCentry SIEM - User and Entity Behavior Analytics (UEBA)

Behavioral baseline analysis and anomaly detection for users and entities.
"""

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from logcentry.utils import get_logger

logger = get_logger(__name__)


@dataclass
class EntityProfile:
    """
    Behavioral profile for a user or IP address.
    
    Tracks baseline behavior patterns for anomaly detection.
    """
    entity_id: str
    entity_type: str  # "user" or "ip"
    project_id: str | None = None
    
    # Activity patterns
    typical_hours: list[int] = field(default_factory=list)  # Hours 0-23 when usually active
    typical_days: list[int] = field(default_factory=list)  # Days 0-6 when usually active
    typical_sources: list[str] = field(default_factory=list)  # Usual source IPs/users
    
    # Statistical baselines
    avg_events_per_hour: float = 0.0
    avg_events_per_session: float = 0.0
    max_events_per_hour: int = 0
    
    # Historical data
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_events: int = 0
    
    # Risk assessment
    risk_score: float = 0.0  # 0-100
    anomaly_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "project_id": self.project_id,
            "typical_hours": self.typical_hours,
            "typical_days": self.typical_days,
            "typical_sources": self.typical_sources,
            "avg_events_per_hour": round(self.avg_events_per_hour, 2),
            "avg_events_per_session": round(self.avg_events_per_session, 2),
            "max_events_per_hour": self.max_events_per_hour,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_events": self.total_events,
            "risk_score": round(self.risk_score, 1),
            "anomaly_count": self.anomaly_count,
        }


@dataclass 
class Anomaly:
    """Detected behavioral anomaly."""
    anomaly_type: str  # "unusual_hour", "high_volume", "new_source", etc.
    entity_id: str
    entity_type: str
    severity: str  # "low", "medium", "high"
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "anomaly_type": self.anomaly_type,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class UEBAEngine:
    """
    User and Entity Behavior Analytics Engine.
    
    Features:
    - Dynamic baseline creation per entity
    - Anomaly detection for unusual behaviors
    - Risk scoring
    - Peer group comparison (basic)
    """
    
    def __init__(self):
        self._profiles: dict[str, EntityProfile] = {}  # entity_id -> profile
        self._hourly_counts: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
    
    def _get_profile_key(self, entity_id: str, entity_type: str) -> str:
        """Generate unique profile key."""
        return f"{entity_type}:{entity_id}"
    
    def _parse_timestamp(self, log: dict) -> datetime | None:
        """Parse timestamp from log."""
        ts = log.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                pass
        return None
    
    def _extract_entity_from_logs(self, logs: list[dict], entity_type: str) -> dict[str, list[dict]]:
        """Group logs by entity (user or IP)."""
        import re
        
        entity_logs: dict[str, list[dict]] = defaultdict(list)
        
        for log in logs:
            metadata = log.get("metadata")
            if not metadata:
                metadata = {}
            elif isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}
            
            entity = None
            if entity_type == "user":
                entity = metadata.get("user") or metadata.get("username")
                if not entity:
                    # Try message parsing
                    match = re.search(r"user[:\s]+['\"]?(\w+)", log.get("message", ""), re.I)
                    if match:
                        entity = match.group(1)
            else:  # ip
                entity = metadata.get("ip") or metadata.get("source_ip")
                if not entity:
                    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log.get("message", ""))
                    if match:
                        entity = match.group()
            
            if entity:
                entity_logs[entity].append(log)
        
        return entity_logs
    
    def update_baseline(
        self,
        entity_id: str,
        entity_type: str,
        logs: list[dict],
        project_id: str | None = None,
    ) -> EntityProfile:
        """
        Update behavioral baseline for an entity.
        
        Args:
            entity_id: The user or IP identifier
            entity_type: "user" or "ip"
            logs: Historical logs for this entity
            project_id: Optional project filter
            
        Returns:
            Updated EntityProfile
        """
        key = self._get_profile_key(entity_id, entity_type)
        profile = self._profiles.get(key)
        
        if not profile:
            profile = EntityProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                project_id=project_id,
            )
            self._profiles[key] = profile
        
        if not logs:
            return profile
        
        # Extract timestamps
        timestamps = []
        for log in logs:
            ts = self._parse_timestamp(log)
            if ts:
                timestamps.append(ts)
        
        if timestamps:
            timestamps.sort()
            
            # Update first/last seen
            if not profile.first_seen or timestamps[0] < profile.first_seen:
                profile.first_seen = timestamps[0]
            if not profile.last_seen or timestamps[-1] > profile.last_seen:
                profile.last_seen = timestamps[-1]
            
            # Calculate typical hours
            hours = [ts.hour for ts in timestamps]
            hour_counts = defaultdict(int)
            for h in hours:
                hour_counts[h] += 1
            
            # Keep top 8 most common hours
            sorted_hours = sorted(hour_counts.items(), key=lambda x: -x[1])
            profile.typical_hours = [h for h, _ in sorted_hours[:8]]
            
            # Calculate typical days
            days = [ts.weekday() for ts in timestamps]
            day_counts = defaultdict(int)
            for d in days:
                day_counts[d] += 1
            sorted_days = sorted(day_counts.items(), key=lambda x: -x[1])
            profile.typical_days = [d for d, _ in sorted_days[:5]]
            
            # Calculate hourly event rates
            hourly_buckets: dict[str, int] = defaultdict(int)
            for ts in timestamps:
                bucket = ts.strftime("%Y-%m-%d-%H")
                hourly_buckets[bucket] += 1
            
            if hourly_buckets:
                counts = list(hourly_buckets.values())
                profile.avg_events_per_hour = statistics.mean(counts)
                profile.max_events_per_hour = max(counts)
        
        # Update total events
        profile.total_events += len(logs)
        
        # Extract typical sources (other entities they interact with)
        sources = set()
        for log in logs:
            metadata = log.get("metadata", {})
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}
            
            source = log.get("source") or metadata.get("source")
            if source:
                sources.add(source)
        
        profile.typical_sources = list(sources)[:10]
        
        logger.info(
            "baseline_updated",
            entity_id=entity_id,
            entity_type=entity_type,
            total_events=profile.total_events,
        )
        return profile
    
    def detect_anomalies(
        self,
        entity_id: str,
        entity_type: str,
        current_logs: list[dict],
    ) -> list[Anomaly]:
        """
        Detect anomalies for an entity based on current behavior vs baseline.
        
        Args:
            entity_id: The entity to check
            entity_type: "user" or "ip"
            current_logs: Recent logs for this entity
            
        Returns:
            List of detected anomalies
        """
        key = self._get_profile_key(entity_id, entity_type)
        profile = self._profiles.get(key)
        
        if not profile or not current_logs:
            return []
        
        anomalies = []
        
        # Extract current timestamps
        current_timestamps = []
        for log in current_logs:
            ts = self._parse_timestamp(log)
            if ts:
                current_timestamps.append(ts)
        
        if not current_timestamps:
            return []
        
        # Check 1: Unusual hour activity
        if profile.typical_hours:
            current_hours = set(ts.hour for ts in current_timestamps)
            unusual_hours = current_hours - set(profile.typical_hours)
            
            if unusual_hours:
                anomalies.append(Anomaly(
                    anomaly_type="unusual_hour",
                    entity_id=entity_id,
                    entity_type=entity_type,
                    severity="medium",
                    description=f"Activity detected during unusual hours: {sorted(unusual_hours)}",
                    details={
                        "unusual_hours": list(unusual_hours),
                        "typical_hours": profile.typical_hours,
                    },
                ))
        
        # Check 2: High volume activity
        if profile.avg_events_per_hour > 0:
            current_rate = len(current_logs)  # Assuming these are from ~1 hour
            threshold = max(profile.avg_events_per_hour * 3, profile.max_events_per_hour * 1.5)
            
            if current_rate > threshold:
                severity = "high" if current_rate > threshold * 2 else "medium"
                anomalies.append(Anomaly(
                    anomaly_type="high_volume",
                    entity_id=entity_id,
                    entity_type=entity_type,
                    severity=severity,
                    description=f"Unusually high activity: {current_rate} events (baseline avg: {profile.avg_events_per_hour:.1f})",
                    details={
                        "current_count": current_rate,
                        "baseline_avg": profile.avg_events_per_hour,
                        "baseline_max": profile.max_events_per_hour,
                    },
                ))
        
        # Check 3: New entity (first time seen recently)
        if profile.first_seen:
            age = datetime.utcnow() - profile.first_seen
            if age < timedelta(hours=24):
                anomalies.append(Anomaly(
                    anomaly_type="new_entity",
                    entity_id=entity_id,
                    entity_type=entity_type,
                    severity="low",
                    description=f"New {entity_type} first seen {age.total_seconds()/3600:.1f} hours ago",
                    details={
                        "first_seen": profile.first_seen.isoformat(),
                        "age_hours": age.total_seconds() / 3600,
                    },
                ))
        
        # Update profile anomaly count
        if anomalies:
            profile.anomaly_count += len(anomalies)
            self._update_risk_score(profile, anomalies)
        
        return anomalies
    
    def _update_risk_score(self, profile: EntityProfile, new_anomalies: list[Anomaly]) -> None:
        """Update risk score based on anomalies."""
        severity_scores = {"low": 5, "medium": 15, "high": 30}
        
        for anomaly in new_anomalies:
            profile.risk_score += severity_scores.get(anomaly.severity, 10)
        
        # Decay over time (cap at 100)
        profile.risk_score = min(100, profile.risk_score)
    
    def get_profile(self, entity_id: str, entity_type: str) -> EntityProfile | None:
        """Get entity profile."""
        key = self._get_profile_key(entity_id, entity_type)
        return self._profiles.get(key)
    
    def get_risk_score(self, entity_id: str, entity_type: str) -> float:
        """Get current risk score for an entity."""
        profile = self.get_profile(entity_id, entity_type)
        return profile.risk_score if profile else 0.0
    
    def get_high_risk_entities(self, threshold: float = 50.0) -> list[EntityProfile]:
        """Get entities with risk score above threshold."""
        return [p for p in self._profiles.values() if p.risk_score >= threshold]
    
    def process_logs(
        self,
        logs: list[dict],
        entity_type: str = "user",
        project_id: str | None = None,
    ) -> tuple[list[EntityProfile], list[Anomaly]]:
        """
        Process a batch of logs: update baselines and detect anomalies.
        
        Args:
            logs: List of logs to process
            entity_type: "user" or "ip"
            project_id: Optional project filter
            
        Returns:
            Tuple of (updated profiles, detected anomalies)
        """
        entity_logs = self._extract_entity_from_logs(logs, entity_type)
        
        all_profiles = []
        all_anomalies = []
        
        for entity_id, entity_log_list in entity_logs.items():
            # Get existing baseline for anomaly detection
            anomalies = self.detect_anomalies(entity_id, entity_type, entity_log_list)
            all_anomalies.extend(anomalies)
            
            # Update baseline with new data
            profile = self.update_baseline(entity_id, entity_type, entity_log_list, project_id)
            all_profiles.append(profile)
        
        logger.info(
            "logs_processed",
            entity_type=entity_type,
            entities=len(entity_logs),
            anomalies=len(all_anomalies),
        )
        return all_profiles, all_anomalies


# Global UEBA instance
_ueba_engine: UEBAEngine | None = None


def get_ueba_engine() -> UEBAEngine:
    """Get or create global UEBA engine."""
    global _ueba_engine
    if _ueba_engine is None:
        _ueba_engine = UEBAEngine()
    return _ueba_engine
