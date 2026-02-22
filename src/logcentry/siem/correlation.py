"""
LogCentry SIEM - Event Correlation Engine

Correlates related events across time windows and sources to detect 
multi-stage attacks and lateral movement.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from logcentry.utils import get_logger

logger = get_logger(__name__)


@dataclass
class CorrelatedEvent:
    """A group of correlated log events."""
    
    correlation_id: str
    correlation_type: str  # "ip", "user", "attack_chain", "lateral_movement"
    events: list[dict] = field(default_factory=list)
    entity: str = ""  # The common entity (IP or username)
    start_time: datetime | None = None
    end_time: datetime | None = None
    severity: str = "medium"
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ""
    
    @property
    def event_count(self) -> int:
        return len(self.events)
    
    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0
    
    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type,
            "entity": self.entity,
            "event_count": self.event_count,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "summary": self.summary,
            "event_ids": [e.get("id", "") for e in self.events],
        }


class EventCorrelator:
    """
    Event Correlation Engine for SIEM.
    
    Correlates events across:
    - Source IP addresses
    - User accounts  
    - Attack chains (kill chain stages)
    - Lateral movement patterns
    """
    
    # MITRE ATT&CK kill chain stages for attack chain detection
    KILL_CHAIN_STAGES = {
        "reconnaissance": ["scan", "probe", "discovery", "enumerat"],
        "initial_access": ["login", "auth", "access", "connect"],
        "execution": ["exec", "command", "script", "shell", "run"],
        "persistence": ["cron", "service", "startup", "scheduled"],
        "privilege_escalation": ["sudo", "root", "admin", "elevat", "privilege"],
        "defense_evasion": ["disable", "bypass", "clear", "delete log"],
        "credential_access": ["password", "credential", "hash", "dump", "brute"],
        "lateral_movement": ["remote", "ssh", "rdp", "smb", "wmi"],
        "exfiltration": ["upload", "transfer", "exfil", "send"],
    }
    
    # Patterns indicating attack types
    ATTACK_PATTERNS = {
        "brute_force": [
            r"failed.*login",
            r"invalid.*password",
            r"authentication.*fail",
            r"failed password",
        ],
        "sqli": [
            r"sql.*injection",
            r"union.*select",
            r"or\s+1\s*=\s*1",
            r"drop\s+table",
            r"--\s*$",
        ],
        "path_traversal": [
            r"\.\./",
            r"etc/passwd",
            r"\.\.\\",
            r"directory.*traversal",
        ],
        "xss": [
            r"<script",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
        ],
        "rce": [
            r"command.*injection",
            r";\s*cat\s",
            r"\|\s*nc\s",
            r"reverse.*shell",
        ],
    }
    
    def __init__(self, time_window_minutes: int = 5):
        """
        Initialize the correlator.
        
        Args:
            time_window_minutes: Default time window for correlation
        """
        self.time_window_minutes = time_window_minutes
        self._correlation_counter = 0
    
    def _generate_correlation_id(self) -> str:
        """Generate a unique correlation ID."""
        self._correlation_counter += 1
        return f"corr_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{self._correlation_counter}"
    
    def _parse_timestamp(self, log: dict) -> datetime | None:
        """Parse timestamp from log entry."""
        ts = log.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                # Try ISO format first
                return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                pass
        return None
    
    def _extract_ip(self, log: dict) -> str | None:
        """Extract IP address from log."""
        # Check metadata
        metadata = log.get("metadata")
        if not metadata:
            metadata = {}
            
        if isinstance(metadata, str):
            import json
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        ip = metadata.get("ip") or metadata.get("source_ip") or metadata.get("client_ip")
        if ip:
            return ip
        
        # Try to extract from message
        message = log.get("message", "")
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, message)
        if match:
            return match.group()
        
        return None
    
    def _extract_user(self, log: dict) -> str | None:
        """Extract username from log."""
        metadata = log.get("metadata")
        if not metadata:
            metadata = {}

        if isinstance(metadata, str):
            import json
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        user = metadata.get("user") or metadata.get("username") or metadata.get("account")
        if user:
            return user
        
        # Try to extract from message
        message = log.get("message", "")
        user_patterns = [
            r"user[:\s]+['\"]?(\w+)['\"]?",
            r"username[:\s]+['\"]?(\w+)['\"]?",
            r"for\s+(\w+)\s+from",
        ]
        for pattern in user_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _detect_attack_type(self, log: dict) -> list[str]:
        """Detect attack types from log content."""
        message = log.get("message", "").lower()
        detected = []
        
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    detected.append(attack_type)
                    break
        
        return detected
    
    def _detect_kill_chain_stage(self, log: dict) -> list[str]:
        """Detect MITRE ATT&CK kill chain stage."""
        message = log.get("message", "").lower()
        stages = []
        
        for stage, keywords in self.KILL_CHAIN_STAGES.items():
            for keyword in keywords:
                if keyword in message:
                    stages.append(stage)
                    break
        
        return stages
    
    def _calculate_severity(self, events: list[dict], attack_types: list[str]) -> str:
        """Calculate severity based on event characteristics."""
        score = 0
        
        # More events = higher severity
        if len(events) >= 20:
            score += 3
        elif len(events) >= 10:
            score += 2
        elif len(events) >= 5:
            score += 1
        
        # Certain attack types are more severe
        severe_attacks = {"rce", "privilege_escalation", "lateral_movement"}
        if any(a in severe_attacks for a in attack_types):
            score += 3
        
        medium_attacks = {"sqli", "brute_force"}
        if any(a in medium_attacks for a in attack_types):
            score += 2
        
        # Security level logs add severity
        security_count = sum(1 for e in events if e.get("level", "").lower() in ("security", "critical", "error"))
        if security_count >= 5:
            score += 2
        elif security_count >= 2:
            score += 1
        
        if score >= 5:
            return "critical"
        elif score >= 3:
            return "high"
        elif score >= 1:
            return "medium"
        return "low"
    
    def correlate_by_ip(
        self,
        logs: list[dict],
        time_window_minutes: int | None = None,
        min_events: int = 3,
    ) -> list[CorrelatedEvent]:
        """
        Correlate events by source IP address.
        
        Args:
            logs: List of log entries
            time_window_minutes: Time window for correlation
            min_events: Minimum events to form a correlation
            
        Returns:
            List of correlated event groups
        """
        window = time_window_minutes or self.time_window_minutes
        
        # Group logs by IP
        ip_groups: dict[str, list[dict]] = defaultdict(list)
        for log in logs:
            ip = self._extract_ip(log)
            if ip:
                ip_groups[ip].append(log)
        
        correlations = []
        for ip, events in ip_groups.items():
            if len(events) < min_events:
                continue
            
            # Sort by timestamp
            events.sort(key=lambda x: self._parse_timestamp(x) or datetime.min)
            
            # Check time window
            timestamps = [self._parse_timestamp(e) for e in events]
            valid_ts = [t for t in timestamps if t]
            
            if valid_ts:
                duration = (max(valid_ts) - min(valid_ts)).total_seconds() / 60
                if duration > window * 2:
                    # Split into multiple correlations if too spread out
                    continue
            
            # Detect characteristics
            attack_types = []
            for e in events:
                attack_types.extend(self._detect_attack_type(e))
            attack_types = list(set(attack_types))
            
            # Map to MITRE techniques
            mitre_map = {
                "brute_force": "T1110",
                "sqli": "T1190",
                "path_traversal": "T1083",
                "xss": "T1059.007",
                "rce": "T1059",
            }
            mitre_techniques = [mitre_map.get(a, "") for a in attack_types if a in mitre_map]
            
            severity = self._calculate_severity(events, attack_types)
            
            summary = f"Detected {len(events)} events from IP {ip}"
            if attack_types:
                summary += f" - Attack types: {', '.join(attack_types)}"
            
            correlations.append(CorrelatedEvent(
                correlation_id=self._generate_correlation_id(),
                correlation_type="ip",
                events=events,
                entity=ip,
                start_time=min(valid_ts) if valid_ts else None,
                end_time=max(valid_ts) if valid_ts else None,
                severity=severity,
                mitre_techniques=mitre_techniques,
                summary=summary,
            ))
        
        logger.info(f"correlate_by_ip completed", ip_groups=len(ip_groups), correlations=len(correlations))
        return correlations
    
    def correlate_by_user(
        self,
        logs: list[dict],
        time_window_minutes: int | None = None,
        min_events: int = 3,
    ) -> list[CorrelatedEvent]:
        """
        Correlate events by username.
        
        Args:
            logs: List of log entries
            time_window_minutes: Time window for correlation
            min_events: Minimum events to form a correlation
            
        Returns:
            List of correlated event groups
        """
        window = time_window_minutes or self.time_window_minutes
        
        # Group logs by user
        user_groups: dict[str, list[dict]] = defaultdict(list)
        for log in logs:
            user = self._extract_user(log)
            if user:
                user_groups[user].append(log)
        
        correlations = []
        for user, events in user_groups.items():
            if len(events) < min_events:
                continue
            
            # Sort by timestamp
            events.sort(key=lambda x: self._parse_timestamp(x) or datetime.min)
            
            timestamps = [self._parse_timestamp(e) for e in events]
            valid_ts = [t for t in timestamps if t]
            
            # Detect characteristics
            attack_types = []
            kill_chain_stages = []
            for e in events:
                attack_types.extend(self._detect_attack_type(e))
                kill_chain_stages.extend(self._detect_kill_chain_stage(e))
            attack_types = list(set(attack_types))
            kill_chain_stages = list(set(kill_chain_stages))
            
            severity = self._calculate_severity(events, attack_types)
            
            summary = f"Detected {len(events)} events for user '{user}'"
            if attack_types:
                summary += f" - Attack indicators: {', '.join(attack_types)}"
            
            correlations.append(CorrelatedEvent(
                correlation_id=self._generate_correlation_id(),
                correlation_type="user", 
                events=events,
                entity=user,
                start_time=min(valid_ts) if valid_ts else None,
                end_time=max(valid_ts) if valid_ts else None,
                severity=severity,
                mitre_techniques=[],
                summary=summary,
            ))
        
        logger.info(f"correlate_by_user completed", user_groups=len(user_groups), correlations=len(correlations))
        return correlations
    
    def detect_attack_chain(self, logs: list[dict]) -> list[CorrelatedEvent]:
        """
        Detect multi-stage attack chains using kill chain analysis.
        
        Looks for sequences of events that match the attack kill chain:
        reconnaissance -> initial_access -> execution -> persistence -> etc.
        
        Returns:
            List of correlated attack chain events
        """
        # Group by entity (IP or user)
        entity_events: dict[str, list[tuple[dict, list[str]]]] = defaultdict(list)
        
        for log in logs:
            stages = self._detect_kill_chain_stage(log)
            if not stages:
                continue
            
            entity = self._extract_ip(log) or self._extract_user(log) or "unknown"
            entity_events[entity].append((log, stages))
        
        correlations = []
        for entity, events_with_stages in entity_events.items():
            if len(events_with_stages) < 2:
                continue
            
            # Check if multiple kill chain stages are present
            all_stages = set()
            for _, stages in events_with_stages:
                all_stages.update(stages)
            
            # Need at least 2 different stages for attack chain
            if len(all_stages) < 2:
                continue
            
            events = [e for e, _ in events_with_stages]
            events.sort(key=lambda x: self._parse_timestamp(x) or datetime.min)
            
            timestamps = [self._parse_timestamp(e) for e in events]
            valid_ts = [t for t in timestamps if t]
            
            # Higher severity for longer kill chains
            severity = "critical" if len(all_stages) >= 4 else "high" if len(all_stages) >= 3 else "medium"
            
            stage_names = sorted(all_stages)
            summary = f"Attack chain detected from {entity}: {' -> '.join(stage_names)}"
            
            correlations.append(CorrelatedEvent(
                correlation_id=self._generate_correlation_id(),
                correlation_type="attack_chain",
                events=events,
                entity=entity,
                start_time=min(valid_ts) if valid_ts else None,
                end_time=max(valid_ts) if valid_ts else None,
                severity=severity,
                mitre_techniques=["T1078", "T1059"],  # Generic chain techniques
                summary=summary,
            ))
        
        logger.info(f"detect_attack_chain completed", entities=len(entity_events), chains=len(correlations))
        return correlations
    
    def find_lateral_movement(self, logs: list[dict]) -> list[CorrelatedEvent]:
        """
        Detect lateral movement patterns.
        
        Looks for:
        - Same user authenticating from multiple IPs
        - Credential hopping (IP -> user -> new IP pattern)
        
        Returns:
            List of correlated lateral movement events
        """
        # Track user -> IPs mapping
        user_ips: dict[str, set[str]] = defaultdict(set)
        user_events: dict[str, list[dict]] = defaultdict(list)
        
        for log in logs:
            user = self._extract_user(log)
            ip = self._extract_ip(log)
            
            if user and ip:
                user_ips[user].add(ip)
                user_events[user].append(log)
        
        correlations = []
        for user, ips in user_ips.items():
            if len(ips) < 2:
                continue
            
            events = user_events[user]
            events.sort(key=lambda x: self._parse_timestamp(x) or datetime.min)
            
            timestamps = [self._parse_timestamp(e) for e in events]
            valid_ts = [t for t in timestamps if t]
            
            # Multiple IPs for same user is suspicious
            severity = "high" if len(ips) >= 3 else "medium"
            
            summary = f"User '{user}' authenticated from {len(ips)} different IPs: {', '.join(sorted(ips))}"
            
            correlations.append(CorrelatedEvent(
                correlation_id=self._generate_correlation_id(),
                correlation_type="lateral_movement",
                events=events,
                entity=user,
                start_time=min(valid_ts) if valid_ts else None,
                end_time=max(valid_ts) if valid_ts else None,
                severity=severity,
                mitre_techniques=["T1021"],  # Remote Services
                summary=summary,
            ))
        
        logger.info(f"find_lateral_movement completed", users=len(user_ips), detections=len(correlations))
        return correlations
    
    def correlate_all(self, logs: list[dict]) -> list[CorrelatedEvent]:
        """
        Run all correlation methods and return combined results.
        
        Args:
            logs: List of log entries
            
        Returns:
            Combined list of all correlated events
        """
        all_correlations = []
        
        all_correlations.extend(self.correlate_by_ip(logs))
        all_correlations.extend(self.correlate_by_user(logs))
        all_correlations.extend(self.detect_attack_chain(logs))
        all_correlations.extend(self.find_lateral_movement(logs))
        
        # Sort by severity (critical first) then by event count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_correlations.sort(
            key=lambda x: (severity_order.get(x.severity, 4), -x.event_count)
        )
        
        logger.info(f"correlate_all completed", total_correlations=len(all_correlations))
        return all_correlations
