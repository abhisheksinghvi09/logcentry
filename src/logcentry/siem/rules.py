"""
LogCentry SIEM - Detection Rules Engine

Configurable detection rules for identifying security threats.
Built-in rules for common attacks plus custom rule support.
"""

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from logcentry.utils import get_logger

logger = get_logger(__name__)


class RuleSeverity(str, Enum):
    """Rule severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Rule:
    """
    A detection rule for identifying security threats.
    
    Attributes:
        id: Unique rule identifier
        name: Human-readable rule name
        description: Detailed description
        condition: Rule condition expression or function
        severity: Severity level when rule triggers
        mitre_technique: Optional MITRE ATT&CK technique ID
        tags: Optional tags for categorization
        enabled: Whether rule is active
    """
    id: str
    name: str
    description: str
    severity: RuleSeverity = RuleSeverity.MEDIUM
    mitre_technique: str | None = None
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    
    # Condition parameters
    threshold: int = 1  # Number of matching events to trigger
    time_window_seconds: int = 60  # Time window for threshold
    match_patterns: list[str] = field(default_factory=list)  # Regex patterns to match
    match_level: str | None = None  # Log level to match (e.g., "security", "error")
    match_fields: dict[str, str] = field(default_factory=dict)  # Field conditions
    
    def matches(self, log: dict) -> bool:
        """Check if a single log entry matches this rule's patterns."""
        # Check log level if specified
        if self.match_level:
            log_level = log.get("level", "").lower()
            if log_level != self.match_level.lower():
                return False
        
        # Check message patterns
        message = log.get("message", "")
        if self.match_patterns:
            matched = False
            for pattern in self.match_patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    matched = True
                    break
            if not matched:
                return False
        
        # Check field conditions
        metadata = log.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        for field_name, expected in self.match_fields.items():
            actual = metadata.get(field_name) or log.get(field_name)
            if actual is None:
                return False
            if str(actual).lower() != str(expected).lower():
                return False
        
        return True
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_technique": self.mitre_technique,
            "tags": self.tags,
            "enabled": self.enabled,
            "threshold": self.threshold,
            "time_window_seconds": self.time_window_seconds,
            "match_patterns": self.match_patterns,
            "match_level": self.match_level,
            "match_fields": self.match_fields,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Create a Rule from a dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data["name"],
            description=data.get("description", ""),
            severity=RuleSeverity(data.get("severity", "medium")),
            mitre_technique=data.get("mitre_technique"),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
            threshold=data.get("threshold", 1),
            time_window_seconds=data.get("time_window_seconds", 60),
            match_patterns=data.get("match_patterns", []),
            match_level=data.get("match_level"),
            match_fields=data.get("match_fields", {}),
        )


@dataclass
class RuleMatch:
    """Result of a rule matching logs."""
    rule: Rule
    matching_logs: list[dict]
    first_match_time: datetime | None
    last_match_time: datetime | None
    
    @property
    def count(self) -> int:
        return len(self.matching_logs)
    
    @property
    def triggered(self) -> bool:
        """Check if threshold is met."""
        return self.count >= self.rule.threshold


# ==================== Built-in Rules ====================

BUILTIN_RULES = [
    Rule(
        id="builtin_brute_force",
        name="Brute Force Attack",
        description="Multiple failed login attempts from same source",
        severity=RuleSeverity.HIGH,
        mitre_technique="T1110",
        tags=["auth", "credential_access"],
        threshold=5,
        time_window_seconds=60,
        match_patterns=[
            r"failed.*login",
            r"invalid.*password",
            r"authentication.*fail",
            r"failed password for",
            r"login.*fail",
        ],
    ),
    Rule(
        id="builtin_sqli",
        name="SQL Injection Attempt",
        description="SQL injection patterns detected in request",
        severity=RuleSeverity.HIGH,
        mitre_technique="T1190",
        tags=["injection", "web"],
        threshold=1,
        match_patterns=[
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"union.*select",
            r"select.*from.*information_schema",
            r"or\s+1\s*=\s*1",
            r"or\s*'[^']*'\s*=\s*'[^']*'",
            r";\s*(drop|delete|update|insert)",
            r"exec(\s|\+)+(s|x)p\w+",
        ],
    ),
    Rule(
        id="builtin_path_traversal",
        name="Path Traversal Attempt",
        description="Directory traversal attack patterns detected",
        severity=RuleSeverity.HIGH,
        mitre_technique="T1083",
        tags=["file_access", "web"],
        threshold=1,
        match_patterns=[
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"c:\\windows",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"..%2f",
            r"%252e%252e%252f",
        ],
    ),
    Rule(
        id="builtin_xss",
        name="Cross-Site Scripting (XSS)",
        description="XSS attack patterns detected",
        severity=RuleSeverity.MEDIUM,
        mitre_technique="T1059.007",
        tags=["xss", "web", "injection"],
        threshold=1,
        match_patterns=[
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on(error|load|click|mouseover)\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
            r"expression\s*\(",
        ],
    ),
    Rule(
        id="builtin_rce",
        name="Remote Code Execution Attempt",
        description="Command injection or RCE patterns detected",
        severity=RuleSeverity.CRITICAL,
        mitre_technique="T1059",
        tags=["rce", "command_injection"],
        threshold=1,
        match_patterns=[
            r";\s*cat\s",
            r"\|\s*nc\s",
            r";\s*(ls|pwd|id|whoami|uname)",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r";\s*wget\s",
            r";\s*curl\s",
            r"\|\s*bash",
            r"\|\s*sh\s",
            r"reverse.*shell",
        ],
    ),
    Rule(
        id="builtin_privilege_escalation",
        name="Privilege Escalation Attempt",
        description="Potential privilege escalation activity",
        severity=RuleSeverity.CRITICAL,
        mitre_technique="T1548",
        tags=["privilege_escalation"],
        threshold=1,
        match_patterns=[
            r"sudo.*failed",
            r"permission denied.*root",
            r"setuid",
            r"elevation.*fail",
            r"admin.*access.*denied",
        ],
    ),
    Rule(
        id="builtin_reconnaissance",
        name="Reconnaissance Activity",
        description="Scanning or enumeration activity detected",
        severity=RuleSeverity.MEDIUM,
        mitre_technique="T1046",
        tags=["reconnaissance", "discovery"],
        threshold=10,
        time_window_seconds=30,
        match_patterns=[
            r"scan",
            r"probe",
            r"enum",
            r"nmap",
            r"nikto",
            r"gobuster",
            r"dirb",
            r"wfuzz",
        ],
    ),
    Rule(
        id="builtin_security_event",
        name="Security Level Event",
        description="Event explicitly marked as security-related",
        severity=RuleSeverity.MEDIUM,
        tags=["security"],
        threshold=1,
        match_level="security",
    ),
]


class RuleEngine:
    """
    Detection rule engine for evaluating logs against security rules.
    
    Supports:
    - Built-in rules for common attacks
    - Custom rules from configuration
    - Threshold-based triggering with time windows
    - MITRE ATT&CK technique mapping
    """
    
    def __init__(self, include_builtin: bool = True):
        """
        Initialize the rule engine.
        
        Args:
            include_builtin: Whether to include built-in detection rules
        """
        self.rules: dict[str, Rule] = {}
        
        if include_builtin:
            for rule in BUILTIN_RULES:
                self.rules[rule.id] = rule
    
    def add_rule(self, rule: Rule) -> None:
        """Add a detection rule."""
        self.rules[rule.id] = rule
        logger.info(f"rule_added", rule_id=rule.id, name=rule.name)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        return self.rules.get(rule_id)
    
    def list_rules(self, enabled_only: bool = False) -> list[Rule]:
        """List all rules."""
        rules = list(self.rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules
    
    def load_rules_from_file(self, path: str) -> int:
        """
        Load rules from a JSON file.
        
        Args:
            path: Path to JSON file containing rules array
            
        Returns:
            Number of rules loaded
        """
        with open(path, "r") as f:
            rules_data = json.load(f)
        
        count = 0
        for rule_data in rules_data:
            rule = Rule.from_dict(rule_data)
            self.add_rule(rule)
            count += 1
        
        logger.info(f"rules_loaded", path=path, count=count)
        return count
    
    def _parse_timestamp(self, log: dict) -> datetime | None:
        """Parse timestamp from log entry."""
        ts = log.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                pass
        return None
    
    def evaluate(
        self,
        logs: list[dict],
        rules: list[Rule] | None = None,
    ) -> list[RuleMatch]:
        """
        Evaluate logs against rules and return matches.
        
        Args:
            logs: List of log entries
            rules: Optional specific rules to evaluate (defaults to all enabled)
            
        Returns:
            List of RuleMatch objects for triggered rules
        """
        if rules is None:
            rules = [r for r in self.rules.values() if r.enabled]
        
        matches: list[RuleMatch] = []
        
        for rule in rules:
            matching_logs = []
            timestamps = []
            
            for log in logs:
                if rule.matches(log):
                    matching_logs.append(log)
                    ts = self._parse_timestamp(log)
                    if ts:
                        timestamps.append(ts)
            
            if not matching_logs:
                continue
            
            # For threshold-based rules, check time window
            if rule.threshold > 1 and timestamps:
                timestamps.sort()
                window = timedelta(seconds=rule.time_window_seconds)
                
                # Sliding window check
                in_window_count = 0
                for i, ts in enumerate(timestamps):
                    count_in_window = sum(
                        1 for t in timestamps[i:]
                        if t - ts <= window
                    )
                    in_window_count = max(in_window_count, count_in_window)
                
                if in_window_count < rule.threshold:
                    continue
            
            match = RuleMatch(
                rule=rule,
                matching_logs=matching_logs,
                first_match_time=min(timestamps) if timestamps else None,
                last_match_time=max(timestamps) if timestamps else None,
            )
            
            if match.triggered:
                matches.append(match)
        
        logger.info(
            f"evaluate completed",
            total_logs=len(logs),
            rules_checked=len(rules),
            matches=len(matches),
        )
        return matches
    
    def evaluate_single(self, log: dict) -> list[Rule]:
        """
        Quick evaluation of a single log entry.
        
        Returns matching rules without threshold checking.
        Useful for real-time alerting on high-severity patterns.
        
        Args:
            log: Single log entry
            
        Returns:
            List of matching rules
        """
        matching_rules = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            if rule.threshold > 1:
                continue  # Skip threshold rules for single evaluation
            if rule.matches(log):
                matching_rules.append(rule)
        
        return matching_rules
