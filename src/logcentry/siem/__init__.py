"""
LogCentry SIEM - Module Initialization

Enhanced Security Information and Event Management capabilities.
"""

from logcentry.siem.correlation import EventCorrelator, CorrelatedEvent
from logcentry.siem.rules import Rule, RuleEngine, RuleSeverity, RuleMatch, BUILTIN_RULES
from logcentry.siem.alerts import Alert, AlertService, AlertStatus, AlertSeverity, get_alert_service
from logcentry.siem.ueba import UEBAEngine, EntityProfile, Anomaly, get_ueba_engine
from logcentry.siem.timeline import TimelineBuilder, IncidentTimeline, TimelineEvent

__all__ = [
    # Correlation
    "EventCorrelator",
    "CorrelatedEvent",
    # Rules
    "Rule",
    "RuleEngine",
    "RuleSeverity",
    "RuleMatch",
    "BUILTIN_RULES",
    # Alerts
    "Alert",
    "AlertService",
    "AlertStatus",
    "AlertSeverity",
    "get_alert_service",
    # UEBA
    "UEBAEngine",
    "EntityProfile",
    "Anomaly",
    "get_ueba_engine",
    # Timeline
    "TimelineBuilder",
    "IncidentTimeline",
    "TimelineEvent",
]

