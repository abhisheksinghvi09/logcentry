"""
LogCentry API - SIEM Routes

API endpoints for SIEM features: alerts, correlation, UEBA, and timelines.
"""

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from logcentry.api.auth import ApiKeyDep
from logcentry.api.database import get_db, Log, SIEMAlert
from logcentry.api.services.logs import LogService
from logcentry.siem import (
    EventCorrelator,
    RuleEngine,
    get_alert_service,
    get_ueba_engine,
    TimelineBuilder,
)
from logcentry.utils import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/siem", tags=["SIEM"])


# ==================== Request/Response Models ====================


class CorrelateRequest(BaseModel):
    """Request for event correlation."""
    log_count: int = 100
    time_window_minutes: int = 5
    correlation_types: list[str] = ["ip", "user", "attack_chain", "lateral_movement"]


class CorrelateResponse(BaseModel):
    """Response from correlation."""
    correlations: list[dict]
    total: int
    timestamp: datetime


class AlertResponse(BaseModel):
    """Single alert response."""
    id: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    summary: str
    entity: str | None
    mitre_techniques: list[str]
    created_at: datetime


class AlertListResponse(BaseModel):
    """List of alerts."""
    alerts: list[dict]
    total: int
    active: int


class AlertActionRequest(BaseModel):
    """Request to change alert status."""
    user: str = "system"
    notes: str = ""


class RulesResponse(BaseModel):
    """List of detection rules."""
    rules: list[dict]
    total: int
    builtin_count: int


class EntityProfileResponse(BaseModel):
    """Entity profile from UEBA."""
    entity_id: str
    entity_type: str
    risk_score: float
    typical_hours: list[int]
    anomaly_count: int
    first_seen: datetime | None
    last_seen: datetime | None


class TimelineResponse(BaseModel):
    """Incident timeline response."""
    entity: str
    entity_type: str
    start_time: datetime
    end_time: datetime
    event_count: int
    events: list[dict]
    summary: str
    severity: str
    attack_chain_stages: list[str]
    mitre_techniques: list[str]


# ==================== Correlation Endpoints ====================


@router.post("/correlate", response_model=CorrelateResponse)
async def correlate_events(
    request: CorrelateRequest,
    auth: ApiKeyDep,
    db: Session = Depends(get_db),
):
    """
    Run event correlation on recent logs.
    
    Correlates events by IP, user, attack chain, and lateral movement patterns.
    """
    service = LogService(db)
    project_id = auth.get("project_id")
    
    # Get logs
    log_records = db.query(Log).filter(
        Log.project_id == project_id
    ).order_by(Log.timestamp.desc()).limit(request.log_count).all()
    
    # Convert to dicts for correlation
    logs = [log.to_dict() for log in log_records]
    
    if not logs:
        return CorrelateResponse(
            correlations=[],
            total=0,
            timestamp=datetime.utcnow(),
        )
    
    # Run correlation
    correlator = EventCorrelator(time_window_minutes=request.time_window_minutes)
    
    all_correlations = []
    
    if "ip" in request.correlation_types:
        all_correlations.extend(correlator.correlate_by_ip(logs))
    if "user" in request.correlation_types:
        all_correlations.extend(correlator.correlate_by_user(logs))
    if "attack_chain" in request.correlation_types:
        all_correlations.extend(correlator.detect_attack_chain(logs))
    if "lateral_movement" in request.correlation_types:
        all_correlations.extend(correlator.find_lateral_movement(logs))
    
    # Convert to response format
    results = [c.to_dict() for c in all_correlations]
    
    logger.info("correlation_completed", project_id=project_id, total=len(results))
    
    return CorrelateResponse(
        correlations=results,
        total=len(results),
        timestamp=datetime.utcnow(),
    )


# ==================== Alert Endpoints ====================


@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    auth: ApiKeyDep,
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
):
    """
    List SIEM alerts for the project.
    
    Filters:
    - status: new, acknowledged, in_progress, resolved, false_positive
    - severity: critical, high, medium, low, info
    """
    project_id = auth.get("project_id")
    
    # Query database
    query = db.query(SIEMAlert).filter(SIEMAlert.project_id == project_id)
    
    if status:
        query = query.filter(SIEMAlert.status == status)
    if severity:
        query = query.filter(SIEMAlert.severity == severity)
    
    query = query.order_by(SIEMAlert.created_at.desc()).limit(limit)
    alerts = query.all()
    
    # Count active
    active_statuses = ["new", "acknowledged", "in_progress"]
    active = sum(1 for a in alerts if a.status in active_statuses)
    
    return AlertListResponse(
        alerts=[a.to_dict() for a in alerts],
        total=len(alerts),
        active=active,
    )


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: AlertActionRequest,
    auth: ApiKeyDep,
    db: Session = Depends(get_db),
):
    """Acknowledge an alert."""
    project_id = auth.get("project_id")
    
    alert = db.query(SIEMAlert).filter(
        SIEMAlert.id == alert_id,
        SIEMAlert.project_id == project_id,
    ).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.utcnow()
    alert.acknowledged_by = request.user
    alert.updated_at = datetime.utcnow()
    
    db.commit()
    
    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    request: AlertActionRequest,
    auth: ApiKeyDep,
    db: Session = Depends(get_db),
):
    """Resolve an alert."""
    project_id = auth.get("project_id")
    
    alert = db.query(SIEMAlert).filter(
        SIEMAlert.id == alert_id,
        SIEMAlert.project_id == project_id,
    ).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = request.user
    alert.resolution_notes = request.notes
    alert.updated_at = datetime.utcnow()
    
    db.commit()
    
    return {"status": "resolved", "alert_id": alert_id}


@router.post("/alerts/from-correlation")
async def create_alerts_from_correlation(
    auth: ApiKeyDep,
    log_count: int = 100,
    db: Session = Depends(get_db),
):
    """
    Run correlation and create alerts from significant correlations.
    
    This is a convenience endpoint that combines correlation + alert creation.
    """
    project_id = auth.get("project_id")
    
    # Get logs
    log_records = db.query(Log).filter(
        Log.project_id == project_id
    ).order_by(Log.timestamp.desc()).limit(log_count).all()
    
    logs = [log.to_dict() for log in log_records]
    
    if not logs:
        return {"alerts_created": 0, "message": "No logs to analyze"}
    
    # Run correlation
    correlator = EventCorrelator()
    correlations = correlator.correlate_all(logs)
    
    # Create alerts for high-severity correlations
    alerts_created = 0
    for corr in correlations:
        if corr.severity in ("high", "critical"):
            alert = SIEMAlert(
                project_id=project_id,
                rule_id=f"correlation_{corr.correlation_type}",
                rule_name=f"Correlated {corr.correlation_type} events",
                severity=corr.severity,
                summary=corr.summary,
                details=json.dumps({"correlation_id": corr.correlation_id}),
                source_log_ids=json.dumps([e.get("id", "") for e in corr.events[:10]]),
                correlation_id=corr.correlation_id,
                mitre_techniques=json.dumps(corr.mitre_techniques),
                entity=corr.entity,
            )
            db.add(alert)
            alerts_created += 1
    
    db.commit()
    
    return {
        "alerts_created": alerts_created,
        "correlations_found": len(correlations),
        "message": f"Created {alerts_created} alerts from {len(correlations)} correlations",
    }


# ==================== Detection Rules Endpoints ====================


@router.get("/rules", response_model=RulesResponse)
async def list_rules(auth: ApiKeyDep):
    """List all detection rules (built-in and custom)."""
    engine = RuleEngine(include_builtin=True)
    rules = engine.list_rules()
    
    return RulesResponse(
        rules=[r.to_dict() for r in rules],
        total=len(rules),
        builtin_count=len([r for r in rules if r.id.startswith("builtin_")]),
    )


@router.post("/rules/evaluate")
async def evaluate_rules(
    auth: ApiKeyDep,
    log_count: int = 100,
    db: Session = Depends(get_db),
):
    """
    Evaluate detection rules against recent logs.
    
    Returns matched rules without creating alerts.
    """
    project_id = auth.get("project_id")
    
    log_records = db.query(Log).filter(
        Log.project_id == project_id
    ).order_by(Log.timestamp.desc()).limit(log_count).all()
    
    logs = [log.to_dict() for log in log_records]
    
    if not logs:
        return {"matches": [], "total_logs": 0}
    
    engine = RuleEngine()
    matches = engine.evaluate(logs)
    
    return {
        "matches": [
            {
                "rule_id": m.rule.id,
                "rule_name": m.rule.name,
                "severity": m.rule.severity.value,
                "match_count": m.count,
                "triggered": m.triggered,
                "mitre_technique": m.rule.mitre_technique,
            }
            for m in matches
        ],
        "total_logs": len(logs),
        "rules_evaluated": len(engine.list_rules(enabled_only=True)),
    }


# ==================== UEBA Endpoints ====================


@router.get("/entities/{entity_id}/profile")
async def get_entity_profile(
    entity_id: str,
    entity_type: str = Query(default="ip", pattern="^(ip|user)$"),
    auth: ApiKeyDep = None,
):
    """
    Get behavioral profile for an entity (user or IP).
    """
    ueba = get_ueba_engine()
    profile = ueba.get_profile(entity_id, entity_type)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Entity profile not found")
    
    return profile.to_dict()


@router.post("/entities/analyze")
async def analyze_entities(
    auth: ApiKeyDep,
    entity_type: str = "ip",
    log_count: int = 100,
    db: Session = Depends(get_db),
):
    """
    Run UEBA analysis on recent logs.
    
    Updates baselines and detects anomalies.
    """
    project_id = auth.get("project_id")
    
    log_records = db.query(Log).filter(
        Log.project_id == project_id
    ).order_by(Log.timestamp.desc()).limit(log_count).all()
    
    logs = [log.to_dict() for log in log_records]
    
    if not logs:
        return {"profiles": [], "anomalies": []}
    
    ueba = get_ueba_engine()
    profiles, anomalies = ueba.process_logs(logs, entity_type, project_id)
    
    return {
        "profiles": [p.to_dict() for p in profiles],
        "anomalies": [a.to_dict() for a in anomalies],
        "total_entities": len(profiles),
        "total_anomalies": len(anomalies),
    }


@router.get("/entities/high-risk")
async def get_high_risk_entities(
    auth: ApiKeyDep,
    threshold: float = 50.0,
):
    """Get entities with risk score above threshold."""
    ueba = get_ueba_engine()
    high_risk = ueba.get_high_risk_entities(threshold)
    
    return {
        "entities": [p.to_dict() for p in high_risk],
        "count": len(high_risk),
        "threshold": threshold,
    }


# ==================== Timeline Endpoints ====================


@router.get("/timeline/{entity_id}")
async def get_entity_timeline(
    entity_id: str,
    entity_type: str = Query(default="ip", pattern="^(ip|user)$"),
    hours: int = Query(default=24, le=168),
    auth: ApiKeyDep = None,
    db: Session = Depends(get_db),
):
    """
    Build incident timeline for an entity.
    
    Shows chronological events for investigation.
    """
    from datetime import timedelta
    
    project_id = auth.get("project_id") if auth else None
    
    # Get logs for entity
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    query = db.query(Log)
    if project_id:
        query = query.filter(Log.project_id == project_id)
    
    # Filter by entity in message or metadata
    log_records = query.filter(
        Log.timestamp >= start_time,
        Log.timestamp <= end_time,
        Log.message.contains(entity_id),
    ).order_by(Log.timestamp.asc()).limit(500).all()
    
    logs = [log.to_dict() for log in log_records]
    
    if not logs:
        return {
            "entity": entity_id,
            "entity_type": entity_type,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "event_count": 0,
            "events": [],
            "summary": "No events found",
            "severity": "low",
            "attack_chain_stages": [],
            "mitre_techniques": [],
        }
    
    # Build timeline
    builder = TimelineBuilder()
    timeline = builder.build_timeline(logs, entity_id, entity_type, start_time, end_time)
    
    return timeline.to_dict()


# ==================== Stats Endpoint ====================


@router.get("/stats")
async def get_siem_stats(
    auth: ApiKeyDep,
    db: Session = Depends(get_db),
):
    """Get SIEM statistics for the project."""
    project_id = auth.get("project_id")
    
    # Alert counts
    alerts = db.query(SIEMAlert).filter(SIEMAlert.project_id == project_id).all()
    
    by_severity = {}
    by_status = {}
    for a in alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
    
    # Rule count
    engine = RuleEngine()
    rules = engine.list_rules()
    
    # High-risk entities
    ueba = get_ueba_engine()
    high_risk = ueba.get_high_risk_entities(50.0)
    
    return {
        "alerts": {
            "total": len(alerts),
            "active": sum(1 for a in alerts if a.status in ("new", "acknowledged", "in_progress")),
            "by_severity": by_severity,
            "by_status": by_status,
        },
        "rules": {
            "total": len(rules),
            "builtin": len([r for r in rules if r.id.startswith("builtin_")]),
            "custom": len([r for r in rules if not r.id.startswith("builtin_")]),
        },
        "ueba": {
            "high_risk_entities": len(high_risk),
        },
    }
