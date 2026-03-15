"""
LogCentry API - FastAPI Server

REST API server for receiving logs from client SDKs and serving the dashboard.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from logcentry.api.auth import ApiKeyDep, create_demo_key
from logcentry.api.database import get_db
from logcentry.api.models import (
    AnalysisResponse,
    AnalyzeRequest,
    BatchLogResponse,
    HealthResponse,
    LogBatchRequest,
    LogRequest,
    LogResponse,
)
from logcentry.api.services.logs import LogService
from logcentry.config import get_cached_settings
from logcentry.core.models import LogBatch
from logcentry.utils import get_logger

logger = get_logger(__name__)

# Server start time for uptime tracking
_start_time = time.time()

# WebSocket connections for live updates
_websocket_clients: list[WebSocket] = []


@lru_cache(maxsize=1)
def _get_cached_retriever():
    """Get a cached RAG retriever instance to avoid reloading models per request."""
    from logcentry.rag import create_rag_pipeline

    return create_rag_pipeline(initialize_knowledge=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Server lifespan handler."""
    logger.info("api_server_starting")
    
    # Initialize database and dev data
    from logcentry.api.database import get_engine, init_database, init_dev_data
    engine = get_engine()
    init_database(engine)
    
    # Create dev user and project
    import os
    if os.getenv("DEV_MODE", "true").lower() in ("true", "1", "yes"):
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=engine)
        db = Session()
        try:
            init_dev_data(db)
        except Exception as e:
            logger.warning("dev_data_init_failed", error=str(e))
        finally:
            db.close()
    
    yield
    logger.info("api_server_stopping")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="LogCentry API",
        description="AI-Powered Security Log Monitoring Service",
        version="2.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )
    
    # CORS for dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register auth and project routes
    from logcentry.api.routes.auth import router as auth_router
    from logcentry.api.routes.projects import router as projects_router
    from logcentry.api.routes.siem import router as siem_router
    app.include_router(auth_router)
    app.include_router(projects_router)
    app.include_router(siem_router)
    
    # Register routes
    register_routes(app)
    
    return app


def register_routes(app: FastAPI) -> None:
    """Register API routes."""
    
    # ==================== Health & Info ====================
    
    @app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
    async def health_check(db: Session = Depends(get_db)):
        """Check server health and status."""
        service = LogService(db)
        return HealthResponse(
            status="healthy",
            version="2.0.0",
            uptime_seconds=time.time() - _start_time,
            log_count=service.get_count(),
        )
    
    @app.get("/api/v1/demo-key", tags=["System"])
    async def get_demo_key():
        """Generate a demo API key for testing."""
        key = create_demo_key()
        return {
            "api_key": key,
            "message": "Use this key in X-API-Key header or Authorization: Bearer <key>",
        }
    
    # ==================== Log Ingestion ====================
    
    @app.post("/api/v1/logs", response_model=LogResponse, tags=["Logs"])
    async def submit_log(log: LogRequest, auth: ApiKeyDep, db: Session = Depends(get_db)):
        """
        Submit a single log entry.
        
        Requires API key in X-API-Key header.
        """
        service = LogService(db)
        project_id = auth.get("project_id")
        project_slug = auth.get("project", "unknown")
        
        if not project_id:
             # Should be handled by auth, but safe check
             project_id = "unknown"

        log_id = service.store_log(
            project_id=project_id,
            level=log.level,
            message=log.message,
            source=log.source,
            timestamp=log.timestamp,
            metadata=log.metadata,
        )
        
        # Broadcast to WebSocket clients
        await broadcast_log({
            "id": log_id,
            "project": project_slug,
            "level": log.level,
            "message": log.message[:200],
            "timestamp": (log.timestamp or datetime.now()).isoformat(),
        })
        
        return LogResponse(
            id=log_id,
            status="received",
            timestamp=datetime.now(),
        )
    
    @app.post("/api/v1/logs/batch", response_model=BatchLogResponse, tags=["Logs"])
    async def submit_logs_batch(batch: LogBatchRequest, auth: ApiKeyDep, db: Session = Depends(get_db)):
        """
        Submit multiple log entries at once.
        
        Efficient for high-volume logging.
        """
        service = LogService(db)
        project_id = auth.get("project_id")
        
        if not project_id:
            project_id = "unknown"
        
        logs_data = [
            {
                "level": log.level,
                "message": log.message,
                "source": log.source,
                "timestamp": log.timestamp,
                "metadata": log.metadata,
            }
            for log in batch.logs
        ]
        
        log_ids = service.store_batch(project_id=project_id, logs=logs_data)
        
        return BatchLogResponse(
            received=len(log_ids),
            log_ids=log_ids,
            status="received",
        )
    
    @app.get("/api/v1/logs", tags=["Logs"])
    async def get_logs(
        auth: ApiKeyDep,
        limit: int = 100,
        level: str | None = None,
        after_id: str | None = None,
        db: Session = Depends(get_db),
    ):
        """
        Retrieve recent logs for your project.
        Use `after_id` for incremental polling — returns only logs received after the given log ID.
        """
        service = LogService(db)
        project_id = auth.get("project_id")
        
        logs = service.get_logs(
            project_id=project_id,
            level=level,
            limit=limit,
            after_id=after_id,
        )
        
        return {"logs": logs, "count": len(logs)}

    @app.delete("/api/v1/logs", tags=["Logs"])
    async def clear_logs(auth: ApiKeyDep, db: Session = Depends(get_db)):
        """
        Clear all logs for the authenticated project.
        """
        service = LogService(db)
        project_id = auth.get("project_id")

        deleted = service.clear_logs(project_id=project_id)
        return {
            "status": "cleared",
            "deleted": deleted,
            "project_id": project_id,
        }
    
    # ==================== Analysis ====================
    
    @app.post("/api/v1/analyze", response_model=AnalysisResponse, tags=["Analysis"])
    async def analyze_logs(request: AnalyzeRequest, auth: ApiKeyDep, db: Session = Depends(get_db)):
        """
        Run AI-powered threat analysis on recent logs.
        """
        try:
            from logcentry.core import ThreatAnalyzer
            
            service = LogService(db)
            project_id = auth.get("project_id")
            
            # Get logs (explicit IDs if provided, else recent logs)
            if request.log_ids:
                entries = service.get_log_entries_by_ids(
                    log_ids=request.log_ids,
                    project_id=project_id,
                    limit=request.count,
                )
            else:
                entries = service.get_log_entries(
                    project_id=project_id,
                    limit=request.count,
                )
            
            if not entries:
                return AnalysisResponse(
                    analysis_id="none",
                    severity=0,
                    severity_label="N/A",
                    threat_assessment="No logs to analyze",
                    countermeasures=[],
                    mitre_techniques=[],
                    cves=[],
                    patch_suggestions=[],
                    vulnerability_categories=[],
                    analyzed_count=0,
                    timestamp=datetime.now(),
                )

            # Fast-path for clearly benign logs to avoid unnecessary LLM latency.
            suspicious_terms = (
                "error", "fail", "denied", "unauthorized", "attack", "inject", "sql",
                "xss", "traversal", "exploit", "malware", "brute", "critical",
                "security", "privilege", "escalation", "cve", "rce",
            )
            has_suspicious_text = any(
                any(term in (entry.message or "").lower() for term in suspicious_terms)
                for entry in entries
            )

            if not has_suspicious_text:
                return AnalysisResponse(
                    analysis_id="benign_fast_path",
                    severity=1,
                    severity_label="low",
                    threat_assessment="No high-risk indicators detected in selected logs. Activity appears normal.",
                    countermeasures=[
                        "Continue routine monitoring",
                        "Keep alerting thresholds and logging enabled",
                    ],
                    mitre_techniques=[],
                    cves=[],
                    patch_suggestions=[],
                    vulnerability_categories=[],
                    analyzed_count=len(entries),
                    timestamp=datetime.now(),
                )
            
            # Run analysis
            batch = LogBatch(entries=entries)
            analyzer = ThreatAnalyzer()
            settings = get_cached_settings()
            
            rag_context = None
            if request.use_rag:
                try:
                    retriever = _get_cached_retriever()
                    try:
                        rag_context = await asyncio.wait_for(
                            asyncio.to_thread(retriever.retrieve_for_logs, batch),
                            timeout=settings.rag_retrieval_timeout_seconds,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "rag_retrieval_timeout",
                            timeout_seconds=settings.rag_retrieval_timeout_seconds,
                            entry_count=len(entries),
                        )
                        rag_context = None
                except Exception as e:
                    logger.warning("rag_retrieval_failed", error=str(e))

            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(analyzer.analyze, batch, rag_context),
                    timeout=settings.analysis_request_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.error(
                    "analysis_timeout",
                    timeout_seconds=settings.analysis_request_timeout_seconds,
                    entry_count=len(entries),
                )
                return AnalysisResponse(
                    analysis_id="timeout",
                    severity=0,
                    severity_label="Timeout",
                    threat_assessment=(
                        f"Analysis timed out after {settings.analysis_request_timeout_seconds}s. "
                        "Try again with fewer logs or verify LLM provider connectivity."
                    ),
                    countermeasures=[
                        "Reduce analysis scope (selected logs only)",
                        "Verify API key and outbound network access",
                        "Retry analysis after provider recovers",
                    ],
                    mitre_techniques=[],
                    cves=[],
                    patch_suggestions=[],
                    vulnerability_categories=[],
                    analyzed_count=len(entries),
                    timestamp=datetime.now(),
                )
            
            return AnalysisResponse(
                analysis_id=result.id,
                severity=result.analysis.severity_score,
                severity_label=result.analysis.severity_level.value,
                threat_assessment=result.analysis.threat_assessment,
                countermeasures=result.analysis.countermeasures,
                mitre_techniques=result.analysis.mitre_attack_ttps,
                cves=result.analysis.cves,
                patch_suggestions=[
                    {
                        "category": p.category.value,
                        "title": p.title,
                        "description": p.description,
                        "priority": p.priority,
                        "commands": p.commands,
                        "related_cves": p.related_cves,
                    }
                    for p in result.analysis.patch_suggestions
                ],
                vulnerability_categories=[c.value for c in result.analysis.vulnerability_categories],
                analyzed_count=len(entries),
                timestamp=result.timestamp,
            )
        except Exception as e:
            logger.error("analysis_failed", error=str(e))
            return AnalysisResponse(
                analysis_id="error",
                severity=0,
                severity_label="Error",
                threat_assessment=f"Analysis failed: {str(e)[:200]}. Please check your API keys and try again.",
                countermeasures=[],
                mitre_techniques=[],
                cves=[],
                patch_suggestions=[],
                vulnerability_categories=[],
                analyzed_count=0,
                timestamp=datetime.now(),
            )
    
    # ==================== WebSocket for Live Updates ====================
    
    @app.websocket("/ws/logs")
    async def websocket_logs(websocket: WebSocket):
        """WebSocket endpoint for real-time log streaming."""
        await websocket.accept()
        _websocket_clients.append(websocket)
        
        try:
            while True:
                # Keep connection alive
                await websocket.receive_text()
        except WebSocketDisconnect:
            _websocket_clients.remove(websocket)
    
    # ==================== Dashboard ====================
    
    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard():
        """Serve the live dashboard."""
        return get_dashboard_html()
    
    @app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard_alt():
        """Serve the live dashboard (alternative path)."""
        return get_dashboard_html()


async def broadcast_log(log_data: dict) -> None:
    """Broadcast a log to all WebSocket clients."""
    import json
    
    message = json.dumps(log_data)
    disconnected = []
    
    for client in _websocket_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)
    
    for client in disconnected:
        _websocket_clients.remove(client)


def get_dashboard_html() -> str:
    """Generate the dashboard HTML."""
    template_path = Path(__file__).parent.parent / "dashboard" / "templates" / "index.html"
    if not template_path.exists():
        return "<h1>Dashboard template not found</h1>"
    return template_path.read_text(encoding="utf-8")


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """
    Run the API server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
    """
    import uvicorn
    
    logger.info("starting_server", host=host, port=port)
    print(f"\n🛡️  LogCentry API Server")
    print(f"   Dashboard: http://localhost:{port}/dashboard")
    print(f"   API Docs:  http://localhost:{port}/api/docs")
    print(f"   Health:    http://localhost:{port}/api/v1/health\n")
    
    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        log_level="info",
    )
