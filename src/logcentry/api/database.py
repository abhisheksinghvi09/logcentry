"""
LogCentry API - Database Models

SQLAlchemy models for users, projects, API keys, and logs.
Supports both PostgreSQL (production) and SQLite (development).
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.pool import StaticPool

# Base class for all models
Base = declarative_base()


# ==================== Models ====================


class User(Base):
    """
    User account model.
    
    Each user can have multiple projects and API keys.
    """
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    # Authentication
    password_hash = Column(String(255), nullable=True)  # Legacy/Standard auth
    password_verifier = Column(String(512), nullable=True)  # ZK Auth verifier (Argon2id)
    password_salt = Column(String(255), nullable=True)      # ZK Auth salt
    
    name = Column(String(100), nullable=True)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    
    # MFA (optional)
    mfa_secret = Column(String(32), nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Post-Auth Flags
    is_first_login = Column(Boolean, default=True, nullable=False)
    role = Column(String(50), default="user", nullable=False)
    
    # Relationships
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert to dictionary for API responses."""
        data = {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "is_active": self.is_active,
            "email_verified": self.email_verified,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_first_login": self.is_first_login,
            "role": self.role,
        }
        if include_sensitive:
            data["is_admin"] = self.is_admin
        return data


class Project(Base):
    """
    Project model - container for logs and API keys.
    
    Each user can have multiple projects for different applications.
    """
    __tablename__ = "projects"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(100), nullable=False)
    slug = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Settings (JSON-like)
    settings = Column(Text, nullable=True)  # Store as JSON string
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    api_keys = relationship("ApiKey", back_populates="project", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="project", cascade="all, delete-orphan")
    
    # Unique constraint: user can't have duplicate project names
    __table_args__ = (
        Index("idx_project_user_slug", "user_id", "slug", unique=True),
    )
    
    def __repr__(self):
        return f"<Project {self.name}>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "log_count": len(self.logs) if self.logs else 0,
            "api_key_count": len(self.api_keys) if self.api_keys else 0,
        }


class ApiKey(Base):
    """
    API Key model - for SDK authentication.
    
    Keys are scoped to a specific project.
    Only the hash is stored; the full key is shown once at creation.
    """
    __tablename__ = "api_keys"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(100), nullable=False)  # e.g., "Production Key"
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(12), nullable=False)  # e.g., "lc_abc123..."
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # Optional expiry
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    project = relationship("Project", back_populates="api_keys")
    
    def __repr__(self):
        return f"<ApiKey {self.key_prefix}...>"
    
    def to_dict(self, include_key: bool = False) -> dict:
        """Convert to dictionary for API responses."""
        data = {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "project_id": self.project_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
        return data
    
    def is_expired(self) -> bool:
        """Check if key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class Log(Base):
    """
    Log entry model.
    
    Stores logs received from SDK clients.
    Isolated by project for multi-tenancy.
    """
    __tablename__ = "logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    
    level = Column(String(20), nullable=False, index=True)
    message = Column(Text, nullable=False)
    source = Column(String(100), nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime, nullable=False, index=True)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Metadata (stored as JSON string)
    log_metadata = Column(Text, nullable=True)
    
    # Analysis status
    analyzed = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="logs")
    
    # Indexes for common queries
    __table_args__ = (
        Index("idx_logs_project_timestamp", "project_id", "timestamp"),
        Index("idx_logs_project_level", "project_id", "level"),
    )
    
    def __repr__(self):
        return f"<Log {self.level}: {self.message[:50]}>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "metadata": self.log_metadata,
            "analyzed": self.analyzed,
        }


# ==================== Audit Logs ====================


class AuditLog(Base):
    """
    Audit log for security events.
    
    Tracks logins, signups, and other security-critical actions.
    """
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    event = Column(String(50), nullable=False, index=True) # login_success, login_failed, signup
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    user = relationship("User")
    
    def __repr__(self):
        return f"<AuditLog {self.event} - {self.user_id}>"


# ==================== SIEM Models ====================


class SIEMAlert(Base):
    """
    SIEM alert model for tracking security alerts.
    
    Stores alerts generated by detection rules or correlation engine.
    """
    __tablename__ = "siem_alerts"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    
    rule_id = Column(String(100), nullable=False, index=True)
    rule_name = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    status = Column(String(20), default="new", nullable=False, index=True)  # new, acknowledged, in_progress, resolved, false_positive
    
    summary = Column(Text, nullable=False)
    details = Column(Text, nullable=True)  # JSON string
    
    source_log_ids = Column(Text, nullable=True)  # JSON array of log IDs
    correlation_id = Column(String(100), nullable=True)
    mitre_techniques = Column(Text, nullable=True)  # JSON array
    entity = Column(String(255), nullable=True)  # IP or username involved
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(255), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    __table_args__ = (
        Index("idx_alerts_project_status", "project_id", "status"),
        Index("idx_alerts_severity_status", "severity", "status"),
    )
    
    def __repr__(self):
        return f"<SIEMAlert {self.rule_name} - {self.severity}>"
    
    def to_dict(self) -> dict:
        import json
        return {
            "id": self.id,
            "project_id": self.project_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "details": json.loads(self.details) if self.details else {},
            "source_log_ids": json.loads(self.source_log_ids) if self.source_log_ids else [],
            "correlation_id": self.correlation_id,
            "mitre_techniques": json.loads(self.mitre_techniques) if self.mitre_techniques else [],
            "entity": self.entity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "resolution_notes": self.resolution_notes,
        }


class EntityBaseline(Base):
    """
    Entity behavior baseline for UEBA.
    
    Stores behavioral profiles for users and IPs.
    """
    __tablename__ = "entity_baselines"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    
    entity_id = Column(String(255), nullable=False)  # username or IP
    entity_type = Column(String(20), nullable=False)  # 'user' or 'ip'
    
    # Baseline data (JSON strings)
    typical_hours = Column(Text, nullable=True)  # JSON array of hours
    typical_days = Column(Text, nullable=True)  # JSON array of days
    typical_sources = Column(Text, nullable=True)  # JSON array
    baseline_stats = Column(Text, nullable=True)  # JSON with avg/max stats
    
    # Risk
    risk_score = Column(Integer, default=0, nullable=False)
    anomaly_count = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    total_events = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_baseline_entity", "entity_id", "entity_type"),
        Index("idx_baseline_project_entity", "project_id", "entity_id"),
    )
    
    def __repr__(self):
        return f"<EntityBaseline {self.entity_type}:{self.entity_id}>"


class DetectionRule(Base):
    """
    Custom detection rules for SIEM.
    
    Stores user-defined detection rules in addition to built-in rules.
    """
    __tablename__ = "detection_rules"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    
    # Rule conditions (JSON strings)
    match_patterns = Column(Text, nullable=True)  # JSON array of regex patterns
    match_level = Column(String(20), nullable=True)  # Log level to match
    match_fields = Column(Text, nullable=True)  # JSON object of field conditions
    
    # Thresholds
    threshold_count = Column(Integer, default=1, nullable=False)
    threshold_window_seconds = Column(Integer, default=60, nullable=False)
    
    mitre_technique = Column(String(20), nullable=True)
    tags = Column(Text, nullable=True)  # JSON array
    
    is_enabled = Column(Boolean, default=True, nullable=False)
    is_builtin = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<DetectionRule {self.name}>"


# ==================== Database Setup ====================


def get_database_url() -> str:
    """
    Get database URL from environment or use default.
    
    Supports:
    - PostgreSQL: DATABASE_URL=postgresql://user:pass@host:port/db
    - SQLite: DATABASE_URL=sqlite:///path/to/db.sqlite
    """
    default_url = "sqlite:///data/logcentry.db"
    return os.getenv("DATABASE_URL", default_url)


def create_db_engine(database_url: str | None = None):
    """
    Create SQLAlchemy engine.
    
    Args:
        database_url: Override database URL
        
    Returns:
        SQLAlchemy engine
    """
    url = database_url or get_database_url()
    
    # SQLite needs special handling for threading
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        
        # Enable foreign keys for SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    else:
        # PostgreSQL with connection pooling
        engine = create_engine(
            url,
            pool_pre_ping=True,          # Test connections before use
            pool_size=10,                 # Number of persistent connections
            max_overflow=20,              # Additional connections when pool exhausted
            pool_timeout=30,              # Seconds to wait for connection
            pool_recycle=1800,            # Recycle connections after 30 min
            echo=False,                   # Disable SQL logging in production
        )
    
    return engine


def init_database(engine=None) -> None:
    """
    Initialize database schema.
    
    Creates all tables if they don't exist.
    """
    if engine is None:
        engine = create_db_engine()
    
    Base.metadata.create_all(engine)


def get_session_factory(engine=None):
    """
    Get a session factory for database operations.
    
    Returns:
        sessionmaker bound to engine
    """
    if engine is None:
        engine = create_db_engine()
    
    return sessionmaker(bind=engine, autoflush=True, autocommit=False)


# ==================== Default Session ====================


_engine = None
_SessionLocal = None


def get_engine():
    """Get or create the default engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_db():
    """
    Database session dependency for FastAPI.
    
    Usage in routes:
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = get_session_factory(get_engine())
    
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_dev_data(db) -> None:
    """
    Initialize development data.
    
    Creates demo user and project for testing.
    """
    import hashlib
    import bcrypt
    
    # Check if demo user exists
    demo_user = db.query(User).filter(User.email == "demo@logcentry.dev").first()
    
    if demo_user is None:
        # Create demo user
        password_hash = bcrypt.hashpw("demo123".encode(), bcrypt.gensalt()).decode()
        
        demo_user = User(
            id="demo-user-id",
            email="demo@logcentry.dev",
            password_hash=password_hash,
            name="Demo User",
            is_active=True,
            email_verified=True,  # Skip verification for dev
        )
        db.add(demo_user)
        db.flush()
        
        # Create demo project
        demo_project = Project(
            id="demo-project-id",
            user_id=demo_user.id,
            name="Demo Project",
            slug="demo",
            description="Default project for testing",
        )
        db.add(demo_project)
        db.flush()
        
        # Create demo API key (lc_dev_bypass_key)
        dev_key = "lc_dev_bypass_key"
        key_hash = hashlib.sha256(dev_key.encode()).hexdigest()
        
        demo_key = ApiKey(
            id="demo-key-id",
            user_id=demo_user.id,
            project_id=demo_project.id,
            name="Development Key",
            key_hash=key_hash,
            key_prefix="lc_dev_byp...",
            is_active=True,
        )
        db.add(demo_key)
        
        db.commit()
        print("✅ Created demo user: demo@logcentry.dev / demo123")
        print("✅ Created demo API key: lc_dev_bypass_key")
