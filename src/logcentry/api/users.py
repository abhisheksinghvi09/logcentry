"""
LogCentry API - User Service

User management: registration, authentication, password hashing, JWT tokens.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from logcentry.api.database import ApiKey, Project, User
from logcentry.utils import get_logger

logger = get_logger(__name__)


# ==================== Configuration ====================


# JWT Settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours for dev convenience
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password Settings
BCRYPT_ROUNDS = 12

# Dev Mode
DEV_MODE = os.getenv("DEV_MODE", "true").lower() in ("true", "1", "yes")


# ==================== Password Hashing ====================


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password
        hashed: Hashed password from database
        
    Returns:
        True if password matches
    """
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ==================== JWT Tokens ====================


def create_access_token(
    user_id: str,
    email: str,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.
    
    Args:
        user_id: User's ID
        email: User's email
        expires_delta: Optional custom expiry
        
    Returns:
        JWT token string
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        user_id: User's ID
        
    Returns:
        JWT refresh token string
    """
    expire = datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Token payload or None if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning("jwt_verification_failed", error=str(e))
        return None


# ==================== API Key Management ====================


def generate_api_key() -> Tuple[str, str]:
    """
    Generate a new API key.
    
    Returns:
        Tuple of (full_key, key_hash)
    """
    # Format: lc_<random_32_chars>
    random_part = secrets.token_urlsafe(32)
    full_key = f"lc_{random_part}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    
    return full_key, key_hash


def hash_api_key(key: str) -> str:
    """
    Hash an API key for storage.
    
    Args:
        key: Full API key
        
    Returns:
        SHA-256 hash
    """
    return hashlib.sha256(key.encode()).hexdigest()


def get_key_prefix(key: str, length: int = 12) -> str:
    """
    Get the display prefix of an API key.
    
    Args:
        key: Full API key
        length: Prefix length
        
    Returns:
        Key prefix with ellipsis
    """
    if len(key) <= length:
        return key
    return key[:length] + "..."


# ==================== User Service ====================


class UserService:
    """
    User management service.
    
    Handles registration, authentication, and user operations.
    """
    
    def __init__(self, db: Session):
        """
        Initialize with database session.
        
        Args:
            db: SQLAlchemy session
        """
        self.db = db
    
    def create_user(
        self,
        email: str,
        password: str,
        name: str | None = None,
    ) -> Tuple[User, str | None]:
        """
        Create a new user.
        
        Args:
            email: User's email
            password: Plain text password
            name: Optional display name
            
        Returns:
            Tuple of (User, error_message)
        """
        # Check if email exists
        existing = self.db.query(User).filter(User.email == email.lower()).first()
        if existing:
            return None, "Email already registered"
        
        # Validate password
        if len(password) < 8:
            return None, "Password must be at least 8 characters"
        
        # Create user
        user = User(
            email=email.lower().strip(),
            password_hash=hash_password(password),
            name=name,
            is_active=True,
            email_verified=DEV_MODE,  # Auto-verify in dev mode
        )
        
        self.db.add(user)
        self.db.flush()
        
        # Create default project
        project = Project(
            user_id=user.id,
            name="My Project",
            slug="my-project",
            description="Default project",
        )
        self.db.add(project)
        
        self.db.commit()
        
        logger.info("user_created", user_id=user.id, email=email)
        return user, None
    
    def authenticate(
        self,
        email: str,
        password: str,
    ) -> Tuple[User | None, str | None]:
        """
        Authenticate a user with email and password.
        
        Args:
            email: User's email
            password: Plain text password
            
        Returns:
            Tuple of (User, error_message)
        """
        user = self.db.query(User).filter(User.email == email.lower()).first()
        
        if not user:
            return None, "Invalid email or password"
        
        if not user.is_active:
            return None, "Account is disabled"
        
        if not verify_password(password, user.password_hash):
            logger.warning("login_failed", email=email)
            return None, "Invalid email or password"
        
        # Update last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        logger.info("user_authenticated", user_id=user.id)
        return user, None
    
    def get_user_by_id(self, user_id: str) -> User | None:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_email(self, email: str) -> User | None:
        """Get user by email."""
        return self.db.query(User).filter(User.email == email.lower()).first()
    
    def update_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> str | None:
        """
        Update user's password.
        
        Args:
            user: User object
            current_password: Current password
            new_password: New password
            
        Returns:
            Error message or None on success
        """
        if not verify_password(current_password, user.password_hash):
            return "Current password is incorrect"
        
        if len(new_password) < 8:
            return "New password must be at least 8 characters"
        
        user.password_hash = hash_password(new_password)
        self.db.commit()
        
        logger.info("password_updated", user_id=user.id)
        return None


# ==================== Project Service ====================


class ProjectService:
    """
    Project management service.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_project(
        self,
        user: User,
        name: str,
        description: str | None = None,
    ) -> Tuple[Project | None, str | None]:
        """
        Create a new project for a user.
        
        Args:
            user: Owner user
            name: Project name
            description: Optional description
            
        Returns:
            Tuple of (Project, error_message)
        """
        # Generate slug
        slug = name.lower().replace(" ", "-")
        slug = "".join(c for c in slug if c.isalnum() or c == "-")
        
        # Check for duplicate slug
        existing = self.db.query(Project).filter(
            Project.user_id == user.id,
            Project.slug == slug,
        ).first()
        
        if existing:
            return None, f"Project '{name}' already exists"
        
        project = Project(
            user_id=user.id,
            name=name,
            slug=slug,
            description=description,
        )
        
        self.db.add(project)
        self.db.commit()
        
        logger.info("project_created", project_id=project.id, user_id=user.id)
        return project, None
    
    def get_user_projects(self, user: User) -> list[Project]:
        """Get all projects for a user."""
        return self.db.query(Project).filter(
            Project.user_id == user.id,
            Project.is_active == True,
        ).all()
    
    def get_project_by_id(
        self,
        project_id: str,
        user: User,
    ) -> Project | None:
        """Get project by ID, verifying ownership."""
        return self.db.query(Project).filter(
            Project.id == project_id,
            Project.user_id == user.id,
        ).first()
    
    def delete_project(self, project: Project) -> None:
        """Soft delete a project."""
        project.is_active = False
        self.db.commit()
        logger.info("project_deleted", project_id=project.id)


# ==================== API Key Service ====================


class ApiKeyService:
    """
    API key management service.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_api_key(
        self,
        user: User,
        project: Project,
        name: str,
        expires_in_days: int | None = None,
    ) -> Tuple[str, ApiKey]:
        """
        Create a new API key for a project.
        
        Args:
            user: Key owner
            project: Target project
            name: Key name
            expires_in_days: Optional expiry in days
            
        Returns:
            Tuple of (full_key, ApiKey object)
        """
        full_key, key_hash = generate_api_key()
        
        api_key = ApiKey(
            user_id=user.id,
            project_id=project.id,
            name=name,
            key_hash=key_hash,
            key_prefix=get_key_prefix(full_key),
            expires_at=datetime.utcnow() + timedelta(days=expires_in_days) if expires_in_days else None,
        )
        
        self.db.add(api_key)
        self.db.commit()
        
        logger.info("api_key_created", key_id=api_key.id, project_id=project.id)
        
        # Return full key (only shown once!)
        return full_key, api_key
    
    def validate_api_key(self, key: str) -> Tuple[dict | None, dict | None, dict | None]:
        """
        Validate an API key and return associated objects (as dicts).
        
        Args:
            key: Full API key
            
        Returns:
            Tuple of (ApiKeyRequest, ProjectRequest, UserRequest) as dicts
        """
        from logcentry.api.services.cache import RedisCacheService
        cache = RedisCacheService()
        
        # Hash the key for secure lookup/storage (never cache raw key)
        key_hash = hash_api_key(key)
        cache_key = f"api_key:{key_hash}"
        
        # 1. Try Cache
        cached = cache.get(cache_key)
        if cached:
            return cached.get("api_key"), cached.get("project"), cached.get("user")

        # 2. Database Lookup
        # Dev bypass key
        if DEV_MODE and key == "lc_dev_bypass_key":
            api_key = self.db.query(ApiKey).filter(ApiKey.id == "demo-key-id").first()
            if api_key:
                project = self.db.query(Project).filter(Project.id == api_key.project_id).first()
                user = self.db.query(User).filter(User.id == api_key.user_id).first()
                return api_key.to_dict(), project.to_dict(), user.to_dict(include_sensitive=False)
        
        api_key = self.db.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        ).first()
        
        if not api_key:
            return None, None, None
        
        if api_key.is_expired():
            return None, None, None
        
        # Update last used (Async or occasional? For now, sync update invalidates strict read-only but acceptable)
        # We won't update 'last_used' on every cache hit to save DB writes, only on miss or background?
        # For this implementation, we only update DB on cache miss, or we skip updating last_used for cached hits.
        # To strictly track usage, we'd need to write to Redis then flush. 
        # For simplicity/performance, we update only on miss, meaning 'last_used' is approximate.
        api_key.last_used = datetime.utcnow()
        self.db.commit()
        
        project = self.db.query(Project).filter(Project.id == api_key.project_id).first()
        user = self.db.query(User).filter(User.id == api_key.user_id).first()
        
        # Serialize
        key_data = api_key.to_dict()
        project_data = {
            "id": project.id,
            "name": project.name,
            "slug": project.slug,
            "description": project.description,
        }
        user_data = user.to_dict(include_sensitive=False)
        
        # 3. Cache Result (60s TTL)
        cache_data = {
            "api_key": key_data,
            "project": project_data,
            "user": user_data,
        }
        cache.set(cache_key, cache_data, ttl=60)
        
        return key_data, project_data, user_data
    
    def get_project_keys(self, project: Project) -> list[ApiKey]:
        """Get all API keys for a project."""
        return self.db.query(ApiKey).filter(
            ApiKey.project_id == project.id,
            ApiKey.is_active == True,
        ).all()
    
    def revoke_key(self, api_key: ApiKey) -> None:
        """Revoke an API key."""
        api_key.is_active = False
        self.db.commit()
        logger.info("api_key_revoked", key_id=api_key.id)


# ==================== MFA Service ====================


class MFAService:
    """
    Multi-Factor Authentication service.
    
    Uses TOTP (Time-based One-Time Password).
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def setup_mfa(self, user: User) -> Tuple[str, str]:
        """
        Generate MFA secret for a user.
        
        Args:
            user: Target user
            
        Returns:
            Tuple of (secret, provisioning_uri)
        """
        import pyotp
        
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        self.db.commit()
        
        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="LogCentry",
        )
        
        return secret, uri
    
    def verify_mfa(self, user: User, code: str) -> bool:
        """
        Verify MFA code.
        
        Args:
            user: User with MFA secret
            code: 6-digit code
            
        Returns:
            True if valid
        """
        import pyotp
        
        if not user.mfa_secret:
            return False
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(code)
    
    def enable_mfa(self, user: User, code: str) -> bool:
        """
        Enable MFA after verifying code.
        
        Args:
            user: Target user
            code: Verification code
            
        Returns:
            True if enabled successfully
        """
        if self.verify_mfa(user, code):
            user.mfa_enabled = True
            self.db.commit()
            logger.info("mfa_enabled", user_id=user.id)
            return True
        return False
    
    def disable_mfa(self, user: User) -> None:
        """Disable MFA for a user."""
        user.mfa_enabled = False
        user.mfa_secret = None
        self.db.commit()
        logger.info("mfa_disabled", user_id=user.id)
