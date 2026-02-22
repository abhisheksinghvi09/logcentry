"""
LogCentry API - Authentication

API key and JWT authentication middleware for FastAPI.
Supports both SDK API keys and user JWT tokens.
"""

import hashlib
import os
import secrets
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from logcentry.api.database import get_db
from logcentry.api.users import ApiKeyService, UserService, verify_token
from logcentry.utils import get_logger

logger = get_logger(__name__)

# Dev mode flag
DEV_MODE = os.getenv("DEV_MODE", "true").lower() in ("true", "1", "yes")


# ==================== User Authentication ====================


async def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
):
    """
    Get current user from JWT token.
    
    Expects: Authorization: Bearer <token>
    """
    if not authorization:
        return None
    
    if not authorization.startswith("Bearer "):
        # Might be an API key in Authorization header, ignore here
        return None
    
    token = authorization[7:]
    
    # Quick check if it looks like a JWT (3 parts)
    if token.count('.') != 2:
        return None
        
    payload = verify_token(token)
    
    if not payload:
        return None
    
    if payload.get("type") != "access":
        return None
    
    user_service = UserService(db)
    user = user_service.get_user_by_id(payload["sub"])
    
    if not user or not user.is_active:
        return None
    
    return user


# ==================== API Key Authentication ====================


async def get_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> dict | None:
    """
    FastAPI dependency to validate API key from headers.
    Returns dict with project info or None if invalid/missing.
    """
    api_key = None
    
    # Try X-API-Key header first
    if x_api_key:
        api_key = x_api_key
    # Fall back to Authorization header
    elif authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
            # If it looks like a JWT, skip API key validation
            if token.count('.') == 2:
                return None
            api_key = token
    
    if not api_key:
        return None
    
    # Dev mode bypass keys
    if DEV_MODE:
        if api_key.startswith("lc_test") or api_key.startswith("lc_demo") or api_key == "test":
            return {
                "project_id": "demo-project-id",
                "project": "demo",
                "user_id": "demo-user-id",
                "key_prefix": api_key[:10] if len(api_key) >= 10 else api_key,
            }
    
    # Validate against database
    api_key_service = ApiKeyService(db)
    key_obj, project, user = api_key_service.validate_api_key(api_key)
    
    if not key_obj or not project:
        logger.warning("invalid_api_key", key_prefix=api_key[:10] if len(api_key) >= 10 else "***")
        return None
    
    return {
        "project_id": project["id"],
        "project": project["slug"],
        "project_name": project["name"],
        "user_id": user["id"] if user else None,
        "key_prefix": key_obj["key_prefix"],
    }


async def get_auth_context(
    x_project_id: Annotated[str | None, Header()] = None,
    user: Annotated[object | None, Depends(get_current_user)] = None,
    api_key_info: Annotated[dict | None, Depends(get_api_key)] = None,
    db: Session = Depends(get_db),
) -> dict:
    """
    Unified authentication dependency.
    
    Accepts either:
    1. API Key (via X-API-Key or Authorization header)
    2. JWT Token (via Authorization header) + Optional X-Project-Id header
    
    Returns:
        Dict with 'project', 'user_id', 'project_id'
    """
    # 1. Check API Key first
    if api_key_info:
        return api_key_info
    
    # 2. Check JWT User
    if user:
        # If user is authenticated, check for project context
        from logcentry.api.database import Project

        project = None
        
        if x_project_id:
            # Validate user has access to this project
            project = db.query(Project).filter(
                Project.id == x_project_id,
                Project.user_id == user.id
            ).first()
        
        # If no specific project requested or found, try to use default/first
        if not project and user.projects:
            project = user.projects[0]
            
        return {
            "project_id": project.id if project else "unknown",
            "project": project.slug if project else "unknown",
            "user_id": user.id,
            "key_prefix": "jwt_auth",
        }


        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (API Key or Login)",
    )


# Type aliases
ApiKeyDep = Annotated[dict, Depends(get_auth_context)]


# ==================== Demo Key Generation ====================


def generate_api_key(project_name: str = "demo") -> tuple[str, str]:
    """
    Generate a new API key.
    
    Returns:
        Tuple of (full_key, key_hash)
    """
    key = f"lc_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash


def create_demo_key() -> str:
    """Create a demo API key for testing."""
    key, _ = generate_api_key("demo-project")
    logger.info("demo_key_created", key_prefix=key[:10])
    return key
