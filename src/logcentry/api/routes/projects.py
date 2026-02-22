"""
LogCentry API - Project Routes

Project and API key management endpoints.
"""

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from logcentry.api.database import ApiKey, Project, User, get_db
from logcentry.api.users import ApiKeyService, ProjectService, UserService, verify_token
from logcentry.utils import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/projects", tags=["Projects"])


# ==================== Request/Response Models ====================


class CreateProjectRequest(BaseModel):
    """Create project request."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    """Project details response."""
    id: str
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    log_count: int
    api_key_count: int


class CreateApiKeyRequest(BaseModel):
    """Create API key request."""
    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = None


class ApiKeyResponse(BaseModel):
    """API key response (without full key)."""
    id: str
    name: str
    key_prefix: str
    project_id: str
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime]
    expires_at: Optional[datetime]


class ApiKeyCreatedResponse(BaseModel):
    """API key creation response (includes full key ONCE)."""
    id: str
    name: str
    key: str  # Full key - shown only once!
    key_prefix: str
    project_id: str
    created_at: datetime
    message: str = "Save this key! It won't be shown again."


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    success: bool = True


# ==================== Dependencies ====================


async def get_current_user_from_header(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User:
    """Get current user from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format",
        )
    
    token = authorization[7:]
    payload = verify_token(token)
    
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    
    user_service = UserService(db)
    user = user_service.get_user_by_id(payload["sub"])
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    return user


CurrentUser = Annotated[User, Depends(get_current_user_from_header)]


# ==================== Project Routes ====================


@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    List all projects for the current user.
    """
    project_service = ProjectService(db)
    projects = project_service.get_user_projects(user)
    
    return [
        ProjectResponse(
            id=p.id,
            name=p.name,
            slug=p.slug,
            description=p.description,
            is_active=p.is_active,
            created_at=p.created_at,
            log_count=len(p.logs) if p.logs else 0,
            api_key_count=len([k for k in p.api_keys if k.is_active]) if p.api_keys else 0,
        )
        for p in projects
    ]


@router.post("", response_model=ProjectResponse)
async def create_project(
    request: CreateProjectRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    Create a new project.
    """
    project_service = ProjectService(db)
    project, error = project_service.create_project(
        user=user,
        name=request.name,
        description=request.description,
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )
    
    return ProjectResponse(
        id=project.id,
        name=project.name,
        slug=project.slug,
        description=project.description,
        is_active=project.is_active,
        created_at=project.created_at,
        log_count=0,
        api_key_count=0,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    Get project details.
    """
    project_service = ProjectService(db)
    project = project_service.get_project_by_id(project_id, user)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    return ProjectResponse(
        id=project.id,
        name=project.name,
        slug=project.slug,
        description=project.description,
        is_active=project.is_active,
        created_at=project.created_at,
        log_count=len(project.logs) if project.logs else 0,
        api_key_count=len([k for k in project.api_keys if k.is_active]) if project.api_keys else 0,
    )


@router.delete("/{project_id}", response_model=MessageResponse)
async def delete_project(
    project_id: str,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    Delete a project (soft delete).
    """
    project_service = ProjectService(db)
    project = project_service.get_project_by_id(project_id, user)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    project_service.delete_project(project)
    
    return MessageResponse(message="Project deleted successfully")


# ==================== API Key Routes ====================


@router.get("/{project_id}/keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    project_id: str,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    List all API keys for a project.
    """
    project_service = ProjectService(db)
    project = project_service.get_project_by_id(project_id, user)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    api_key_service = ApiKeyService(db)
    keys = api_key_service.get_project_keys(project)
    
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            project_id=k.project_id,
            is_active=k.is_active,
            created_at=k.created_at,
            last_used=k.last_used,
            expires_at=k.expires_at,
        )
        for k in keys
    ]


@router.post("/{project_id}/keys", response_model=ApiKeyCreatedResponse)
async def create_api_key(
    project_id: str,
    request: CreateApiKeyRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    Create a new API key for a project.
    
    **Warning**: The full key is only shown once! Save it securely.
    """
    project_service = ProjectService(db)
    project = project_service.get_project_by_id(project_id, user)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    api_key_service = ApiKeyService(db)
    full_key, api_key = api_key_service.create_api_key(
        user=user,
        project=project,
        name=request.name,
        expires_in_days=request.expires_in_days,
    )
    
    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key=full_key,  # Only shown once!
        key_prefix=api_key.key_prefix,
        project_id=api_key.project_id,
        created_at=api_key.created_at,
    )


@router.delete("/{project_id}/keys/{key_id}", response_model=MessageResponse)
async def revoke_api_key(
    project_id: str,
    key_id: str,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    """
    Revoke an API key.
    """
    project_service = ProjectService(db)
    project = project_service.get_project_by_id(project_id, user)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Find the key
    api_key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.project_id == project_id,
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    api_key_service = ApiKeyService(db)
    api_key_service.revoke_key(api_key)
    
    return MessageResponse(message="API key revoked successfully")
