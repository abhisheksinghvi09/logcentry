"""
LogCentry API - Auth Routes

Authentication endpoints: signup, login, tokens, user info.
"""

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from logcentry.api.database import get_db, init_dev_data
from logcentry.api.users import (
    UserService,
    create_access_token,
    create_refresh_token,
    verify_token,
    DEV_MODE,
)
from logcentry.utils import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ==================== Request/Response Models ====================


class SignupRequest(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    """User login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict
    redirect_to: str = "/dashboard"


class RefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class UserResponse(BaseModel):
    """User info response."""
    id: str
    email: str
    name: Optional[str]
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]


class ChangePasswordRequest(BaseModel):
    """Password change request."""
    current_password: str
    new_password: str = Field(..., min_length=8)


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    success: bool = True


# ==================== Dependencies ====================


async def get_current_user(
    authorization: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Get current user from JWT token.
    
    Expects: Authorization: Bearer <token>
    """
    from fastapi import Header
    
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format. Use: Bearer <token>",
        )
    
    token = authorization[7:]
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    
    user_service = UserService(db)
    user = user_service.get_user_by_id(payload["sub"])
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    return user


# Type alias
CurrentUser = Annotated[object, Depends(get_current_user)]


# ==================== Routes ====================


@router.post("/signup", response_model=TokenResponse)
async def signup(request: SignupRequest, db: Session = Depends(get_db)):
    """
    Register a new user account.
    
    Returns JWT tokens on successful registration.
    """
    user_service = UserService(db)
    user, error = user_service.create_user(
        email=request.email,
        password=request.password,
        name=request.name,
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )
    
    # Generate tokens
    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * 60 * 24,  # 24 hours
        user=user.to_dict(),
        redirect_to="/welcome",  # New users always go to welcome/onboarding
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    login_request: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Login with email and password.
    
    Returns JWT tokens on success.
    """
    # Initialize Audit Service
    from logcentry.api.services.audit import AuditService
    audit = AuditService(db)
    client_ip = request.client.host
    
    # Dev mode bypass
    if DEV_MODE:
        if login_request.email == "demo@logcentry.dev" and login_request.password == "demo123":
            # Ensure demo user exists
            init_dev_data(db)
            user_service = UserService(db)
            user = user_service.get_user_by_email("demo@logcentry.dev")
            
            if user:
                access_token = create_access_token(user.id, user.email)
                refresh_token = create_refresh_token(user.id)
                
                audit.log_event("login_success", user_id=user.id, ip_address=client_ip, details="Dev Mode Bypass")
                
                return TokenResponse(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    expires_in=60 * 60 * 24,
                    user=user.to_dict(),
                    redirect_to="/admin" if user.is_admin else "/dashboard",
                )
    
    user_service = UserService(db)
    user, error = user_service.authenticate(
        email=login_request.email,
        password=login_request.password,
    )
    
    if error:
        audit.log_event("login_failed", details=f"Email: {login_request.email}, Error: {error}", ip_address=client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error,
        )
    
    audit.log_event("login_success", user_id=user.id, ip_address=client_ip)
    
    # Check if MFA is required
    if user.mfa_enabled:
        # Return partial token that requires MFA verification
        partial_token = create_access_token(
            user.id, user.email,
        )
        return TokenResponse(
            access_token="",  # Empty until MFA verified
            refresh_token="",
            expires_in=0,
            user={
                "id": user.id,
                "email": user.email,
                "mfa_required": True,
                "mfa_token": partial_token,
            },
            redirect_to="/mfa-verify",
        )
    
    # Generate tokens
    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    
    # Determine redirect
    redirect_to = "/dashboard"
    if user.is_first_login:
        redirect_to = "/welcome"
    elif user.is_admin or user.role == "admin":
        redirect_to = "/admin/dashboard"
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * 60 * 24,
        user=user.to_dict(),
        redirect_to=redirect_to,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token.
    """
    payload = verify_token(request.refresh_token)
    
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    
    user_service = UserService(db)
    user = user_service.get_user_by_id(payload["sub"])
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    access_token = create_access_token(user.id, user.email)
    new_refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=60 * 60 * 24,
        user=user.to_dict(),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(
    authorization: str = None,
    db: Session = Depends(get_db),
):
    """
    Get current authenticated user info.
    
    Requires: Authorization: Bearer <token>
    """
    user = await get_current_user(authorization, db)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    request: ChangePasswordRequest,
    authorization: str = None,
    db: Session = Depends(get_db),
):
    """
    Change current user's password.
    """
    user = await get_current_user(authorization, db)
    user_service = UserService(db)
    
    error = user_service.update_password(
        user=user,
        current_password=request.current_password,
        new_password=request.new_password,
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )
    
    return MessageResponse(message="Password updated successfully")


# ==================== MFA Routes ====================


class MFASetupResponse(BaseModel):
    """MFA setup response with secret and QR code."""
    secret: str
    qr_uri: str
    message: str


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""
    code: str = Field(..., min_length=6, max_length=6)
    mfa_token: Optional[str] = None  # For login flow


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    authorization: str = None,
    db: Session = Depends(get_db),
):
    """
    Setup MFA for current user.
    
    Returns secret and QR code URI for authenticator app.
    """
    user = await get_current_user(authorization, db)
    
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )
    
    from logcentry.api.users import MFAService
    mfa_service = MFAService(db)
    secret, uri = mfa_service.setup_mfa(user)
    
    return MFASetupResponse(
        secret=secret,
        qr_uri=uri,
        message="Scan QR code with authenticator app, then verify with /mfa/enable",
    )


@router.post("/mfa/enable", response_model=MessageResponse)
async def enable_mfa(
    request: MFAVerifyRequest,
    authorization: str = None,
    db: Session = Depends(get_db),
):
    """
    Enable MFA after verifying code from authenticator app.
    """
    user = await get_current_user(authorization, db)
    
    from logcentry.api.users import MFAService
    mfa_service = MFAService(db)
    
    if not mfa_service.enable_mfa(user, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )
    
    return MessageResponse(message="MFA enabled successfully")


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    request: MFAVerifyRequest,
    db: Session = Depends(get_db),
):
    """
    Verify MFA code during login flow.
    
    Complete login by providing the mfa_token from login response.
    """
    if not request.mfa_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mfa_token required",
        )
    
    payload = verify_token(request.mfa_token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )
    
    user_service = UserService(db)
    user = user_service.get_user_by_id(payload["sub"])
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    from logcentry.api.users import MFAService
    mfa_service = MFAService(db)
    
    if not mfa_service.verify_mfa(user, request.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )
    
    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * 60 * 24,
        user=user.to_dict(),
    )


@router.post("/mfa/disable", response_model=MessageResponse)
async def disable_mfa(
    request: MFAVerifyRequest,
    authorization: str = None,
    db: Session = Depends(get_db),
):
    """
    Disable MFA (requires current MFA code).
    """
    user = await get_current_user(authorization, db)
    
    from logcentry.api.users import MFAService
    mfa_service = MFAService(db)
    
    if not mfa_service.verify_mfa(user, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code",
        )
    
    mfa_service.disable_mfa(user)
    
    return MessageResponse(message="MFA disabled successfully")


# ==================== Zero-Knowledge Auth Routes ====================


class ZKSignupRequest(BaseModel):
    """ZK Registration Request."""
    email: EmailStr
    username: str
    salt: str      # Base64
    verifier: str  # Base64


class ZKChallengeRequest(BaseModel):
    """ZK Login Challenge Request."""
    email: EmailStr


class ZKChallengeResponse(BaseModel):
    """ZK Login Challenge Response."""
    salt: str
    challenge: str
    login_token: str


class ZKVerifyRequest(BaseModel):
    """ZK Login Verification Request."""
    login_token: str
    proof: str     # Base64


@router.post("/signup-zk", response_model=UserResponse)
async def signup_zk(request: ZKSignupRequest, db: Session = Depends(get_db)):
    """
    Register a user using Zero-Knowledge Proofs.
    Server stores ONLY verifier and salt.
    """
    from logcentry.api.services.auth_zk import ZKAuthService
    service = ZKAuthService(db)
    
    user = service.register_user(
        email=request.email,
        username=request.username,
        salt=request.salt,
        verifier=request.verifier,
    )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.post("/login-zk/challenge", response_model=ZKChallengeResponse)
async def login_zk_challenge(request: ZKChallengeRequest, db: Session = Depends(get_db)):
    """
    Step 1: Request login challenge.
    Returns salt and random challenge.
    """
    from logcentry.api.services.auth_zk import ZKAuthService
    service = ZKAuthService(db)
    
    salt, challenge, login_token = service.create_login_challenge(request.email)
    
    return ZKChallengeResponse(
        salt=salt,
        challenge=challenge,
        login_token=login_token,
    )


@router.post("/login-zk/verify", response_model=TokenResponse)
async def login_zk_verify(
    request: Request,
    verify_request: ZKVerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Step 2: Verify proof and issue token.
    Proof = HMAC(verifier, challenge)
    """
    from logcentry.api.services.auth_zk import ZKAuthService
    from logcentry.api.services.audit import AuditService
    
    service = ZKAuthService(db)
    audit = AuditService(db)
    client_ip = request.client.host
    
    try:
        user = service.verify_login_proof(verify_request.login_token, verify_request.proof)
    except HTTPException as e:
        audit.log_event("login_zk_failed", details=f"Token: {verify_request.login_token[:10]}..., Error: {e.detail}", ip_address=client_ip)
        raise e
    except Exception as e:
        audit.log_event("login_zk_failed", details=f"Unexpected error: {str(e)}", ip_address=client_ip)
        raise e
        
    audit.log_event("login_zk_success", user_id=user.id, ip_address=client_ip)
    
    # Generate tokens
    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    
    # Determine redirect
    redirect_to = "/dashboard"
    if user.is_first_login:
        redirect_to = "/welcome"
    elif user.is_admin or user.role == "admin":
        redirect_to = "/admin/dashboard"
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=60 * 60 * 24,
        user=user.to_dict(),
        redirect_to=redirect_to,
    )

