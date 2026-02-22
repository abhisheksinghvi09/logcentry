"""
LogCentry API - Zero-Knowledge Auth Service

Implements specific logic for ZK authentication (registration and login).
"""

import hmac
import hashlib
import secrets
import time
import base64
from typing import Tuple

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from logcentry.api.database import User
from logcentry.api.users import UserService, create_access_token
from logcentry.core.config import settings

# Helper to decode base64 safely
def decode_base64(data: str) -> bytes:
    try:
        return base64.b64decode(data)
    except Exception:
        raise ValueError("Invalid base64 encoding")

class ZKAuthService:
    def __init__(self, db: Session):
        self.db = db
        self.user_service = UserService(db)

    def register_user(self, email: str, username: str, salt: str, verifier: str) -> User:
        """
        Register a user with ZK credentials.
        """
        # Check if user exists
        if self.user_service.get_user_by_email(email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        
        # Verify formats
        try:
            decode_base64(salt)
            decode_base64(verifier)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid salt or verifier format (must be base64)",
            )

        # Create user
        user = User(
            email=email,
            name=username,
            password_verifier=verifier,
            password_salt=salt,
            is_active=True,
            email_verified=True, # Auto-verify for now
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def create_login_challenge(self, email: str) -> Tuple[str, str, str]:
        """
        Start login flow.
        
        Returns:
            (salt, challenge, login_token)
        """
        user = self.user_service.get_user_by_email(email)
        if not user:
            # Return fake data to prevent enumeration? 
            # For simplicity in this demo, we'll return error or fake.
            # Returning error for better DX for now.
             raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        
        if not user.password_verifier:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not setup for ZK auth",
            )

        # Generate random challenge
        challenge_bytes = secrets.token_bytes(32)
        challenge = base64.b64encode(challenge_bytes).decode('utf-8')

        # Create a temporary signed token containing the challenge
        # We reuse the JWT mechanism but with a special subject/type
        # Payload: sub=user_id, type=login_challenge, challenge=challenge
        # Expire in 2 minutes
        login_token = create_access_token(
            subject=user.id,
            email=email,
            expires_delta=120, # 2 minutes
            extra_claims={"type": "login_challenge", "challenge": challenge}
        )

        return user.password_salt, challenge, login_token

    def verify_login_proof(self, login_token: str, proof: str) -> User:
        """
        Verify client proof.
        """
        # 1. Verify token
        from logcentry.api.users import verify_token
        payload = verify_token(login_token)
        
        if not payload or payload.get("type") != "login_challenge":
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired login token",
            )
        
        user_id = payload["sub"]
        challenge_b64 = payload["challenge"]
        
        user = self.user_service.get_user_by_id(user_id)
        if not user:
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        # 2. Compute expected proof
        # Proof = HMAC_SHA256(verifier_bytes, challenge_bytes)
        try:
            verifier_bytes = decode_base64(user.password_verifier)
            challenge_bytes = decode_base64(challenge_b64)
            proof_bytes = decode_base64(proof)
        except ValueError:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid encoding",
            )

        # Calculate HMAC
        h = hmac.new(verifier_bytes, challenge_bytes, hashlib.sha256)
        expected_proof = h.digest()
        
        # Constant time comparison
        if not hmac.compare_digest(proof_bytes, expected_proof):
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid proof",
            )
            
        return user
