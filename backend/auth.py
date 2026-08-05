"""
ThreatVista authentication utilities.

Provides bcrypt password hashing, JWT issuance/verification, and FastAPI
dependencies for protecting routes with optional role-based access control.

Session model: every issued JWT carries a unique `jti` claim backed by a row
in the `sessions` table. `get_current_user` rejects tokens whose session has
been revoked (real logout / session management), so a stolen token can be
killed server-side rather than lingering until it expires.
"""
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.config import SECRET_KEY
from backend.database.connection import get_db
from backend.models.database import Session as SessionModel
from backend.models.database import User

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hour analyst session

security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(user: User) -> tuple:
    """Issue a signed JWT for the given user.

    Returns ``(token, jti, expires_at)`` so the caller can persist a matching
    ``Session`` row. Each token gets a fresh ``jti`` (a UUID) that uniquely
    identifies the session and enables server-side revocation.
    """
    jti = uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": expires_at,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti, expires_at


def create_session(db: Session, user: User, jti: str, expires_at: datetime, ip: Optional[str] = None) -> SessionModel:
    """Persist an active session row for an issued token."""
    session = SessionModel(
        user_id=user.id,
        jti=jti,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
        revoked=False,
        last_seen_at=datetime.utcnow(),
        ip_address=ip,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def revoke_session(db: Session, jti: str) -> None:
    """Revoke the session matching ``jti`` (used by logout / admin removal)."""
    session = db.query(SessionModel).filter(SessionModel.jti == jti).first()
    if session and not session.revoked:
        session.revoked = True
        db.commit()


def _session_is_active(session: SessionModel) -> bool:
    """A session is valid when not revoked and not expired."""
    if session is None or session.revoked:
        return False
    if session.expires_at is not None and session.expires_at < datetime.utcnow():
        return False
    return True


def decode_token(token: str) -> dict:
    """Decode and validate a JWT, raising HTTPException on failure."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency that resolves the authenticated user from the token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Session check: the token's jti must map to a live (non-revoked,
    # non-expired) session row. This is what makes logout actually revoke.
    jti = payload.get("jti")
    session = None
    if jti:
        session = db.query(SessionModel).filter(SessionModel.jti == jti).first()
    if not _session_is_active(session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Touch last-seen so active sessions stay visible in the audit UI.
    session.last_seen_at = datetime.utcnow()
    db.commit()
    return user


def require_roles(*roles: str):
    """Factory for a FastAPI dependency that enforces one of the given roles."""

    def role_dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_dependency
