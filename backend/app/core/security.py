from datetime import UTC, datetime, timedelta
import secrets

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.admin import Admin


JWT_ALGORITHM = "HS256"
password_hasher = PasswordHasher()
# A dummy Argon2 hash helps make unknown-email and wrong-password failures less distinguishable.
_DUMMY_PASSWORD_HASH = password_hasher.hash("SNWebShield-dummy-login-check-" + secrets.token_urlsafe(24))
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="AdminBearerToken")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_unknown_user_password(plain_password: str) -> None:
    verify_password(plain_password, _DUMMY_PASSWORD_HASH)


def get_jwt_signing_key() -> str:
    key = settings.jwt_secret_key.get_secret_value()
    if len(key.encode("utf-8")) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY is not configured. Set a random secret of at least 32 bytes in backend/.env."
        )
    return key


def create_access_token(admin: Admin) -> tuple[str, int]:
    expires_in = settings.jwt_access_token_minutes * 60
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=expires_in)
    claims = {
        "sub": str(admin.id),
        "role": admin.role,
        "token_type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": secrets.token_urlsafe(24),
    }
    token = jwt.encode(claims, get_jwt_signing_key(), algorithm=JWT_ALGORITHM)
    return token, expires_in


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired administrator credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Admin:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    try:
        key = get_jwt_signing_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        claims = jwt.decode(
            credentials.credentials,
            key,
            algorithms=[JWT_ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": ["sub", "role", "token_type", "iss", "aud", "iat", "nbf", "exp", "jti"]
            },
            leeway=15,
        )
    except jwt.InvalidTokenError as exc:
        raise _unauthorized() from exc

    if claims.get("token_type") != "access" or claims.get("role") != "admin":
        raise _unauthorized()

    try:
        admin_id = int(claims["sub"])
    except (TypeError, ValueError) as exc:
        raise _unauthorized() from exc

    admin = db.get(Admin, admin_id)
    if admin is None or not admin.is_active:
        raise _unauthorized()
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return admin
