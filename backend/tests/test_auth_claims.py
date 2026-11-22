from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import jwt
import pytest

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import Admin
from test_auth import create_admin_and_login


@pytest.mark.parametrize("change", ["expired", "issuer", "audience", "role", "token_type", "missing_exp"])
def test_invalid_claims_are_rejected(change):
    with TestClient(app) as client:
        _, headers = create_admin_and_login(client)
        key = settings.jwt_secret_key.get_secret_value()
        claims = jwt.decode(headers["Authorization"].split()[1], key,
                            algorithms=["HS256"], audience=settings.jwt_audience)
        if change == "expired":
            claims["exp"] = int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())
        elif change == "missing_exp":
            del claims["exp"]
        else:
            claims[{"issuer": "iss", "audience": "aud"}.get(change, change)] = "incorrect"
        token = jwt.encode(claims, key, algorithm="HS256")
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_deactivating_admin_invalidates_existing_token():
    with TestClient(app) as client:
        admin, headers = create_admin_and_login(client)
        with SessionLocal() as db:
            db.get(Admin, admin.id).is_active = False
            db.commit()
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_unknown_email_is_rejected():
    with TestClient(app) as client:
        result = client.post("/api/v1/auth/login", json={"email": "unknown@example.com", "password": "Synthetic-password-123!"})
        assert result.status_code == 401
        assert result.json()["detail"] == "Incorrect email or password"
