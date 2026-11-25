from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_public_routes_are_only_the_account_ones():
    with TestClient(app) as client:
        paths = client.get("/openapi.json").json()["paths"]
    for path in ("/api/v1/auth/signup", "/api/v1/auth/verify-email", "/api/v1/auth/forgot-password",
                 "/api/v1/auth/reset-password", "/api/v1/auth/change-password", "/api/v1/websites",
                 "/api/v1/websites/{website_id}/verify", "/api/v1/admin/users"):
        assert path in paths, path
