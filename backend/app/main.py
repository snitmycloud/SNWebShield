from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api.routes import auth, authorizations, clients, health, websites, evidence
from app.core.config import settings
from app.db.session import engine
from app.models import (  # noqa: F401 - register the model relationships
    Admin,
    AuthorizationAuditEvent,
    Client,
    Website,
    WebsiteAuthorization,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    inspector = inspect(engine)
    if not inspector.has_table("website_authorizations") or "timestamps_verified" not in {
        column["name"] for column in inspector.get_columns("website_authorizations")
    }:
        raise RuntimeError("Database migration required. From backend run: python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("authorization_evidence", "evidence_reviews", "evidence_events")) or "evidence_revision" not in {c["name"] for c in inspector.get_columns("website_authorizations")} or "evidence_review_id" not in {c["name"] for c in inspector.get_columns("authorization_audit_events")}:
        raise RuntimeError("Evidence migration required: python -m alembic upgrade head")
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "SNWebShield local development API. Authorization records require admin authentication "
        "for access and decisions. Approval requires a stored document and a current accepted human evidence review; "
        "it does not itself start security testing."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Evidence-Filename"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(clients.router, prefix="/api/v1")
app.include_router(websites.router, prefix="/api/v1")
app.include_router(authorizations.router, prefix="/api/v1")

app.include_router(evidence.router, prefix="/api/v1")
