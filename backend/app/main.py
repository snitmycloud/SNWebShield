from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api.routes import auth, authorizations, clients, health, websites, evidence, monitoring, assessments, findings, vulnerabilities, workbench, reports, remediation, port_watch
from app.core.config import settings
from app.core.headers import SecurityHeadersMiddleware
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
    if not inspector.has_table("jobs") or not inspector.has_table("monitoring_configs"):
        raise RuntimeError("Operations migration required: python -m alembic upgrade head")
    if not inspector.has_table("assessment_requests"):
        raise RuntimeError("Assessment migration required: python -m alembic upgrade head")
    if not inspector.has_table("assessment_reports"):
        raise RuntimeError("Local assessment migration required: python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("observation_reviews", "reviewed_assessment_exports")):
        raise RuntimeError("Analyst review migration required: python -m alembic upgrade head")
    if not inspector.has_table("finding_due_dates"):
        raise RuntimeError("Findings migration required: python -m alembic upgrade head")
    if not inspector.has_table("vulnerabilities"):
        raise RuntimeError("Vulnerability migration required: python -m alembic upgrade head")
    if not inspector.has_table("vulnerability_signoffs"):
        raise RuntimeError("Analyst workbench migration required: python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("vapt_reports", "vapt_report_approvals", "vapt_report_artifacts", "vapt_report_events")):
        raise RuntimeError("VAPT reporting migration required: python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("vulnerability_remediations", "remediation_events", "retest_requests", "assessment_closures")):
        raise RuntimeError("Remediation migration required: python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("auth_events", "revoked_tokens", "assessment_closure_reopenings")) or "purged_at" not in {c["name"] for c in inspector.get_columns("authorization_evidence")}:
        raise RuntimeError("Production hardening migration required: python -m alembic upgrade head")
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
    max_age=600,
)
# Added last so it is outermost and also decorates CORS preflight and error responses.
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(clients.router, prefix="/api/v1")
app.include_router(websites.router, prefix="/api/v1")
app.include_router(authorizations.router, prefix="/api/v1")

app.include_router(evidence.router, prefix="/api/v1")

app.include_router(monitoring.router, prefix="/api/v1")

app.include_router(assessments.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(workbench.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(remediation.router, prefix="/api/v1")
app.include_router(port_watch.router, prefix="/api/v1")
