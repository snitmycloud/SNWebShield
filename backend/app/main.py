from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api import legacy
from app.api.routes import (admin_users, assessments, auth, clients, findings, health, monitoring, port_watch,
                            remediation, reports, vulnerabilities, websites, workbench)
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
    if not all(inspector.has_table(name) for name in ("scan_ports", "scan_technologies", "scan_observations")):
        raise RuntimeError("Detection migration required (back up first): python -m alembic upgrade head")
    if not all(inspector.has_table(name) for name in ("scans", "account_tokens", "retired_tables")) or not {
            "owner_id", "removed_at"} <= {c["name"] for c in inspector.get_columns("websites")}:
        raise RuntimeError("Self-service migration required (back up first): python -m alembic upgrade head")
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "SNWebShield API. Customers sign up, add websites and prove ownership (DNS TXT, file or meta tag); "
        "ownership verification is the only approval step and starts the first scan automatically."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)
# Added last so it is outermost and also decorates CORS preflight and error responses.
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(websites.router, prefix="/api/v1")
app.include_router(admin_users.router, prefix="/api/v1")

# Legacy analyst pipeline: staff-only and read-only (stop actions excepted) until Phases 2-4 replace it.
# The written-permission system (authorisations, evidence) was removed in Phase 1; its tables keep their data.
for _legacy in (clients, monitoring, assessments, findings, vulnerabilities, workbench, reports, remediation, port_watch):
    app.include_router(_legacy.router, prefix="/api/v1", dependencies=[Depends(legacy.read_only)])
