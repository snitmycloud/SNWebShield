from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import auth, authorizations, clients, health, websites
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.models import (  # noqa: F401 - register every SQLAlchemy model before create_all
    Admin,
    AuthorizationAuditEvent,
    Client,
    Website,
    WebsiteAuthorization,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Local MVP convenience. Use Alembic migrations before production deployment.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "SNWebShield local development API. Authorization records require admin authentication "
        "for access and decisions. Approval records an administrator's evidence-review attestation; "
        "it does not itself start security testing."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(clients.router, prefix="/api/v1")
app.include_router(websites.router, prefix="/api/v1")
app.include_router(authorizations.router, prefix="/api/v1")
