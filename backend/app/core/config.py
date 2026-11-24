
from functools import lru_cache
from pathlib import Path
from typing import Literal

import re

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SNWebShield API"
    app_version: str = "0.1.0"

    database_url: str = "sqlite:///./snwebshield_dev.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    evidence_root: Path = Path.home() / "SNWebShield-Private" / "evidence"
    evidence_max_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=25 * 1024 * 1024)
    evidence_retention_days: int = Field(default=365, ge=1, le=3650)

    notification_channel: Literal["dashboard", "smtp"] = "dashboard"
    notification_recipient: str = ""
    smtp_host: str = ""
    smtp_port: int = Field(default=465, ge=1, le=65535)
    smtp_sender: str = ""
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")

    assessment_local_http_enabled: bool = False
    assessment_remote_docker_enabled: bool = False
    # Immutable image ID, not a tag or arbitrary Docker arguments. SSH uses the OS agent/config.
    assessment_remote_image_id: str = Field(default="", pattern=r"^(sha256:[0-9a-f]{64})?$")
    # Set true once the VM runner from Milestone 1 (per-run isolation inspection) is installed.
    assessment_remote_require_isolation_attestation: bool = False
    assessment_nmap_enabled: bool = False
    assessment_nmap_image_id: str = Field(default="", pattern=r"^(sha256:[0-9a-f]{64})?$")

    # JWT authentication settings
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_access_token_minutes: int = Field(default=20, ge=1, le=1440)
    jwt_issuer: str = "snwebshield-api"
    jwt_audience: str = "snwebshield-admin"

    # Login brute-force protection (failures per window; see services/auth_audit.py).
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_window_minutes: int = Field(default=15, ge=1, le=1440)

    # Dual sign-off. Off by default so a single bootstrap admin can still operate the whole workflow.
    # When true: the analyst who assessed a finding cannot approve it, the report creator cannot approve
    # the report, and whoever updated remediation (or accepted risk) cannot close the assessment.
    separation_of_duties_enabled: bool = False

    # Sent only when the API itself is served over HTTPS.
    hsts_max_age_seconds: int = Field(default=31536000, ge=0, le=63072000)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("cors_origins")
    @classmethod
    def _strict_cors(cls, value: str) -> str:
        # Credentials are allowed, so a wildcard or a malformed origin must fail at start-up.
        for origin in (part.strip() for part in value.split(",") if part.strip()):
            if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?", origin):
                raise ValueError("CORS_ORIGINS must be comma-separated http(s) origins without wildcards or paths")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
