
from functools import lru_cache
from pathlib import Path
from typing import Literal

import re

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Fixed list of approved test targets: addresses the project that owns them publicly allows scanning for testing.
# It is a constant in code, not a setting that can be read from .env or changed from the app. Only `admin`
# accounts can use it, at most TEST_TARGET_SCANS_PER_DAY scans per target per UTC day, and every scan is audited.
APPROVED_TEST_TARGETS = ("scanme.nmap.org",)  # published by the Nmap project for test scans
TEST_TARGET_SCANS_PER_DAY = 2


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

    # --- Self-service accounts (Phase 1) ---
    # Used to build the links in verification and password-reset emails.
    frontend_base_url: str = Field(default="http://localhost:5173", pattern=r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$")
    # Account emails use SMTP when SMTP_HOST and SMTP_SENDER are set; otherwise (development only) each email
    # is written as a .eml file to this private folder, which must stay outside the repository.
    mail_outbox_dir: Path = Path.home() / "SNWebShield-Private" / "outbox"
    smtp_security: Literal["ssl", "starttls"] = "ssl"
    email_verification_hours: int = Field(default=24, ge=1, le=168)
    password_reset_minutes: int = Field(default=60, ge=10, le=1440)
    # Sign-ups per client address, and reset/verification emails per address, within signup_window_minutes.
    signup_max_per_ip: int = Field(default=5, ge=1, le=1000)
    account_email_max_per_ip: int = Field(default=10, ge=1, le=1000)
    signup_window_minutes: int = Field(default=60, ge=1, le=1440)

    # --- Ownership verification and scans ---
    ownership_cache_hours: int = Field(default=24, ge=1, le=168)
    ownership_http_timeout_seconds: float = Field(default=8.0, ge=1, le=30)
    scan_max_concurrent: int = Field(default=3, ge=1, le=20)
    scan_max_per_website: Literal[1] = 1  # enforced by a unique index on active scans
    scan_time_limit_seconds: int = Field(default=900, ge=30, le=7200)
    # --- Detection limits (Phase 2) ---
    scan_connect_concurrency: int = Field(default=100, ge=1, le=500)
    scan_port_timeout_seconds: float = Field(default=1.5, ge=0.2, le=10)
    scan_ports_per_second: int = Field(default=300, ge=1, le=2000)
    scan_probe_timeout_seconds: float = Field(default=3.0, ge=0.5, le=15)   # per open port: banner, HTTP and TLS together
    scan_probe_concurrency: int = Field(default=8, ge=1, le=50)
    scan_banner_max_bytes: int = Field(default=1024, ge=64, le=8192)
    scan_http_body_max_bytes: int = Field(default=256 * 1024, ge=4096, le=2 * 1024 * 1024)
    scan_http_request_timeout_seconds: float = Field(default=3.0, ge=0.5, le=15)
    scan_dns_timeout_seconds: float = Field(default=3.0, ge=0.5, le=15)
    crtsh_timeout_seconds: float = Field(default=6.0, ge=1, le=15)           # short: never holds up the scan
    # How often a running scan re-reads the website, owner and verification, so it can stop cleanly (seconds).
    scan_guard_poll_seconds: float = Field(default=1.0, ge=0.2, le=10)
    # Extra addresses of this server (comma-separated) that a scan must never target, on top of its own
    # interface addresses, which are detected automatically.
    server_public_ips: str = ""

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
    def approved_test_targets(self) -> tuple[str, ...]:
        """Read-only. There is no environment variable or API for this list."""
        return APPROVED_TEST_TARGETS

    @property
    def test_target_scans_per_day(self) -> int:
        return TEST_TARGET_SCANS_PER_DAY

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
