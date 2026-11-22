
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
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

    # JWT authentication settings
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_access_token_minutes: int = Field(default=20, ge=1, le=1440)
    jwt_issuer: str = "snwebshield-api"
    jwt_audience: str = "snwebshield-admin"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

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
