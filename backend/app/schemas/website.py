from datetime import datetime
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from app.schemas.authorization import EffectiveAuthorizationStatus


class WebsiteCreate(BaseModel):
    client_id: int = Field(gt=0)
    name: str = Field(min_length=2, max_length=200)
    url: AnyHttpUrl
    platform: str | None = Field(default=None, max_length=100)
    environment: str = Field(default="production", pattern="^(production|staging|development)$")
    hosting_provider: str | None = Field(default=None, max_length=150)
    notes: str | None = Field(default=None, max_length=5000)

    @field_validator("url")
    @classmethod
    def reject_url_credentials(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.username or value.password:
            raise ValueError("Website URL must not contain a username or password")
        return value


class WebsiteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: int
    name: str
    url: str
    platform: str | None
    environment: str
    hosting_provider: str | None
    notes: str | None
    authorisation_status: str
    effective_authorisation_status: EffectiveAuthorizationStatus | Literal["not_requested"]
    created_at: datetime
