import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.time import as_utc

PermittedTestingMethod = Literal[
    "passive_reconnaissance",
    "configuration_review",
    "automated_non_intrusive_scanning",
    "manual_web_application_testing",
    "authenticated_testing",
    "api_security_testing",
]

AuthorizationStatus = Literal["pending", "approved", "rejected", "expired", "revoked"]
EffectiveAuthorizationStatus = Literal[
    "pending", "active", "scheduled", "expired", "rejected", "revoked", "needs_date_review"
]

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _normalise_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or "*" in domain or "@" in domain:
        raise ValueError("Enter a hostname only, without scheme, path, wildcard or credentials")

    try:
        return str(ipaddress.ip_address(domain))
    except ValueError:
        pass

    if len(domain) > 253 or "." not in domain:
        raise ValueError("Enter a fully qualified domain name or IP address")
    labels = domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Domain contains an invalid hostname label")
    return domain


class AuthorizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    website_id: int = Field(gt=0)
    authorization_reference: str = Field(min_length=3, max_length=120)
    # Name transcribed from the written authorization; identity is not verified
    # until authenticated client onboarding is implemented.
    authorized_by: str = Field(min_length=2, max_length=150)
    authorized_domains: list[str] = Field(min_length=1, max_length=50)
    permitted_methods: list[PermittedTestingMethod] = Field(min_length=1, max_length=6)
    valid_from: datetime
    valid_until: datetime

    @field_validator("authorization_reference", "authorized_by")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field cannot be blank")
        return cleaned

    @field_validator("authorized_domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        normalised = [_normalise_domain(value) for value in values]
        if len(normalised) != len(set(normalised)):
            raise ValueError("Authorized domains must not contain duplicates")
        return normalised

    @field_validator("valid_from", "valid_until")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Date and time must include a timezone, such as Z or +05:30")
        return as_utc(value)

    @model_validator(mode="after")
    def validate_date_window(self):
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        return self


class AuthorizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    website_id: int
    authorization_reference: str
    authorized_by: str
    authorized_domains: list[str]
    permitted_methods: list[PermittedTestingMethod]
    valid_from: datetime
    valid_until: datetime
    status: AuthorizationStatus
    effective_status: EffectiveAuthorizationStatus
    timestamps_verified: bool
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at")
    @classmethod
    def utc_system_timestamp(cls, value: datetime) -> datetime:
        return as_utc(value)


class AuthorizationSummary(BaseModel):
    as_of: datetime
    total: int
    decision_counts: dict[str, int]
    effective_counts: dict[str, int]
