from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.time import as_utc


class AuthorizationApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Admin must explicitly attest that the original written permission was reviewed.
    evidence_reviewed: Literal[True]
    review_note: str = Field(min_length=20, max_length=2000)

    @field_validator("review_note")
    @classmethod
    def strip_review_note(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 20:
            raise ValueError("Provide at least 20 characters describing the evidence and scope review")
        return value


class AuthorizationDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Provide a reason of at least 10 characters")
        return value


class AuthorizationAuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    authorization_id: int
    admin_id: int
    action: Literal["approved", "rejected", "revoked"]
    previous_status: str
    new_status: str
    note: str
    evidence_reviewed: bool
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return as_utc(value)
