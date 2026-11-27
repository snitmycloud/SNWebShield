from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class WebsiteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Cleaned up and checked by services.domains.normalize_domain (scheme, path, case, IPs, internal names).
    domain: str = Field(min_length=1, max_length=2048)


class RemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The owner must type the website's domain to confirm.
    confirm_domain: str = Field(min_length=1, max_length=2048)


class AcceptRiskRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    days: Literal[30, 90, 180, 365] = 90


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # "full" (all 65,535 ports) is gated to Pro and above in plans.json; there is no UI for it yet.
    scan_type: Literal["standard", "full"] = "standard"


class ManualVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # All three are required and audit-logged; the rules (a real reason, not "admin only") are in ownership.manual_details_problem.
    owner_name: str = Field(min_length=1, max_length=120)
    consent_method: Literal["email", "written_letter", "in_person"]
    reason: str = Field(min_length=1, max_length=300)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["dns", "file", "meta"]
