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


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["dns", "file", "meta"]
