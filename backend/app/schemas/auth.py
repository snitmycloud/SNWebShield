from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AdminLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class AdminRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None


class TokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    admin: AdminRead
