from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def _clean_email(value) -> str:
    return str(value).strip().lower()


class AdminLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SignUp(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    full_name: str = Field(default="", max_length=150)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value):
        return _clean_email(value)


class EmailOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value):
        return _clean_email(value)


class TokenOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=10, max_length=200)


class ResetPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=1, max_length=128)


class ChangePassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class AdminRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    plan: str
    email_verified_at: datetime | None
    last_login_at: datetime | None


class TokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    admin: AdminRead
