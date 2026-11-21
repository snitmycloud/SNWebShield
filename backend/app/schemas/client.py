from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ClientCreate(BaseModel):
    company_name: str = Field(min_length=2, max_length=200)
    primary_contact_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    phone: str | None = Field(default=None, max_length=40)
    industry: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=5000)


class ClientRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    company_name: str
    primary_contact_name: str
    email: EmailStr
    phone: str | None
    industry: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime
