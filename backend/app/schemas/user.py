from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    full_name: str = Field(..., min_length=2, max_length=255)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    organization_id: Optional[int] = None
    role: str = "auditor"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None


class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    is_verified: bool
    organization_id: Optional[int]
    avatar_url: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    user_id: Optional[int] = None


class OrganizationCreate(BaseModel):
    name: str
    description: Optional[str] = None
    contact_email: Optional[str] = None
    website: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    contact_email: Optional[str]
    website: Optional[str]
    plan: str
    created_at: datetime

    class Config:
        from_attributes = True
