from pydantic import BaseModel, EmailStr
from backend.auth.roles import Role

from typing import Optional

class LoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    identity: Optional[str] = None
    password: str

    @property
    def resolved_identity(self) -> str:
        return self.identity or self.email or self.username or ""


class RefreshRequest(BaseModel):
    refresh_token: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: Role

from typing import Optional

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: Optional[str] = None
