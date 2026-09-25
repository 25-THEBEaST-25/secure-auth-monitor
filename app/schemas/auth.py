from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # Loose limits here on purpose: login must not reveal the signup policy.
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
