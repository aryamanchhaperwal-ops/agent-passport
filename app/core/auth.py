import jwt
from jwt import PyJWKClient
from pydantic import BaseModel
from typing import Any
from app.core.config import settings

class AuthenticatedPrincipal(BaseModel):
    subject: str
    organization_id: str | None = None
    role: str = "VIEWER"
    auth_method: str
    claims: dict[str, Any] = {}

_jwks_client = None
if settings.auth_mode == "prod" and settings.jwt_jwks_url:
    _jwks_client = PyJWKClient(settings.jwt_jwks_url)

def validate_jwt(token: str) -> AuthenticatedPrincipal:
    if settings.auth_mode != "prod":
        raise ValueError("JWT validation requires prod auth_mode")
        
    if not _jwks_client:
        raise ValueError("Missing JWT configuration (JWKS URL)")
        
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=settings.jwt_algorithms,
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "sub"]}
        )
        
        # In a real OIDC setup, org/role might come from custom claims
        return AuthenticatedPrincipal(
            subject=payload["sub"],
            organization_id=payload.get("org_id"),
            role=payload.get("role", "VIEWER"),
            auth_method="jwt",
            claims=payload
        )
    except jwt.PyJWTError as e:
        raise ValueError(f"Invalid JWT: {str(e)}")

