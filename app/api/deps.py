from fastapi import Header, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.repositories.user import UserRepository
from app.db.models import UserRecord
from app.core.config import settings
from app.core.auth import validate_jwt, AuthenticatedPrincipal
from app.core.apikey import verify_api_key, parse_prefix
from app.repositories.apikey import ApiKeyRepository
import datetime

security = HTTPBearer(auto_error=False)

def get_current_principal(
    x_user_id: str | None = Header(default=None),
    auth: HTTPAuthorizationCredentials | None = Depends(security)
) -> AuthenticatedPrincipal:
    
    # Dev mode fallback
    if settings.auth_mode == "dev" and x_user_id:
        repo = UserRepository()
        user = repo.get(x_user_id)
        if not user or user.status != "ACTIVE":
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return AuthenticatedPrincipal(
            subject=user.id,
            organization_id=user.organization_id,
            role=user.role,
            auth_method="dev_header"
        )
        
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    token = auth.credentials
    
    # Check if API Key
    if token.startswith("ap_"):
        prefix = parse_prefix(token)
        if not prefix:
            raise HTTPException(status_code=401, detail="Invalid API key format")
            
        key_repo = ApiKeyRepository()
        record = key_repo.get_by_prefix(prefix)
        if not record or record.status != "ACTIVE":
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
            
        if record.expires_at and record.expires_at < datetime.datetime.now(datetime.timezone.utc):
            raise HTTPException(status_code=401, detail="Expired API key")
            
        if not verify_api_key(token, record.key_hash):
            raise HTTPException(status_code=401, detail="Invalid API key")
            
        user_repo = UserRepository()
        user = user_repo.get(record.user_id)
        if not user or user.status != "ACTIVE":
            raise HTTPException(status_code=401, detail="User inactive")
            
        return AuthenticatedPrincipal(
            subject=record.user_id,
            organization_id=record.organization_id,
            role=user.role,
            auth_method="api_key",
            claims={"scopes": record.scopes}
        )
        
    # Otherwise treat as JWT
    if settings.auth_mode == "prod":
        try:
            return validate_jwt(token)
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
    else:
        raise HTTPException(status_code=401, detail="Invalid auth mode for JWT")

def get_current_user(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> UserRecord:
    repo = UserRepository()
    user = repo.get(principal.subject)
    if not user or user.status != "ACTIVE":
        raise HTTPException(status_code=401, detail="User not found")
        
    # Optionally verify org matches
    if principal.organization_id and user.organization_id != principal.organization_id:
        raise HTTPException(status_code=403, detail="Organization mismatch")
        
    return user

def require_role(action: str):
    def role_checker(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> AuthenticatedPrincipal:
        from app.core.rbac import has_permission, Action
        
        try:
            enum_action = Action(action)
        except ValueError:
            raise HTTPException(status_code=500, detail=f"Invalid action {action}")
            
        # 1. RBAC check
        if not has_permission(principal.role, enum_action):
            raise HTTPException(status_code=403, detail="Insufficient RBAC permissions")
            
        # 2. API Key scope check (if applicable)
        if principal.auth_method == "api_key":
            scopes = principal.claims.get("scopes", [])
            # Map action to a required scope, or assume action name is the scope
            # For simplicity, we require the scope to match the action exactly, or have a wildcard
            if action not in scopes and "*" not in scopes:
                raise HTTPException(status_code=403, detail="API key missing required scope")
            
        return principal
    return role_checker

