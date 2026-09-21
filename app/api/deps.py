from fastapi import Header, HTTPException, Depends
from app.repositories.user import UserRepository
from app.db.models import UserRecord

def get_current_user(x_user_id: str | None = Header(default=None)) -> UserRecord:
    """Mock authentication dependency. In production, this will use real auth."""
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Authentication required (missing X-User-Id)")
    
    repo = UserRepository()
    user = repo.get(x_user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
        
    if user.status != "ACTIVE":
        raise HTTPException(status_code=403, detail="User is inactive")
        
    return user

def require_role(action: str):
    def role_checker(user: UserRecord = Depends(get_current_user)) -> UserRecord:
        from app.core.rbac import has_permission, Action
        
        # Convert string action to Action enum
        try:
            enum_action = Action(action)
        except ValueError:
            raise HTTPException(status_code=500, detail=f"Invalid action {action}")
            
        if not has_permission(user.role, enum_action):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
            
        return user
    return role_checker
