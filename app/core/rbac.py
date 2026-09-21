from enum import Enum

class Role(str, Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"
    VIEWER = "VIEWER"

class Action(str, Enum):
    MANAGE_ORGANIZATION = "manage_organization"
    MANAGE_AGENTS = "manage_agents"
    MANAGE_DELEGATIONS = "manage_delegations"
    VIEW_SECURITY = "view_security"
    USE_AGENTS = "use_agents"
    READ_ONLY = "read_only"

# Role to explicit permissions mapping
ROLE_PERMISSIONS = {
    Role.OWNER: {
        Action.MANAGE_ORGANIZATION,
        Action.MANAGE_AGENTS,
        Action.MANAGE_DELEGATIONS,
        Action.VIEW_SECURITY,
        Action.USE_AGENTS,
        Action.READ_ONLY,
    },
    Role.ADMIN: {
        Action.MANAGE_AGENTS,
        Action.MANAGE_DELEGATIONS,
        Action.VIEW_SECURITY,
        Action.USE_AGENTS,
        Action.READ_ONLY,
    },
    Role.MEMBER: {
        Action.USE_AGENTS,
        Action.READ_ONLY,
    },
    Role.VIEWER: {
        Action.READ_ONLY,
    }
}

def has_permission(user_role: str, action: Action) -> bool:
    try:
        role = Role(user_role)
        return action in ROLE_PERMISSIONS[role]
    except ValueError:
        return False

