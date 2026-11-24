"""Role gate for the analyst workbench, layered on top of session authentication.

Only the `admin` role exists today (Milestone 6 adds finer roles). Every workbench route depends on
`require_analyst`, so introducing or removing a role is a one-line change to ANALYST_ROLES.
"""
from fastapi import Depends, HTTPException

from app.core.security import get_current_admin
from app.models.admin import Admin

ANALYST_ROLES = frozenset({"admin"})


def require_analyst(admin: Admin = Depends(get_current_admin)) -> Admin:
    # Read the module global at call time so the allow-list is the single source of truth.
    if admin.role not in ANALYST_ROLES:
        raise HTTPException(status_code=403, detail="Security analyst role required")
    return admin
