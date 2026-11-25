"""Staff role gates for the legacy (read-only) analyst pages, layered on top of session authentication.

Customer accounts have the `user` role and never pass `get_current_admin`. Staff roles
(`models.admin.ADMIN_ROLES`): `analyst`, `lead_analyst` and `admin`. Dual sign-off was removed in Phase 1.
"""
from fastapi import Depends, HTTPException

from app.core.security import get_current_admin
from app.models.admin import Admin

ANALYST_ROLES = frozenset({"admin", "lead_analyst", "analyst"})


def require_analyst(admin: Admin = Depends(get_current_admin)) -> Admin:
    # Read the module global at call time so the allow-list is the single source of truth.
    if admin.role not in ANALYST_ROLES:
        raise HTTPException(status_code=403, detail="Security analyst role required")
    return admin


# --- Module G: VAPT reports --------------------------------------------------------------
# Separate allow-lists so Milestone 6 can split "may prepare reports" from "may approve them".
REPORT_ROLES = frozenset({"admin", "lead_analyst", "analyst"})
REPORT_APPROVER_ROLES = frozenset({"admin", "lead_analyst"})


def require_report_role(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in REPORT_ROLES:
        raise HTTPException(status_code=403, detail="Report role required")
    return admin


def require_report_approver(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in REPORT_APPROVER_ROLES:
        raise HTTPException(status_code=403, detail="Report approver role required")
    return admin


# --- Module H: remediation, retesting and closure ----------------------------------------
# Separate allow-lists: who may update remediation and request retests, who may accept a risk,
# and who may close an assessment. Read at call time so each is the single source of truth.
REMEDIATION_ROLES = frozenset({"admin", "lead_analyst", "analyst"})
RISK_ACCEPTANCE_ROLES = frozenset({"admin", "lead_analyst"})
CLOSURE_ROLES = frozenset({"admin", "lead_analyst"})
# Lifting a closure lock is a formal, audited act reserved for the same senior roles.
CLOSURE_REOPEN_ROLES = frozenset({"admin", "lead_analyst"})


def require_remediation_role(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in REMEDIATION_ROLES:
        raise HTTPException(status_code=403, detail="Remediation role required")
    return admin


def require_closure_role(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in CLOSURE_ROLES:
        raise HTTPException(status_code=403, detail="Assessment closure role required")
    return admin


def ensure_risk_acceptor(admin: Admin) -> None:
    if admin.role not in RISK_ACCEPTANCE_ROLES:
        raise HTTPException(status_code=403, detail="Risk acceptance role required")


def require_closure_reopen_role(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in CLOSURE_REOPEN_ROLES:
        raise HTTPException(status_code=403, detail="Closure reopening role required")
    return admin


INFRASTRUCTURE_ROLES = frozenset({"admin", "lead_analyst"})


def require_infrastructure_role(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role not in INFRASTRUCTURE_ROLES:
        raise HTTPException(status_code=403, detail="Infrastructure role required")
    return admin
