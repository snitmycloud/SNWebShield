"""The analyst-era pipeline is read-only (Phase 1 decision).

Staff can still read past assessments, vulnerabilities, reports, remediation, monitoring and port-watch data,
but nothing can start new work there. Only actions that STOP work stay allowed (cancel a run, disable
monitoring or port watch). This code is deleted once Phases 2-4 replace it.
"""
import re

from fastapi import HTTPException, Request

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STOP_ACTIONS = (
    re.compile(r"^/api/v1/assessments/[^/]+/cancel$"),
    re.compile(r"^/api/v1/websites/\d+/monitoring/(disable|revoke-consent)$"),
    re.compile(r"^/api/v1/monitoring/stop$"),
    re.compile(r"^/api/v1/port-watch/\d+/disable$"),
)
RETIRED_MESSAGE = ("This older feature is now read-only. New scans start automatically after you verify "
                   "ownership on the Websites page.")


def read_only(request: Request) -> None:
    if request.method in SAFE_METHODS:
        return
    if any(pattern.match(request.url.path) for pattern in STOP_ACTIONS):
        return
    raise HTTPException(status_code=410, detail=RETIRED_MESSAGE)
