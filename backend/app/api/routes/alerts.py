"""Alert settings (per account) and the admin worker-health page."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import get_current_account, require_platform_admin
from app.core.time import utc_now
from app.db.session import get_db
from app.models.admin import Admin
from app.models.jobs import ExecutionEvent
from app.services import alerts, plans, worker_health
from app.services.scans import _day_start

router = APIRouter(tags=["Alerts"])
TEST_ALERTS_PER_DAY = 5


class PreferenceChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


@router.get("/alerts/preferences")
def read_preferences(account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    from app.services import mailer
    return {"alerts": alerts.preferences(db, account), "email_included": "email" in plans.get(account.plan).get("alerts", ["email"]),
            "delivery": mailer.channel(), "email": account.email}


@router.put("/alerts/preferences/{alert_type}")
def change_preference(alert_type: str, payload: PreferenceChange, account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    try:
        alerts.set_preference(db, account, alert_type, payload.enabled)
    except ValueError:
        raise HTTPException(404, "Unknown alert type")
    db.commit()
    return {"alerts": alerts.preferences(db, account)}


@router.post("/alerts/test")
def send_test_alert(account: Admin = Depends(get_current_account), db: Session = Depends(get_db)):
    """'Send me a test alert': one email to the account's own address (the outbox folder until SMTP is set up)."""
    used = db.scalar(select(func.count()).select_from(ExecutionEvent).where(
        ExecutionEvent.action == "alert_test_sent", ExecutionEvent.actor_id == account.id, ExecutionEvent.occurred_at >= _day_start(utc_now()))) or 0
    if used >= TEST_ALERTS_PER_DAY:
        raise HTTPException(429, {"code": "test_alert_limit", "message": f"You can send {TEST_ALERTS_PER_DAY} test alerts a day. Try again tomorrow."})
    channel = alerts.send_test(db, account)
    db.commit()
    return {"sent": True, "channel": channel}


@router.get("/admin/workers")
def worker_status(admin: Admin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    """Administrator only: is each background role running (judged by the server clock)."""
    return worker_health.status(db)
