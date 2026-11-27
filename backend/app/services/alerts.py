"""Email alerts (spec section 7), in plain language.

Every alert has the website name in the subject, one clear "What to do" line, a link to the place in the app, and a link to turn
that alert type off in Settings. The same alert (same website, type and key) is sent at most once per ALERT_REPEAT_HOURS (24 h).
An account can turn each alert type on or off; an alert that is off is not sent and not recorded. Until SMTP is configured the
mailer writes each email to the outbox folder (see mailer.py).

Types (the on/off switches in Settings):
  new_open_port         a port is open that the last scan did not find
  new_serious_finding   a new Critical or High finding
  certificate_expiring  the certificate ends within 14 days
  site_down_up          the website is down (2 checks in a row) and when it is back
  verification_lost     ownership could no longer be proved, so scans are paused
  risk_expiring         an accepted risk ends within 7 days
"""
from datetime import timedelta
import hashlib

from sqlalchemy import select

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.admin import Admin
from app.models.watch import Alert, AlertPreference
from app.models.website import Website
from app.services import job_engine as engine
from app.services import mailer, plans

ALERT_TYPES = {
    "new_open_port": {"label": "A new open port", "help": "A port is open that the last scan did not find."},
    "new_serious_finding": {"label": "A new Critical or High finding", "help": "A scan found a serious problem that was not there before."},
    "certificate_expiring": {"label": "Certificate ending soon", "help": "Your website's certificate ends within 14 days."},
    "site_down_up": {"label": "Website down, and back up", "help": "Your website did not answer 2 checks in a row, and when it answers again."},
    "verification_lost": {"label": "Ownership no longer proved", "help": "We could not prove you still own the website, so scans are paused."},
    "risk_expiring": {"label": "Accepted risk ending soon", "help": "A risk you accepted ends within 7 days."},
}


def website_name(website: Website) -> str:
    return website.name or website.domain or f"website {website.id}"


def settings_link(alert_type: str) -> str:
    return f"{settings.public_app_url.rstrip('/')}/#/settings/alerts/{alert_type}"


def website_link(website: Website, finding: str | None = None) -> str:
    base = f"{settings.public_app_url.rstrip('/')}/#/websites/{website.id}"
    return f"{base}/findings/{finding}" if finding else base


def key_for(*parts) -> str:
    """A short stable key for 'the same alert' (for example the set of new ports)."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def enabled(db, account_id: int, alert_type: str) -> bool:
    row = db.scalar(select(AlertPreference).where(AlertPreference.account_id == account_id, AlertPreference.alert_type == alert_type))
    return True if row is None else bool(row.enabled)


def preferences(db, account: Admin) -> list[dict]:
    chosen = {p.alert_type: p.enabled for p in db.scalars(select(AlertPreference).where(AlertPreference.account_id == account.id))}
    return [{"type": key, "label": meta["label"], "help": meta["help"], "enabled": chosen.get(key, True)} for key, meta in ALERT_TYPES.items()]


def set_preference(db, account: Admin, alert_type: str, on: bool) -> None:
    if alert_type not in ALERT_TYPES:
        raise ValueError("unknown_alert_type")
    row = db.scalar(select(AlertPreference).where(AlertPreference.account_id == account.id, AlertPreference.alert_type == alert_type))
    if row is None:
        db.add(AlertPreference(account_id=account.id, alert_type=alert_type, enabled=bool(on)))
    else:
        row.enabled = bool(on)
    engine.event(db, "alert_preference_changed", actor_id=account.id, detail={"alert_type": alert_type, "enabled": bool(on)})


def compose(website: Website, alert_type: str, headline: str, what: str, do: str, link: str, extra: list[str] | None = None) -> tuple[str, str]:
    name = website_name(website)
    subject = f"[{name}] {headline}"[:200]
    lines = [f"Hello,", "", f"About your website {name}:", "", what, ""]
    lines += list(extra or []) + ([""] if extra else [])
    lines += [f"What to do: {do}", "", f"See it in SNWebShield: {link}", "",
              "You get this email because alerts are on for your account.",
              f"Turn off this kind of alert: {settings_link(alert_type)}", "", "SNWebShield"]
    return subject, "\n".join(lines)


def raise_alert(db, website: Website, alert_type: str, key: str, *, headline: str, what: str, do: str, link: str | None = None,
                extra: list[str] | None = None, window_hours: int | None = None, now=None) -> Alert | None:
    """Send one alert unless it is switched off or the same alert was already sent inside the window. Returns the record or None."""
    if alert_type not in ALERT_TYPES:
        raise ValueError("unknown_alert_type")
    now = now or utc_now()
    owner = db.get(Admin, website.owner_id) if website.owner_id else None
    if owner is None or not owner.is_active or website.removed_at is not None:
        return None
    if "email" not in plans.get(owner.plan).get("alerts", ["email"]):
        return None
    if not enabled(db, owner.id, alert_type):
        return None
    window = timedelta(hours=window_hours or settings.alert_repeat_hours)
    seen = db.scalar(select(Alert.id).where(Alert.website_id == website.id, Alert.alert_type == alert_type, Alert.alert_key == key,
                                            Alert.created_at >= now - window).limit(1))
    if seen is not None:
        return None
    subject, body = compose(website, alert_type, headline, what, do, link or website_link(website), extra)
    record = Alert(website_id=website.id, owner_id=owner.id, alert_type=alert_type, alert_key=key, created_at=now,
                   channel=mailer.channel(), subject=subject, delivered=False)
    try:
        mailer.send(owner.email, subject, body)
        record.delivered = True
    except Exception as error:   # a mail problem must never stop the scan or the monitor; it is recorded and the alert is not retried for 24 h
        record.error = type(error).__name__[:80]
    db.add(record)
    engine.event(db, "alert_sent" if record.delivered else "alert_failed", resource_id=website.id, actor_id=None,
                 detail={"alert_type": alert_type, "channel": record.channel, "domain": website.domain})
    db.flush()
    return record


def send_test(db, account: Admin) -> str:
    """A test email to the account's own address (Settings: 'Send me a test alert'). Goes to the outbox until SMTP is set up."""
    subject = "[SNWebShield] Test alert"
    body = ("Hello,\n\nThis is a test alert from SNWebShield. Real alerts look like this one: the website name in the subject, "
            "what happened, one line saying what to do, and a link.\n\nWhat to do: nothing. This is only a test.\n\n"
            f"See SNWebShield: {settings.public_app_url}\n\nChange which alerts you get: {settings.public_app_url.rstrip('/')}/#/settings\n\nSNWebShield")
    channel = mailer.send(account.email, subject, body)
    engine.event(db, "alert_test_sent", actor_id=account.id, detail={"channel": channel})
    return channel


# --- alerts raised from a finished scan --------------------------------------------------------------------------------------------------------

def after_scan(db, scan, now=None) -> dict:
    """New open port and new Critical/High finding, compared with the website's previous scan. The first scan raises nothing."""
    from app.models.scan import ScanPort
    from app.services import comparison, finding_states
    website = db.get(Website, scan.website_id)
    sent = {"ports": 0, "findings": 0}
    if website is None or scan.scan_type == "recheck" or scan.status not in ("completed", "incomplete"):
        return sent
    before = comparison.previous_scan(db, scan)
    if before is None:
        return sent
    now_steps, old_steps = (scan.result or {}).get("steps") or {}, (before.result or {}).get("steps") or {}
    if now_steps.get("ports", {}).get("state") == "ok" and old_steps.get("ports", {}).get("state") == "ok":
        opened = lambda s: {p.port for p in db.scalars(select(ScanPort).where(ScanPort.scan_id == s.id, ScanPort.state == "open"))}
        new_ports = sorted(opened(scan) - opened(before))
        if new_ports:
            names = ", ".join(str(p) for p in new_ports[:10])
            if raise_alert(db, website, "new_open_port", key_for("ports", *new_ports), headline=f"New open port: {names}",
                           what=f"The latest scan found {'a port' if len(new_ports) == 1 else 'ports'} open that the scan before did not: {names}.",
                           do="If you did not expect this, close the port in your firewall or stop the service that uses it. If you did, no action is needed.",
                           now=now):
                sent["ports"] = 1
    data = comparison.compare(db, scan)
    serious = [f for f in data["new"] if f["severity"] in ("critical", "high") and f["confidence"] == "confirmed"]
    if serious:
        top = serious[0]
        extra = [f"- {f['severity'].capitalize()}: {f['title']}" for f in serious[:5]]
        if raise_alert(db, website, "new_serious_finding", key_for("findings", *sorted(f["fingerprint"] for f in serious)),
                       headline=f"{len(serious)} new serious finding{'s' if len(serious) != 1 else ''}",
                       what="The latest scan found serious problems that were not there before:", extra=extra,
                       do="Open the finding, read how to fix it, fix it, then use \"Re-scan to confirm fix\".",
                       link=website_link(website, top["fingerprint"]), now=now):
            sent["findings"] = 1
    return sent


# --- sweeps (run by the monitor role) -----------------------------------------------------------------------------------------------------------

def sweep_verification_lost(db, now=None) -> int:
    count = 0
    for website in db.scalars(select(Website).where(Website.verification_status == "lost", Website.removed_at.is_(None), Website.owner_id.is_not(None))):
        if raise_alert(db, website, "verification_lost", "lost", headline="We can no longer prove you own this website",
                       what="We checked again and could not find your ownership proof, so scans of this website are paused.",
                       do="Put the verification record or file back (or add it again), then press \"Check now\" on the website page.", now=now):
            count += 1
    return count


def sweep_risk_expiring(db, now=None) -> int:
    from app.models.scan import FindingState
    from app.services import finding_states
    now = now or utc_now()
    count = 0
    limit = now + timedelta(days=finding_states.REVIEW_SOON_DAYS)
    for state in db.scalars(select(FindingState).where(FindingState.status == "open", FindingState.accepted_until.is_not(None),
                                                      FindingState.accepted_until > now, FindingState.accepted_until <= limit)):
        website = db.get(Website, state.website_id)
        until = as_utc(state.accepted_until)
        if website and raise_alert(db, website, "risk_expiring", key_for(state.fingerprint, until.date()), window_hours=24 * 8,
                                   headline="An accepted risk ends soon",
                                   what=f"You accepted the risk \"{state.title}\" and it ends on {until.date().isoformat()}. After that it counts in your score again.",
                                   do="Fix it, or open it and accept the risk again with a new reason.",
                                   link=website_link(website, state.fingerprint), now=now):
            count += 1
    return count
