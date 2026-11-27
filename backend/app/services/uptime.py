"""Uptime checks (spec section 7): every 5 minutes (30 for the test target, a setting) for every verified website.

One small request to "/" over HTTPS (HTTP on port 80 if HTTPS does not answer), to the website's own address, which is looked up once
and must be public (the same rules as scans: no private, loopback, link-local, cloud-metadata or this server's own addresses). The
answer text is never kept: only the status code, the response time and the certificate's end date. A 5xx answer, no answer or a time-out
is a failed check; any other answer (even 401 or 404) means the site is up. After 2 failed checks in a row the website is down and
an alert is sent; the first good check afterwards sends "back up". A website whose address is not allowed is "could not check", which
is never counted as down. Uptime checks do not count against any scan limit. The certificate is read from the same connection once
a day, so the 14-day expiry alert works between weekly scans.
"""
import asyncio
from datetime import timedelta
import time

from sqlalchemy import delete, func, select

from app.core.config import settings
from app.core.time import as_utc, utc_now
from app.models.watch import UptimeCheck, UptimeState
from app.models.website import Website
from app.services import alerts, ip_policy, netio, scans, x509_lite

MAX_HEAD = 4096
_last_prune = {"at": 0.0}


def interval_for(website: Website) -> int:
    return settings.test_target_uptime_interval_seconds if scans.is_test_target(website) else settings.uptime_interval_seconds


async def _request(ip: str, port: int, tls: bool, domain: str, timeout: float) -> dict:
    began = time.monotonic()
    writer = None
    try:
        reader, writer = await netio.open_connection(ip, port, tls=tls, server_name=domain, timeout=timeout)
        cert = None
        if tls:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            parsed = x509_lite.parse_certificate(der) if der else None
            if parsed and parsed.get("not_after"):
                cert = {"not_after": parsed["not_after"], "subject_cn": parsed.get("subject_cn")}
        writer.write(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: SNWebShield-Uptime\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode("ascii", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout)
        head = await netio.read_some(reader, MAX_HEAD, timeout)
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split(" ")
        if not line.startswith("HTTP/") or len(parts) < 2 or not parts[1].isdigit():
            return {"ok": False, "error": "no_http_answer", "cert": cert, "scheme": "https" if tls else "http"}
        code = int(parts[1])
        return {"ok": code < 500, "status_code": code, "error": None if code < 500 else f"http_{code}", "cert": cert,
                "response_ms": int((time.monotonic() - began) * 1000), "scheme": "https" if tls else "http"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout", "scheme": "https" if tls else "http"}
    except Exception as error:
        return {"ok": False, "error": type(error).__name__[:40], "scheme": "https" if tls else "http"}
    finally:
        if writer is not None:
            await netio.close(writer)


async def probe(domain: str, *, resolve=None, timeout: float | None = None, ports=((443, True), (80, False))) -> dict:
    """One uptime check. Returns {ok, status_code, response_ms, error, scheme, cert}; ok is None when the check could not be made."""
    timeout = timeout or settings.uptime_timeout_seconds
    resolve = resolve or ip_policy.resolve_public
    try:
        addresses = await asyncio.get_running_loop().run_in_executor(None, resolve, domain)
    except ip_policy.Blocked as blocked:
        reason = str(blocked)
        if reason == "dns_lookup_failed":   # the name does not resolve: the site cannot be reached, which is down
            return {"ok": False, "error": "dns_lookup_failed", "scheme": None, "cert": None}
        return {"ok": None, "error": f"blocked_{reason}"[:60], "scheme": None, "cert": None}
    ip = addresses[0]   # one address, looked up once for this check
    (secure_port, _), (plain_port, _) = ports
    https = await _request(ip, secure_port, True, domain, timeout)
    if https.get("ok"):
        return https
    plain = await _request(ip, plain_port, False, domain, timeout)
    if plain.get("ok"):
        plain["cert"] = https.get("cert")
        return plain
    return {**https, "cert": https.get("cert")} if https.get("status_code") else {**plain, "cert": https.get("cert")} if plain.get("status_code") else https


def summary(db, website_id: int, now=None) -> dict:
    """What the screen shows: up / down / unknown, the last response time, 30-day uptime and the certificate."""
    now = now or utc_now()
    state = db.get(UptimeState, website_id)
    since = now - timedelta(days=30)
    total = db.scalar(select(func.count()).select_from(UptimeCheck).where(UptimeCheck.website_id == website_id, UptimeCheck.checked_at >= since, UptimeCheck.ok.is_not(None))) or 0
    good = db.scalar(select(func.count()).select_from(UptimeCheck).where(UptimeCheck.website_id == website_id, UptimeCheck.checked_at >= since, UptimeCheck.ok.is_(True))) or 0
    last = db.scalar(select(UptimeCheck).where(UptimeCheck.website_id == website_id).order_by(UptimeCheck.checked_at.desc()).limit(1))
    if state is None or last is None:
        status = "unknown"
    elif last.ok is None:
        status = "unknown"
    else:
        status = "down" if state.is_down else "up"
    days_left = (as_utc(state.cert_not_after) - now).days if state and state.cert_not_after else None
    return {"status": status, "last_checked_at": as_utc(state.last_checked_at).isoformat() if state and state.last_checked_at else None,
            "response_ms": last.response_ms if last else None, "status_code": last.status_code if last else None, "error": last.error if last else None,
            "down_since": as_utc(state.down_since).isoformat() if state and state.down_since else None,
            "uptime_30d": round(100.0 * good / total, 2) if total else None, "checks_30d": total, "certificate_days_left": days_left}


def _apply(db, website: Website, result: dict, now) -> dict:
    """Record one result and raise the down / back-up / certificate alerts. Returns what happened."""
    state = db.get(UptimeState, website.id)
    if state is None:
        state = UptimeState(website_id=website.id, consecutive_failures=0, is_down=False)
        db.add(state)
    db.add(UptimeCheck(website_id=website.id, checked_at=now, ok=result.get("ok"), status_code=result.get("status_code"),
                       response_ms=result.get("response_ms"), scheme=result.get("scheme"), error=(result.get("error") or None)))
    state.last_checked_at = now
    outcome = {"down_alert": False, "up_alert": False, "cert_alert": False}
    ok = result.get("ok")
    if ok is True:
        state.consecutive_failures, state.last_ok_at = 0, now
        if state.is_down:
            was_since = as_utc(state.down_since) if state.down_since else now
            state.is_down, state.down_since = False, None
            minutes = max(1, int((now - was_since).total_seconds() // 60))
            outcome["up_alert"] = bool(alerts.raise_alert(
                db, website, "site_down_up", alerts.key_for("up", was_since.isoformat()), headline="Your website is back up",
                what=f"Your website answers again. It was not answering for about {minutes} minute{'s' if minutes != 1 else ''}.",
                do="Nothing. If you did not expect the outage, check your hosting provider's status page and your server logs.", now=now))
    elif ok is False:
        state.consecutive_failures = (state.consecutive_failures or 0) + 1
        if state.consecutive_failures >= settings.uptime_failures_before_alert and not state.is_down:
            state.is_down, state.down_since = True, now
            outcome["down_alert"] = bool(alerts.raise_alert(
                db, website, "site_down_up", alerts.key_for("down", now.isoformat()), headline="Your website is down",
                what=f"Your website did not answer {state.consecutive_failures} checks in a row.",
                do="Check that your server is running and your domain still points to it. We will email you when it answers again.", now=now))
    cert = result.get("cert")
    if cert and (state.cert_checked_at is None or now - as_utc(state.cert_checked_at) >= timedelta(hours=24)):
        try:
            from datetime import datetime
            state.cert_not_after = as_utc(datetime.fromisoformat(cert["not_after"]))
            state.cert_subject = (cert.get("subject_cn") or "")[:255] or None
            state.cert_checked_at = now
            days = (state.cert_not_after - now).days
            if days <= settings.certificate_alert_days:
                when = "has ended" if days < 0 else f"ends in {days} day{'s' if days != 1 else ''} ({state.cert_not_after.date().isoformat()})"
                outcome["cert_alert"] = bool(alerts.raise_alert(
                    db, website, "certificate_expiring", alerts.key_for("cert", state.cert_not_after.date()), headline="Your certificate ends soon" if days >= 0 else "Your certificate has ended",
                    what=f"The security certificate of your website {when}. After that, visitors see a warning instead of your site.",
                    do="Renew the certificate with your hosting provider or certificate service (many renew automatically; check that this one does).", now=now))
        except (ValueError, KeyError, TypeError):
            pass
    return outcome


def due_websites(db, now) -> list[Website]:
    due = []
    states = {s.website_id: s for s in db.scalars(select(UptimeState))}
    for website in db.scalars(select(Website).where(Website.verification_status == "verified", Website.removed_at.is_(None), Website.domain.is_not(None))):
        if not settings.monitor_may_touch(website.domain):
            continue
        state = states.get(website.id)
        if state is None or state.last_checked_at is None or (now - as_utc(state.last_checked_at)).total_seconds() >= interval_for(website):
            due.append(website)
    return due


def tick(db, now=None, *, checker=None, concurrency: int = 10) -> dict:
    """Check every website whose time has come (concurrently), record the results and raise alerts."""
    now = now or utc_now()
    checker = checker or probe
    sites = due_websites(db, now)
    result = {"checked": 0, "down_alerts": 0, "up_alerts": 0, "cert_alerts": 0}
    if sites:
        async def run_all():
            gate = asyncio.Semaphore(concurrency)

            async def one(website):
                async with gate:
                    try:
                        return await checker(website.domain)
                    except Exception as error:
                        return {"ok": None, "error": type(error).__name__[:40], "scheme": None, "cert": None}
            return await asyncio.gather(*(one(w) for w in sites))
        answers = asyncio.run(run_all())
        for website, answer in zip(sites, answers):
            try:
                outcome = _apply(db, website, answer, utc_now())
                db.commit()
                result["checked"] += 1
                result["down_alerts"] += outcome["down_alert"]
                result["up_alerts"] += outcome["up_alert"]
                result["cert_alerts"] += outcome["cert_alert"]
            except Exception:
                db.rollback()
    prune(db, now)
    return result


def prune(db, now=None) -> int:
    """Uptime rows older than the keep period are removed (at most once an hour)."""
    if time.monotonic() - _last_prune["at"] < 3600:
        return 0
    _last_prune["at"] = time.monotonic()
    cutoff = (now or utc_now()) - timedelta(days=settings.uptime_keep_days)
    removed = db.execute(delete(UptimeCheck).where(UptimeCheck.checked_at < cutoff)).rowcount or 0
    db.commit()
    return removed
