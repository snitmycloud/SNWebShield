"""Landing page price safety: the built page is compared with plans.json (the only source of truth; checkout never reads the page)."""
import html
import json
import logging
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from app.cli.supervisor import SiteWatch
from app.main import app
from app.services import plans, site_check
from account_helpers import account_headers

FRONTEND = site_check.FRONTEND


def plans_file(tmp_path, pro=(550, 5500), business=(2999, 29990), currency="INR"):
    data = json.loads(plans.PLANS_FILE.read_text(encoding="utf-8"))
    data["currency"] = currency
    data["plans"]["pro"]["price"] = {"monthly": pro[0], "yearly": pro[1]}
    data["plans"]["business"]["price"] = {"monthly": business[0], "yearly": business[1]}
    path = tmp_path / "plans.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def page(tmp_path, pro=(550, 5500), business=(2999, 29990), currency="INR", tag=True):
    marker = {"currency": currency, "prices": {"free": [0, 0], "pro": list(pro), "business": list(business)}}
    meta = f'<meta name="snwebshield-prices" content="{html.escape(json.dumps(marker), quote=True)}">' if tag else ""
    path = tmp_path / "index.html"
    path.write_text(f"<!doctype html><html><head>{meta}</head><body>prices</body></html>", encoding="utf-8")
    return path


def test_matching_prices_are_ok(tmp_path):
    result = site_check.check(page(tmp_path), plans_file(tmp_path))
    assert result["status"] == "ok" and result["differences"] == []


def test_a_different_price_is_reported_with_both_values(tmp_path):
    result = site_check.check(page(tmp_path, pro=(500, 5000)), plans_file(tmp_path))
    assert result["status"] == "mismatch"
    assert {"plan": "pro", "field": "monthly", "page": 500, "plans_json": 550} in result["differences"]
    assert {"plan": "pro", "field": "yearly", "page": 5000, "plans_json": 5500} in result["differences"]
    assert "plans.json" in result["message"]


def test_a_currency_change_or_new_plan_is_a_mismatch(tmp_path):
    assert site_check.check(page(tmp_path, currency="USD"), plans_file(tmp_path))["status"] == "mismatch"
    data = json.loads(plans_file(tmp_path).read_text(encoding="utf-8"))
    data["plans"]["team"] = {**data["plans"]["pro"], "price": {"monthly": 1, "yearly": 10}}
    changed = tmp_path / "more.json"
    changed.write_text(json.dumps(data), encoding="utf-8")
    assert site_check.check(page(tmp_path), changed)["status"] == "mismatch"


def test_could_not_check_is_never_ok(tmp_path):
    assert site_check.check(tmp_path / "missing.html", plans_file(tmp_path))["status"] == "not_built"
    assert site_check.check(page(tmp_path, tag=False), plans_file(tmp_path))["status"] == "unreadable"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert site_check.check(page(tmp_path), bad)["status"] == "unreadable"
    (tmp_path / "broken.html").write_text('<meta name="snwebshield-prices" content="{oops">', encoding="utf-8")
    assert site_check.check(tmp_path / "broken.html", plans_file(tmp_path))["status"] == "unreadable"


def test_a_mismatch_is_logged_as_a_clear_error_and_ok_is_not(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="snwebshield.site_check"):
        site_check.log_result(site_check.check(page(tmp_path), plans_file(tmp_path)))
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
        site_check.log_result(site_check.check(page(tmp_path, pro=(1, 2)), plans_file(tmp_path)))
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1 and "LANDING PAGE PRICE CHECK" in errors[0] and "mismatch" in errors[0] and "plans_json" in errors[0]


def test_the_admin_page_endpoint_is_admin_only_and_reports_the_state(monkeypatch, tmp_path):
    monkeypatch.setattr(site_check, "LANDING", page(tmp_path, pro=(1, 2)))
    monkeypatch.setattr(site_check.check, "__defaults__", (site_check.LANDING, plans.PLANS_FILE))
    with TestClient(app) as client:
        _, _, user_headers = account_headers(client)
        assert client.get("/api/v1/admin/site-check", headers=user_headers).status_code == 403
        assert client.get("/api/v1/admin/site-check").status_code in (401, 403)
        _, _, admin_headers = account_headers(client, role="admin")
        body = client.get("/api/v1/admin/site-check", headers=admin_headers).json()
    assert body["status"] == "mismatch" and body["differences"]


def test_the_page_built_from_this_repo_shows_the_same_prices_as_plans_json(tmp_path):
    node = shutil.which("node")
    if not node or not (FRONTEND / "site" / "pages.js").exists():
        pytest.skip("node is not installed")
    script = ("import {buildSite} from './site/pages.js';import fs from 'node:fs';"
              "const plans=JSON.parse(fs.readFileSync('../backend/app/plans.json','utf8'));"
              "const f=buildSite({config:JSON.parse(fs.readFileSync('site/site.config.json','utf8')),plans,css:'',domain:'x.test'});"
              "process.stdout.write(f['index.html'])")
    out = subprocess.run([node, "--input-type=module", "-e", script], cwd=FRONTEND, capture_output=True, encoding="utf-8", timeout=60, check=True).stdout
    generated = tmp_path / "landing.html"
    generated.write_text(out, encoding="utf-8")
    assert site_check.check(generated)["status"] == "ok"


def test_the_built_dist_page_if_present_matches_plans_json():
    if not site_check.LANDING.exists():
        pytest.skip("the site has not been built here (npm run build)")
    result = site_check.check()
    assert result["status"] == "ok", result


# --- the supervisor keeps the page in step ---------------------------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def watch(statuses, rebuilt, clock, record=None, retry=600):
    results = iter(statuses)
    last = {"v": {"status": "ok", "differences": []}}

    def check():
        try:
            last["v"] = next(results)
        except StopIteration:
            pass
        return last["v"]

    def rebuild():
        rebuilt.append(clock.now)
        return True

    return SiteWatch(check=check, rebuild=rebuild, clock=clock, interval=30, retry=retry, threaded=False, record=record or (lambda *a: None))


MISMATCH = {"status": "mismatch", "differences": [{"plan": "pro"}], "message": "x"}
OK = {"status": "ok", "differences": []}


def test_the_supervisor_rebuilds_when_prices_differ_and_not_when_they_match():
    clock, rebuilt, events = Clock(), [], []
    w = watch([OK, MISMATCH, OK], rebuilt, clock, record=lambda action, detail: events.append(action))
    w.step()
    assert rebuilt == []
    clock.now += 31
    w.step()
    assert len(rebuilt) == 1 and events == ["site_rebuilt"]
    clock.now += 31
    w.step()
    assert len(rebuilt) == 1 and w.status == "ok"


def test_the_supervisor_checks_only_every_interval():
    clock, rebuilt = Clock(), []
    w = watch([MISMATCH] * 5, rebuilt, clock)
    w.step()
    clock.now += 5
    w.step()
    assert len(rebuilt) == 1   # the second step was inside the interval


def test_a_rebuild_that_keeps_failing_is_not_retried_in_a_loop(monkeypatch):
    clock, tries, events = Clock(), [], []

    def failing():
        tries.append(clock.now)
        return False

    w = SiteWatch(check=lambda: MISMATCH, rebuild=failing, clock=clock, interval=30, retry=600, threaded=False, record=lambda a, d: events.append(a))
    monkeypatch.setattr(SiteWatch, "_mtime", staticmethod(lambda: 1))
    for _ in range(10):
        clock.now += 31
        w.step()
    assert len(tries) == 1 and events == ["site_rebuild_failed"]
    clock.now += 700
    w.step()
    assert len(tries) == 2   # tried again after the retry time
    monkeypatch.setattr(SiteWatch, "_mtime", staticmethod(lambda: 2))   # plans.json was edited: try again at once
    clock.now += 31
    w.step()
    assert len(tries) == 3
