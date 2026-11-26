"""The plan setting `pdf_report` (plans.json): true for every plan for now; the owner decides the limits in Phase 7."""
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import plans
from account_helpers import account_headers


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_every_plan_has_pdf_report_switched_on():
    data = plans.load()["plans"]
    assert set(data) == {"free", "pro", "business"}
    assert all(plan["pdf_report"] is True for plan in data.values())


@pytest.mark.parametrize("plan", ["free", "pro", "business"])
def test_my_plan_tells_the_app_whether_pdf_is_included(client, plan):
    _, _, headers = account_headers(client, plan=plan)
    body = client.get("/api/v1/auth/me/plan", headers=headers).json()
    assert body["pdf_report"] is True and body["name"] == plan


def test_changing_the_file_changes_the_answer_without_a_code_change(client, tmp_path, monkeypatch):
    data = json.loads(plans.PLANS_FILE.read_text(encoding="utf-8"))
    data["plans"]["free"]["pdf_report"] = False
    copy = tmp_path / "plans.json"
    copy.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(plans.load, "__defaults__", (copy,))      # load() reads its path from a default argument
    monkeypatch.setattr(plans, "_cache", {"mtime": None, "data": None})
    _, _, free = account_headers(client, plan="free")
    _, _, pro = account_headers(client, plan="pro")
    assert client.get("/api/v1/auth/me/plan", headers=free).json()["pdf_report"] is False
    assert client.get("/api/v1/auth/me/plan", headers=pro).json()["pdf_report"] is True
