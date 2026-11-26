"""The self-test's decisions (firewall reading, caching, early failure) and the pinned installer. No real Nuclei is started."""
import asyncio
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services import nuclei_lock, nuclei_selftest as st

BINARY = Path(r"C:\Users\someone\SNWebShield-Private\engines\nuclei-3.11.1\nuclei.exe")
RULE_OK = f"""
Rule Name:                            {st.RULE_NAME}
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
Edge traversal:                       No
Program:                              {BINARY}
Action:                               Block
Ok.
"""


def netsh(monkeypatch, text, platform="win32"):
    monkeypatch.setattr(st.sys, "platform", platform)
    monkeypatch.setattr(st.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=text, returncode=0))


def test_an_active_blocking_rule_for_this_exact_binary_passes(monkeypatch):
    netsh(monkeypatch, RULE_OK)
    assert st.firewall_rule_state(BINARY) == (True, "active")
    assert st.firewall_rule_state(Path(str(BINARY).upper())) == (True, "active")   # Windows paths are case-insensitive


@pytest.mark.parametrize("text, detail", [
    ("No rules match the specified criteria.\n", "rule_missing"),
    (RULE_OK.replace("Enabled:                              Yes", "Enabled:                              No"), "rule_present_but_not_blocking_this_binary"),
    (RULE_OK.replace("Action:                               Block", "Action:                               Allow"), "rule_present_but_not_blocking_this_binary"),
    (RULE_OK.replace("Direction:                            Out", "Direction:                            In"), "rule_present_but_not_blocking_this_binary"),
    (RULE_OK.replace(str(BINARY), r"C:\Other\program.exe"), "rule_present_but_not_blocking_this_binary"),
    ("", "rule_missing"),
])
def test_a_missing_disabled_wrong_or_allowing_rule_fails(monkeypatch, text, detail):
    netsh(monkeypatch, text)
    assert st.firewall_rule_state(BINARY) == (False, detail)


def test_an_unreadable_firewall_fails_closed(monkeypatch):
    monkeypatch.setattr(st.sys, "platform", "win32")

    def boom(*a, **k):
        raise OSError("no netsh")
    monkeypatch.setattr(st.subprocess, "run", boom)
    assert st.firewall_rule_state(BINARY) == (False, "firewall_unreadable")


def test_on_linux_the_marker_rule_is_required_and_its_absence_fails(monkeypatch):
    monkeypatch.setattr(st.shutil, "which", lambda name: "/usr/sbin/" + name)
    netsh(monkeypatch, "table inet filter { chain output { } }", platform="linux")
    assert st.firewall_rule_state(BINARY) == (False, "rule_missing")
    netsh(monkeypatch, f'table inet filter {{ chain output {{ meta skuid 998 oif != "lo" drop comment "{st.LINUX_MARKER}" }} }}', platform="linux")
    assert st.firewall_rule_state(BINARY) == (True, "active")


# --- caching ----------------------------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def counting(monkeypatch):
    st.reset()
    calls = []
    outcome = {"ok": True}

    async def fake_run_all(guard=None):
        calls.append(1)
        result = {"ok": outcome["ok"], "failed": [] if outcome["ok"] else ["firewall"], "checks": {}, "at": __import__("time").time()}
        st._cache.clear()
        st._cache.update(result)
        return result
    monkeypatch.setattr(st, "run_all", fake_run_all)
    monkeypatch.setattr(nuclei_lock, "binary_path", lambda *a: BINARY)
    state = {"rule": True}
    monkeypatch.setattr(st, "firewall_rule_state", lambda binary: (state["rule"], "x"))
    return calls, outcome, state


def test_a_pass_is_reused_while_recent_and_the_rule_is_still_there(counting):
    calls, _, _ = counting
    asyncio.run(st.ensure())
    asyncio.run(st.ensure())
    assert len(calls) == 1


def test_removing_the_firewall_rule_forces_a_new_test_at_once(counting):
    calls, outcome, state = counting
    asyncio.run(st.ensure())
    state["rule"] = False
    outcome["ok"] = False
    result = asyncio.run(st.ensure())
    assert len(calls) == 2 and result["ok"] is False


def test_a_failure_is_never_reused_as_a_pass(counting):
    calls, outcome, _ = counting
    outcome["ok"] = False
    assert asyncio.run(st.ensure())["ok"] is False
    outcome["ok"] = True
    assert asyncio.run(st.ensure())["ok"] is True and len(calls) == 2


def test_an_old_pass_expires(counting, monkeypatch):
    calls, _, _ = counting
    asyncio.run(st.ensure())
    st._cache["at"] -= (settings.nuclei_selftest_valid_minutes * 60) + 5
    asyncio.run(st.ensure())
    assert len(calls) == 2


def test_before_any_run_nothing_counts_as_passed():
    st.reset()
    assert st._cache["ok"] is False and st._cache["failed"] == ["not_run"]


def test_a_binary_problem_fails_the_self_test_before_anything_is_started(monkeypatch):
    def bad():
        raise nuclei_lock.LockError("binary_hash_mismatch")
    monkeypatch.setattr(nuclei_lock, "verified_binary", bad)
    result = asyncio.run(st.run_all())
    assert result["ok"] is False and result["failed"] == ["binary"] and result["checks"]["binary"]["detail"] == "binary_hash_mismatch"


def test_the_canaries_are_loopback_only_and_count_hits():
    async def scenario():
        canary = st.Canary()
        await canary.start()
        bound = canary._server.sockets[0].getsockname()[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", canary.port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        body = await reader.read(1000)
        writer.close()
        await canary.stop()
        return bound, canary.hits, body
    bound, hits, body = asyncio.run(scenario())
    assert bound == "127.0.0.1" and hits == 1 and b"SELFTEST-OK" in body


# --- the installer ----------------------------------------------------------------------------------------------------------------------------------

def load_installer():
    spec = importlib.util.spec_from_file_location("install_nuclei_tool", Path(__file__).resolve().parents[1] / "tools" / "install_nuclei.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installer(tmp_path, monkeypatch):
    tool = load_installer()
    name = nuclei_lock.load_lock()["platforms"][nuclei_lock.platform_key()]["binary"]
    archive = tmp_path / "good.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(name, b"the real binary")
        bundle.writestr("../escape.txt", b"zip slip")
        bundle.writestr("README.md", b"docs")
    lock = {"nuclei": {"version": "9.9.9", "platforms": {nuclei_lock.platform_key(): {
        "url": "https://github.com/projectdiscovery/nuclei/releases/download/v9.9.9/x.zip", "zip_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "binary": name, "binary_sha256": hashlib.sha256(b"the real binary").hexdigest()}}}}
    lock_file = tmp_path / "lock.json"
    lock_file.write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(nuclei_lock, "LOCK_PATH", lock_file)
    monkeypatch.setattr(settings, "nuclei_dir", tmp_path / "engines")
    monkeypatch.setattr(tool, "download", lambda url, target: target.write_bytes(archive.read_bytes()))
    monkeypatch.setattr(sys, "argv", ["install_nuclei.py"])
    return tool, archive, lock_file, lock, tmp_path, name


def test_a_verified_download_installs_only_the_one_expected_file(installer):
    tool, _, _, _, tmp_path, name = installer
    assert tool.main() == 0
    folder = tmp_path / "engines" / "nuclei-9.9.9"
    assert [p.name for p in folder.iterdir()] == [name] and (folder / name).read_bytes() == b"the real binary"
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path / "engines" / "escape.txt").exists()


def test_a_download_with_the_wrong_hash_is_refused_and_nothing_is_installed(installer, monkeypatch):
    tool, _, lock_file, lock, tmp_path, _ = installer
    lock["nuclei"]["platforms"][nuclei_lock.platform_key()]["zip_sha256"] = "0" * 64
    lock_file.write_text(json.dumps(lock), encoding="utf-8")
    assert tool.main() == 1
    assert not (tmp_path / "engines").exists()


def test_a_binary_that_differs_from_the_pinned_binary_hash_is_refused(installer):
    tool, _, lock_file, lock, tmp_path, _ = installer
    lock["nuclei"]["platforms"][nuclei_lock.platform_key()]["binary_sha256"] = "f" * 64
    lock_file.write_text(json.dumps(lock), encoding="utf-8")
    assert tool.main() == 1 and not (tmp_path / "engines").exists()


def test_an_archive_without_the_expected_binary_is_refused(installer, monkeypatch):
    tool, _, _, lock, tmp_path, _ = installer
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as bundle:
        bundle.writestr("something-else.exe", b"x")
    lock_file = nuclei_lock.LOCK_PATH
    lock["nuclei"]["platforms"][nuclei_lock.platform_key()]["zip_sha256"] = hashlib.sha256(other.read_bytes()).hexdigest()
    lock_file.write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(tool, "download", lambda url, target: target.write_bytes(other.read_bytes()))
    assert tool.main() == 1 and not (tmp_path / "engines").exists()


def test_the_installer_only_downloads_from_the_pinned_release_location():
    tool = load_installer()
    with pytest.raises(SystemExit):
        tool.download("https://evil.example.org/nuclei.zip", Path("x"))
    with pytest.raises(SystemExit):
        tool.download("https://github.com/someone-else/nuclei/releases/download/v1/x.zip", Path("x"))


def test_an_unpinned_binary_hash_needs_an_explicit_record_step(installer):
    tool, _, lock_file, lock, tmp_path, _ = installer
    lock["nuclei"]["platforms"][nuclei_lock.platform_key()]["binary_sha256"] = None
    lock_file.write_text(json.dumps(lock), encoding="utf-8")
    assert tool.main() == 1 and not (tmp_path / "engines").exists()
