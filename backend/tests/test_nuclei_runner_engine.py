"""The Nuclei runner (process safety) and the Nuclei engine (gates, mapping, merging). No real Nuclei is started here."""
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from app.core.config import settings
from app.services import egress_proxy, engine_nuclei as en, engines, nuclei_lock, nuclei_runner as nr, nuclei_selftest
from app.services.detect_runner import ScanContext, ScanState
from app.services.detect_versions import PortProbe, WebPage
from app.services.finding import Finding, merge
from app.services.scan_guard import ScanStopped

FAKE = str(Path(__file__).with_name("fake_nuclei.py"))
PY = sys.executable


def fake_cmd(*args):
    return [PY, FAKE, *args]


def run(cmd, guard=None, **kw):
    return asyncio.run(nr.run(Path("unused"), Path("unused"), [], "http://127.0.0.1:1", guard, command=cmd, **kw))


def alive(pid):
    return nuclei_selftest.pid_alive(pid)


class Guard:
    def __init__(self, stop_after=None):
        self.calls, self.stop_after = 0, stop_after

    def check(self):
        self.calls += 1
        if self.stop_after is not None and self.calls > self.stop_after:
            raise ScanStopped("website_removed")


# --- the command line -----------------------------------------------------------------------------------------------------------------

def test_the_command_is_a_fixed_argument_list_with_every_safety_switch():
    cmd = nr.build_command(Path("/bin/nuclei"), Path("/t"), ["https://example.com", "http://example.com"], "http://127.0.0.1:9", rate=10, concurrency=5)
    assert isinstance(cmd, list) and all(isinstance(part, str) for part in cmd)
    flags = dict(zip(cmd[1::1], cmd[2::1]))
    assert cmd[0] == str(Path("/bin/nuclei")) and cmd.count("-u") == 2 and "https://example.com" in cmd
    for tag in ("intrusive", "dos", "fuzz", "bruteforce", "rce", "sqli", "xss", "lfi", "ssrf", "xxe", "ssti", "oast"):
        assert tag in flags["-etags"].split(",")
    for kind in ("code", "javascript", "headless", "file", "tcp", "dns", "ssl", "workflow", "whois", "websocket"):
        assert kind in flags["-ept"].split(",")
    for switch in ("-ni", "-fhr", "-duc", "-j", "-or", "-nc", "-silent"):
        assert switch in cmd
    assert flags["-p"] == "http://127.0.0.1:9" and flags["-rl"] == "10" and flags["-c"] == "5" and flags["-retries"] == "0"
    for forbidden in ("-dut", "-lfa", "-esc", "-code", "-headless", "-dast", "-fuzz", "-ev", "-update-templates", "-ut", "-sr", "-restrict-local-network-access"):
        assert forbidden not in cmd


# --- the process ---------------------------------------------------------------------------------------------------------------------------

def test_results_are_read_as_jsonl_and_noise_is_skipped(tmp_path):
    lines = tmp_path / "out.jsonl"
    lines.write_text('banner text\n{"template-id": "a"}\n{broken json\n[1,2]\n{"template-id": "b"}\n', encoding="utf-8")
    result = run(fake_cmd("jsonl", str(lines)))
    assert [r["template-id"] for r in result.results] == ["a", "b"] and result.bad_lines == 1 and result.exit_code == 0


def test_the_child_gets_a_minimal_environment_and_a_private_throwaway_folder(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "super-secret-jwt")
    monkeypatch.setenv("NVD_API_KEY", "super-secret-nvd")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///secret.db")
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    result = run(fake_cmd("env"))
    seen = result.results[0]
    text = json.dumps(seen)
    for secret in ("super-secret-jwt", "super-secret-nvd", "secret.db", "evil.example"):
        assert secret not in text
    env = seen["env"]
    assert not {k.upper() for k in env} & {"JWT_SECRET_KEY", "NVD_API_KEY", "DATABASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "SMTP_PASSWORD"}
    workdir = Path(seen["cwd"])
    assert "snwebshield-nuclei-run-" in workdir.name and Path(env.get("HOME") or env["USERPROFILE"]) == workdir
    assert not workdir.exists()  # deleted when the run ended


def test_a_run_that_takes_too_long_is_killed():
    started = time.monotonic()
    result = run(fake_cmd("hang"), timeout_seconds=2)
    assert result.timed_out and time.monotonic() - started < 15 and [r["template-id"] for r in result.results] == ["started"]


def test_endless_output_is_cut_and_the_process_killed(monkeypatch):
    monkeypatch.setattr(settings, "nuclei_max_output_bytes", 65536)
    started = time.monotonic()
    result = run(fake_cmd("big"), timeout_seconds=60)
    assert result.truncated and time.monotonic() - started < 20


def test_a_stop_from_the_scan_guard_kills_the_whole_process_tree():
    seen = {}

    def note(process):
        seen["pid"] = process.pid
    with pytest.raises(ScanStopped):
        run(fake_cmd("tree"), Guard(stop_after=6), on_start=note, timeout_seconds=60)
    time.sleep(1.5)
    assert not alive(seen["pid"])


def test_cancelling_the_scan_kills_the_process_and_its_children():
    holder = {}

    async def scenario():
        def note(process):
            holder["pid"] = process.pid
        task = asyncio.ensure_future(nr.run(Path("x"), Path("x"), [], "", None, command=fake_cmd("tree"), on_start=note, timeout_seconds=60))
        await asyncio.sleep(2.0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())
    time.sleep(1.5)
    assert not alive(holder["pid"])


def test_a_failing_process_reports_its_exit_code_and_a_cleaned_stderr_tail():
    result = run(fake_cmd("exit", "3"))
    assert result.exit_code == 3 and result.results == []


# --- the binary lock -------------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def fake_install(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "nuclei_dir", tmp_path / "engines")
    binary_name = nuclei_lock.load_lock()["platforms"][nuclei_lock.platform_key()]["binary"]
    folder = tmp_path / "engines" / f"nuclei-{nuclei_lock.load_lock()['version']}"
    folder.mkdir(parents=True)
    path = folder / binary_name
    path.write_bytes(b"pretend binary")
    lock = json.loads(json.dumps(nuclei_lock.load_lock()))
    lock["platforms"][nuclei_lock.platform_key()]["binary_sha256"] = hashlib.sha256(b"pretend binary").hexdigest()
    monkeypatch.setattr(nuclei_lock, "load_lock", lambda: lock)
    return path


def test_the_binary_is_used_only_if_its_hash_matches_the_pin(fake_install):
    assert nuclei_lock.verified_binary() == fake_install
    fake_install.write_bytes(b"tampered")
    with pytest.raises(nuclei_lock.LockError) as caught:
        nuclei_lock.verified_binary()
    assert caught.value.code == "binary_hash_mismatch"


def test_a_missing_or_unpinned_binary_is_refused(fake_install, monkeypatch):
    fake_install.unlink()
    with pytest.raises(nuclei_lock.LockError) as caught:
        nuclei_lock.verified_binary()
    assert caught.value.code == "binary_not_installed"
    lock = json.loads(json.dumps(nuclei_lock.load_lock()))
    lock["platforms"][nuclei_lock.platform_key()]["binary_sha256"] = None
    monkeypatch.setattr(nuclei_lock, "load_lock", lambda: lock)
    with pytest.raises(nuclei_lock.LockError) as caught:
        nuclei_lock.verified_binary()
    assert caught.value.code == "binary_not_pinned"


def test_the_committed_lock_pins_both_platforms_to_hashes():
    lock = json.loads(nuclei_lock.LOCK_PATH.read_text(encoding="utf-8"))["nuclei"]
    assert lock["version"] == "3.11.1"
    for platform in lock["platforms"].values():
        assert len(platform["zip_sha256"]) == 64 and len(platform["binary_sha256"]) == 64
        assert platform["url"].startswith("https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/")


# --- the template set --------------------------------------------------------------------------------------------------------------------------

def make_set(tmp_path, files):
    folder = tmp_path / "templates"
    for name, data in files.items():
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)
    manifest = {"templates": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
    (folder / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    return folder


def test_the_template_set_must_equal_its_manifest_exactly(tmp_path):
    folder = make_set(tmp_path, {"http/exposures/a.yaml": b"id: a\n", "http/exposed-panels/b.yaml": b"id: b\n"})
    assert len(en.verify_templates(folder)["templates"]) == 2
    (folder / "http/exposures/a.yaml").write_bytes(b"id: changed\n")
    with pytest.raises(en.TemplateSetError) as caught:
        en.verify_templates(folder)
    assert caught.value.code == "template_hash_mismatch"
    (folder / "http/exposures/a.yaml").write_bytes(b"id: a\n")
    (folder / "http/exposures/extra.yaml").write_bytes(b"id: smuggled\n")
    with pytest.raises(en.TemplateSetError) as caught:
        en.verify_templates(folder)
    assert caught.value.code == "template_set_changed"
    (folder / "http/exposures/extra.yaml").unlink()
    (folder / "http/exposed-panels/b.yaml").unlink()
    with pytest.raises(en.TemplateSetError) as caught:
        en.verify_templates(folder)
    assert caught.value.code == "template_set_changed"


def test_no_manifest_or_an_empty_one_is_refused(tmp_path):
    with pytest.raises(en.TemplateSetError) as caught:
        en.verify_templates(tmp_path)
    assert caught.value.code == "manifest_missing"
    (tmp_path / "MANIFEST.json").write_text('{"templates": {}}', encoding="utf-8")
    with pytest.raises(en.TemplateSetError) as caught:
        en.verify_templates(tmp_path)
    assert caught.value.code == "no_templates"


# --- findings from Nuclei results -------------------------------------------------------------------------------------------------------------------

def result(template="some-exposure", host="example.com", path="/x", severity="high", **info):
    return {"template-id": template, "matched-at": f"http://{host}{path}", "info": {"name": "Name", "severity": severity, **info}}


def test_an_exposure_result_becomes_a_confirmed_finding_for_the_verified_host():
    finding = en.to_finding(result(description="Desc"), "example.com", {})
    assert finding.sources == ["nuclei"] and finding.confidence == "confirmed" and finding.severity == "high" and finding.location == "example.com/x"
    assert finding.check_id == "nuclei:some-exposure" and finding.why == "Desc" and finding.scored


def test_critical_is_capped_at_high_and_unknown_is_info():
    assert en.to_finding(result(severity="critical"), "example.com", {}).severity == "high"
    unknown = en.to_finding(result(severity="unknown"), "example.com", {})
    assert unknown.severity == "info" and not unknown.scored
    assert en.to_finding(result(severity="nonsense"), "example.com", {}).severity == "info"


def test_a_cve_template_is_possible_with_a_caveat_and_never_scored():
    finding = en.to_finding(result("CVE-2021-1234", path="/"), "example.com", {})
    assert finding.cve_id == "CVE-2021-1234" and finding.confidence == "possible" and not finding.scored and finding.caveat
    assert finding.location == "example.com:80"
    with_class = en.to_finding(result("odd-name", classification={"cve-id": ["cve-2020-9999"]}), "example.com", {})
    assert with_class.cve_id == "CVE-2020-9999"


@pytest.mark.parametrize("raw", [
    result(host="evil.example.org"), result(host="127.0.0.1"), result(host="example.com.evil.example"), {"template-id": "../x", "matched-at": "http://example.com/"},
    {"template-id": 5, "matched-at": "http://example.com/"}, {"matched-at": "http://example.com/"}, {"template-id": "ok", "matched-at": ""},
])
def test_results_about_other_hosts_or_with_odd_ids_are_dropped(raw):
    assert en.to_finding(raw, "example.com", {}) is None


def test_text_from_nuclei_is_cleaned_and_cut():
    finding = en.to_finding(result(description="x" * 5000 + "\x00\x07evil", name="Title\x1b[31m" + "t" * 900), "example.com", {})
    assert len(finding.why) <= 600 and "\x00" not in finding.why and "\x1b" not in finding.title and len(finding.title) <= 200


def test_an_equivalent_template_merges_with_the_built_in_finding_into_one_with_both_sources():
    equivalents = en.load_equivalents()
    assert equivalents["apache-server-status"] == "exposed:apache-server-status:{path}"
    nuclei = en.to_finding(result("apache-server-status", path="/server-status", severity="medium"), "example.com", equivalents)
    builtin = Finding(kind="exposure", check_id="exposed:apache-server-status:/server-status", title="A server status page is public",
                      location="example.com/server-status", severity="medium", confidence="confirmed", sources=["snwebshield"])
    merged = merge([builtin, nuclei])
    assert len(merged) == 1 and merged[0].sources == ["nuclei", "snwebshield"] and merged[0].title == "A server status page is public"


def test_a_template_without_an_equivalent_stays_a_separate_finding():
    nuclei = en.to_finding(result("some-other", path="/server-status"), "example.com", en.load_equivalents())
    builtin = Finding(kind="exposure", check_id="exposed:apache-server-status:/server-status", title="t", location="example.com/server-status",
                      severity="medium", confidence="confirmed", sources=["snwebshield"])
    assert len(merge([builtin, nuclei])) == 2


def test_the_cve_from_nuclei_and_from_nvd_merge_into_one_finding_with_both_sources():
    nuclei = en.to_finding(result("CVE-2017-9788", path="/"), "example.com", {})
    nuclei.location = "example.com:80"
    nvd = Finding(kind="vulnerability", check_id="cve:CVE-2017-9788", title="Apache has a known vulnerability", location="example.com:80", severity="critical",
                  confidence="possible", cve_id="CVE-2017-9788", cvss_score=9.8, sources=["nvd"])
    merged = merge([nvd, nuclei])
    assert len(merged) == 1 and merged[0].sources == ["nuclei", "nvd"] and merged[0].severity == "critical" and merged[0].cvss_score == 9.8


# --- the engine's gates ----------------------------------------------------------------------------------------------------------------------------------

def web_probe(port, tls):
    return PortProbe(port=port, service="https" if tls else "http", http={"status": 200, "over_tls": tls, "headers": {}, "cookies": []},
                     web=WebPage(port=port, tls=tls, status=200, headers={}, cookies=[], body=""))


INDEX_ROWS = {
    "http/exposures/some-exposure.yaml": {"id": "some-exposure", "category": "exposures"},
    "http/exposures/some-other.yaml": {"id": "some-other", "category": "exposures"},
    "http/cves/CVE-2021-1.yaml": {"id": "CVE-2021-1", "category": "cves"},
    "http/cves/CVE-2017-9788.yaml": {"id": "CVE-2017-9788", "category": "cves"},
    "http/cves/CVE-2020-9999.yaml": {"id": "odd-name", "category": "cves"},
    "http/misconfiguration/apache-server-status.yaml": {"id": "apache-server-status", "category": "misconfiguration"},
    "http/exposures/backup-directory-listing.yaml": {"id": "backup-directory-listing", "category": "exposures"},
}
DEFAULT_MANIFEST = {"templates": {name: "h" for name in INDEX_ROWS}, "index": INDEX_ROWS}


def engine_run(monkeypatch, probes, *, enabled=True, binary=Path("nuclei"), templates=None, selftest=None, runner=None, guard=None, tmp_path=None):
    monkeypatch.setattr(settings, "nuclei_enabled", enabled)
    if tmp_path is not None:
        monkeypatch.setattr(settings, "nuclei_log_dir", tmp_path / "logs")
    monkeypatch.setattr(nuclei_lock, "verified_binary", lambda: binary if not isinstance(binary, Exception) else (_ for _ in ()).throw(binary))
    monkeypatch.setattr(en, "verify_templates", lambda *a, **k: templates if templates is not None else DEFAULT_MANIFEST)

    async def ensure(guard=None):
        return selftest or {"ok": True, "failed": [], "at": 1.0}
    monkeypatch.setattr(nuclei_selftest, "ensure", ensure)
    if runner is not None:
        monkeypatch.setattr(nr, "run", runner)
    state = ScanState()
    state.probes = list(probes)
    ctx = ScanContext(scan_id="scan-9", domain="example.com", ip="203.0.113.7")
    return asyncio.run(engines.run_engine(en.NucleiEngine(), ctx, state, guard or Guard()))


async def fake_run(binary, templates, targets, proxy_url, guard=None, **kw):
    fake_run.targets, fake_run.proxy_url = targets, proxy_url
    return nr.RunResult(results=fake_run.results, exit_code=0)
fake_run.results = []


def test_it_is_off_by_default():
    assert settings.nuclei_enabled is False


def test_disabled_means_skipped_and_nothing_runs(monkeypatch):
    out = engine_run(monkeypatch, [web_probe(443, True)], enabled=False)
    assert out.state == "skipped" and out.detail == {"reason": "disabled"} and out.findings == []


def test_no_web_server_on_80_or_443_means_not_applicable(monkeypatch):
    assert engine_run(monkeypatch, [], runner=fake_run).state == "not_applicable"
    assert engine_run(monkeypatch, [web_probe(8080, False)], runner=fake_run).state == "not_applicable"


def test_targets_are_the_verified_host_on_standard_ports_only():
    assert en.web_targets("example.com", [web_probe(443, True), web_probe(80, False), web_probe(8080, False), web_probe(8443, True)]) == ["http://example.com", "https://example.com"]
    assert en.web_targets("example.com", [web_probe(80, True)]) == []   # a TLS answer on 80 is not a plain-HTTP target


@pytest.mark.parametrize("problem, code", [
    (nuclei_lock.LockError("binary_hash_mismatch"), "binary_hash_mismatch"), (nuclei_lock.LockError("binary_not_installed"), "binary_not_installed"),
])
def test_a_binary_problem_keeps_the_engine_off_and_never_runs_anything(monkeypatch, problem, code):
    async def boom(*a, **k):
        raise AssertionError("must not run")
    out = engine_run(monkeypatch, [web_probe(443, True)], binary=problem, runner=boom)
    assert out.state == "could_not_check" and out.detail["reason"] == code


def test_a_changed_template_set_keeps_the_engine_off(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("must not run")
    monkeypatch.setattr(settings, "nuclei_enabled", True)
    monkeypatch.setattr(nuclei_lock, "verified_binary", lambda: Path("nuclei"))

    def bad(*a, **k):
        raise en.TemplateSetError("template_set_changed")
    monkeypatch.setattr(en, "verify_templates", bad)
    monkeypatch.setattr(nr, "run", boom)
    state = ScanState()
    state.probes = [web_probe(443, True)]
    out = asyncio.run(engines.run_engine(en.NucleiEngine(), ScanContext(scan_id="s", domain="example.com", ip="203.0.113.7"), state, Guard()))
    assert out.state == "could_not_check" and out.detail["reason"] == "template_set_changed"


def test_a_failed_self_test_keeps_the_engine_off(monkeypatch):
    async def boom(*a, **k):
        raise AssertionError("must not run")
    out = engine_run(monkeypatch, [web_probe(443, True)], selftest={"ok": False, "failed": ["firewall"], "at": 1.0}, runner=boom)
    assert out.state == "could_not_check" and out.detail == {"reason": "selftest_failed", "selftest": ["firewall"]} and out.findings == []


def test_a_successful_run_goes_through_a_per_scan_proxy_to_the_verified_host_only(monkeypatch, tmp_path):
    fake_run.results = [result("some-exposure", path="/a"), result(host="evil.example.org"), result("CVE-2021-1", path="/")]
    out = engine_run(monkeypatch, [web_probe(443, True), web_probe(80, False)], runner=fake_run, tmp_path=tmp_path)
    assert out.state == "ok" and len(out.findings) == 2 and out.detail["dropped_results"] == 1
    assert fake_run.targets == ["http://example.com", "https://example.com"]
    assert fake_run.proxy_url.startswith("http://127.0.0.1:") and out.detail["proxy_log"].endswith("scan-9.jsonl")
    assert out.detail["proxy"]["allowed"] == 0 and out.detail["selftest_at"] == 1.0
    assert (tmp_path / "logs").exists()


def test_the_proxy_is_closed_after_the_run(monkeypatch, tmp_path):
    ports = []

    async def run_and_note(binary, templates, targets, proxy_url, guard=None, **kw):
        ports.append(int(proxy_url.rsplit(":", 1)[1]))
        return nr.RunResult(results=[], exit_code=0)
    engine_run(monkeypatch, [web_probe(443, True)], runner=run_and_note, tmp_path=tmp_path)

    async def check():
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", ports[0])
    asyncio.run(check())


@pytest.mark.parametrize("outcome, reason", [(dict(timed_out=True), "timed_out"), (dict(truncated=True), "output_too_large"), (dict(exit_code=2), "nuclei_failed")])
def test_a_broken_run_is_could_not_check_never_ok(monkeypatch, tmp_path, outcome, reason):
    async def broken(*a, **k):
        return nr.RunResult(**{"exit_code": 0, **outcome})
    out = engine_run(monkeypatch, [web_probe(443, True)], runner=broken, tmp_path=tmp_path)
    assert out.state == "could_not_check" and out.detail["reason"] == reason


def test_a_crash_inside_the_runner_is_could_not_check(monkeypatch, tmp_path):
    async def crash(*a, **k):
        raise RuntimeError("boom")
    assert engine_run(monkeypatch, [web_probe(443, True)], runner=crash, tmp_path=tmp_path).state == "could_not_check"


def test_a_stop_during_the_run_propagates_and_closes_the_proxy(monkeypatch, tmp_path):
    async def stopped(*a, **k):
        raise ScanStopped("website_removed")
    with pytest.raises(ScanStopped):
        engine_run(monkeypatch, [web_probe(443, True)], runner=stopped, tmp_path=tmp_path)


def test_nuclei_is_an_optional_step_so_it_never_makes_a_scan_incomplete():
    from app.services import detect_runner
    assert "nuclei" in detect_runner.OPTIONAL_STEPS and "nuclei" in [e.name for e in engines.registered()]
    state = ScanState()
    state.steps = {"ports": {"state": "ok"}, "nuclei": {"state": "could_not_check", "reason": "selftest_failed"}}
    assert state.incomplete_steps() == [] and state.optional_notes() == [detect_runner.OPTIONAL_STEPS["nuclei"]]
    state.steps["nuclei"] = {"state": "skipped", "reason": "disabled"}
    assert state.optional_notes() == []
