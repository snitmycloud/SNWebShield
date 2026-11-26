"""Nuclei speed: QUICK and DEEP template sets, the loopback resolver (the measured cause of the slowness) and the run settings."""
import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.core.config import settings
from app.services import engine_nuclei as en, engines, nuclei_lock, nuclei_runner as nr, nuclei_selftest
from app.services.detect_runner import ScanContext, ScanState
from app.services.detect_versions import PortProbe, WebPage


def meta(category, id_, name="", severity="info", tags=(), vendor=None, product=None):
    return {"id": id_, "category": category, "name": name or id_, "severity": severity, "tags": list(tags), "vendor": vendor, "product": product}


INDEX = {
    "e1.yaml": meta("exposures", "env-exposure", severity="high"), "e2.yaml": meta("exposures", "git-config"),
    "m1.yaml": meta("misconfiguration", "server-status"), "m2.yaml": meta("misconfiguration", "cors-wildcard"),
    "p1.yaml": meta("exposed-panels", "jenkins-login", "Jenkins Login"), "p2.yaml": meta("exposed-panels", "wordpress-login", "WordPress Login"),
    "p3.yaml": meta("exposed-panels", "pfsense-login", "pfSense Login Panel"), "p4.yaml": meta("exposed-panels", "typo3-panel", "TYPO3 Login"),
    "t1.yaml": meta("technologies", "wp-detect", "WordPress Detection"),
    "c1.yaml": meta("cves", "CVE-2021-41773", severity="critical", tags=["cve", "apache", "lfi"], vendor="apache", product="http_server"),
    "c2.yaml": meta("cves", "CVE-2018-1312", severity="high", tags=["cve", "apache"], vendor="apache", product="http_server"),
    "c3.yaml": meta("cves", "CVE-2020-1938", severity="high", tags=["cve", "tomcat"], vendor="apache", product="tomcat"),
    "c4.yaml": meta("cves", "CVE-2019-0001", severity="low", tags=["cve", "wordpress", "wp-plugin"], vendor="wp", product="plugin"),
    "c5.yaml": meta("cves", "CVE-2022-9999", severity="medium", tags=["cve", "nginx"], vendor="f5", product="nginx"),
}
MANIFEST = {"templates": {k: "h" for k in INDEX}, "index": INDEX}


# --- QUICK ---------------------------------------------------------------------------------------------------------------------------------------

def quick(tokens=(), **kw):
    return en.select_templates(MANIFEST, "quick", set(tokens), **kw)


def test_quick_has_all_exposures_all_misconfigurations_and_only_the_sensitive_panels():
    chosen = quick()
    assert {"e1.yaml", "e2.yaml", "m1.yaml", "m2.yaml"} <= set(chosen)
    assert {"p1.yaml", "p3.yaml"} <= set(chosen)                         # Jenkins and pfSense are sensitive
    assert not {"p2.yaml", "p4.yaml"} & set(chosen)                      # ordinary login pages wait for the deep set
    assert "t1.yaml" not in chosen                                        # built-in technology detection covers this in a normal scan


def test_cve_templates_are_chosen_only_when_they_match_software_we_detected():
    assert not [p for p in quick() if p.startswith("c")]                  # nothing detected: no CVE templates
    assert [p for p in quick(["apache"]) if p.startswith("c")] == ["c1.yaml", "c2.yaml"]
    assert [p for p in quick(["nginx", "wordpress"]) if p.startswith("c")] == ["c4.yaml", "c5.yaml"]
    assert [p for p in quick(["tomcat"]) if p.startswith("c")] == ["c3.yaml"]
    assert [p for p in quick(["iis"]) if p.startswith("c")] == []


def test_the_cve_list_is_capped_and_highest_severity_comes_first():
    assert [p for p in quick(["apache"], max_cves=1) if p.startswith("c")] == ["c1.yaml"]     # the critical one survives the cap
    assert [p for p in quick(["apache"], max_cves=0) if p.startswith("c")] == []
    assert settings.nuclei_max_quick_cves == 300


def test_deep_is_every_vendored_template_whatever_was_detected():
    assert en.select_templates(MANIFEST, "deep", set()) == sorted(INDEX)


def test_the_real_vendored_quick_set_is_small_enough_to_finish_in_time():
    manifest = en.verify_templates()
    plain = en.select_templates(manifest, "quick", set())
    assert len(plain) == 1426 and len(en.select_templates(manifest, "deep", set())) == 3948
    busy = en.select_templates(manifest, "quick", {"apache", "nginx", "php", "wordpress", "jquery", "openssh", "mysql"})
    assert len(plain) < len(busy) <= 1426 + settings.nuclei_max_quick_cves
    categories = {manifest["index"][p]["category"] for p in plain}
    assert categories == {"exposures", "misconfiguration", "exposed-panels"}


def test_detected_software_becomes_matching_words():
    technologies = [{"name": "Apache HTTP Server"}, {"name": "WordPress"}, {"name": "jQuery"}, {"name": "PHP"}]
    probes = [PortProbe(port=22, product="OpenSSH"), PortProbe(port=80, product="nginx"), PortProbe(port=3306, product=None)]
    tokens = en.detected_tokens(technologies, probes)
    assert {"apache", "wordpress", "jquery", "openssh", "nginx"} <= tokens
    assert not {"http", "server", "php"} & tokens                         # too generic to pick templates by
    assert en.detected_tokens([], []) == set()


# --- the run ---------------------------------------------------------------------------------------------------------------------------------------

def test_the_command_names_a_loopback_only_resolver_with_the_system_fallback_and_a_5_second_request_timeout(tmp_path):
    resolvers = tmp_path / "resolvers.txt"
    cmd = nr.build_command(Path("nuclei"), Path("t"), ["http://example.com"], "http://127.0.0.1:9", rate=25, concurrency=10, resolvers=resolvers)
    flags = dict(zip(cmd[1:], cmd[2:]))
    assert flags["-r"] == str(resolvers) and "-sr" in cmd and flags["-timeout"] == "5" and flags["-retries"] == "0"
    assert "-r" not in nr.build_command(Path("nuclei"), Path("t"), [], "http://127.0.0.1:9", rate=1, concurrency=1)


def test_the_resolver_file_names_only_the_loopback_address_and_a_subset_becomes_a_list_file(tmp_path):
    resolvers, argument = nr.prepare_files(tmp_path, [tmp_path / "a" / "one.yaml", tmp_path / "b" / "two.yaml"])
    assert resolvers.read_text(encoding="utf-8").split() == ["127.0.0.1"]
    assert argument == tmp_path / "templates.txt"
    assert argument.read_text(encoding="utf-8").splitlines() == [str(tmp_path / "a" / "one.yaml"), str(tmp_path / "b" / "two.yaml")]
    resolvers2, same = nr.prepare_files(tmp_path, tmp_path / "folder")
    assert same == tmp_path / "folder"                                   # a folder is passed through unchanged


def test_the_run_limits():
    assert settings.nuclei_run_seconds == 100 and settings.nuclei_deep_run_seconds == 600 and settings.nuclei_rate_limit == 25
    assert settings.nuclei_enabled is False


# --- the engine uses the selection ------------------------------------------------------------------------------------------------------------------

class Guard:
    def check(self):
        pass


def web_probe(port=80, product=None):
    probe = PortProbe(port=port, service="http", product=product, http={"status": 200, "over_tls": False, "headers": {}, "cookies": []},
                      web=WebPage(port=port, tls=False, status=200, headers={}, cookies=[], body=""))
    return probe


def run_engine(monkeypatch, tmp_path, *, scan_type="standard", probes=None, technologies=()):
    calls = {}

    async def fake_run(binary, templates, targets, proxy_url, guard=None, **kw):
        calls.update(templates=list(templates), timeout=kw.get("timeout_seconds"), targets=targets)
        return nr.RunResult(results=[], exit_code=0)

    async def passed(guard=None):
        return {"ok": True, "failed": [], "at": 1.0}
    monkeypatch.setattr(settings, "nuclei_enabled", True)
    monkeypatch.setattr(settings, "nuclei_log_dir", tmp_path / "logs")
    monkeypatch.setattr(nuclei_lock, "verified_binary", lambda: Path("nuclei"))
    monkeypatch.setattr(en, "verify_templates", lambda *a, **k: MANIFEST)
    monkeypatch.setattr(nuclei_selftest, "ensure", passed)
    monkeypatch.setattr(nr, "run", fake_run)
    state = ScanState()
    state.probes = probes if probes is not None else [web_probe(product="Apache")]
    state.technologies = list(technologies)
    ctx = ScanContext(scan_id="scan-q", domain="example.com", ip="203.0.113.7", scan_type=scan_type)
    return asyncio.run(engines.run_engine(en.NucleiEngine(), ctx, state, Guard())), calls


def test_a_normal_scan_runs_the_quick_set_with_the_quick_time_limit(monkeypatch, tmp_path):
    result, calls = run_engine(monkeypatch, tmp_path)
    names = sorted(p.name for p in calls["templates"])
    assert result.state == "ok" and result.detail["mode"] == "quick" and calls["timeout"] == settings.nuclei_run_seconds
    assert names == sorted(["e1.yaml", "e2.yaml", "m1.yaml", "m2.yaml", "p1.yaml", "p3.yaml", "c1.yaml", "c2.yaml"])   # Apache was detected
    assert all(p.parent == en.TEMPLATES_DIR for p in calls["templates"])                     # only vendored files
    assert result.detail["templates"] == 8 and result.detail["templates_available"] == len(INDEX) and "requests" in result.detail and "seconds" in result.detail


def test_a_deep_scan_runs_every_template_with_the_deep_time_limit(monkeypatch, tmp_path):
    result, calls = run_engine(monkeypatch, tmp_path, scan_type="deep")
    assert result.detail["mode"] == "deep" and calls["timeout"] == settings.nuclei_deep_run_seconds
    assert sorted(p.name for p in calls["templates"]) == sorted(INDEX)


def test_nothing_to_run_is_ok_not_a_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(en, "select_templates", lambda *a, **k: [])
    result, calls = run_engine(monkeypatch, tmp_path)
    assert result.state == "ok" and result.detail["templates"] == 0 and calls == {}


# --- the vendored set is complete in git (4 templates under "backups/" were once ignored by .gitignore) -----------------------------------------------

@pytest.mark.skipif(shutil.which("git") is None, reason="git is not available")
def test_every_vendored_template_is_tracked_by_git_not_ignored():
    repo = Path(__file__).resolve().parents[2]
    folder = "backend/app/data/nuclei/templates"
    tracked = subprocess.run(["git", "ls-files", folder], cwd=repo, capture_output=True, text=True, check=True).stdout.split()
    if not tracked:
        pytest.skip("not inside a git checkout")
    manifest = json.loads((en.TEMPLATES_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    expected = {f"{folder}/{name}" for name in manifest["templates"]} | {f"{folder}/MANIFEST.json", f"{folder}/LICENSE.md"}
    ignored = subprocess.run(["git", "check-ignore", "--stdin"], cwd=repo, input="\n".join(sorted(expected)), capture_output=True, text=True).stdout.split()
    assert ignored == []
    missing = expected - set(tracked)
    # Files added in this working tree but not yet committed are fine; ignored ones are not (checked above).
    status = subprocess.run(["git", "status", "--porcelain", folder], cwd=repo, capture_output=True, text=True).stdout
    assert not missing or all(path.split("/", 3)[-1] in status.replace("\\", "/") or f"{folder}" in status for path in list(missing)[:5])
