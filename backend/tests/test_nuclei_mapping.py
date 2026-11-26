"""How Nuclei results are mapped: technologies go to the Technologies list (never findings); login/admin pages are grouped into
ONE Info finding per website, with Medium only for sensitive panels (an editable list)."""
import json
from pathlib import Path

import pytest

from app.services import detect_tech, engine_nuclei as en, sensitive_panels as sp

DOMAIN = "example.com"


def idx(*rows):
    return {rid: {"id": rid, "category": category} for rid, category in rows}


def tech(template, name, version=None, host=DOMAIN, path="/"):
    raw = {"template-id": template, "matched-at": f"http://{host}{path}", "info": {"name": name, "severity": "info"}}
    if version is not None:
        raw["extracted-results"] = version if isinstance(version, list) else [version]
    return raw


def panel(template, name, path="/login", host=DOMAIN):
    return {"template-id": template, "matched-at": f"http://{host}{path}", "info": {"name": name, "severity": "info"}}


def process(results, index, existing=()):
    return en.process_results(results, DOMAIN, index, {}, list(existing))


# --- technologies: Technologies list only, merged with the built-in detection ----------------------------------------------------------

def test_technology_templates_never_create_findings():
    index = idx(("wp-detect", "technologies"), ("nginx-detect", "technologies"))
    out = process([tech("wp-detect", "WordPress Version Detection", "6.4.2"), tech("nginx-detect", "nginx Detection")], index)
    assert out["findings"] == [] and len(out["technologies"]) == 2 and out["panels"] == 0


def test_a_technology_row_has_name_version_and_source_nuclei():
    out = process([tech("wp-detect", "WordPress Version Detection", "6.4.2")], idx(("wp-detect", "technologies")))
    [row] = out["technologies"]
    assert row["name"] == "WordPress" and row["version"] == "6.4.2" and row["source"] == "nuclei" and row["port"] == 80
    assert row["evidence"] == "Nuclei check wp-detect" and set(row) == {"name", "category", "version", "source", "evidence", "port"}


@pytest.mark.parametrize("name, expected", [
    ("WordPress Detection", "WordPress"), ("Apache Tomcat Version Detection", "Apache Tomcat"), ("Nginx Detect", "Nginx"),
    ("Drupal Fingerprint", "Drupal"), ("jQuery Technology Detection", "jQuery"), ("Plain Name", "Plain Name"),
])
def test_technology_names_are_cleaned(name, expected):
    assert en.technology_name(name) == expected


@pytest.mark.parametrize("extracted, expected", [(["6.4.2"], "6.4.2"), (["v1.18.0"], "1.18.0"), (["not a version", "2.4.7"], "2.4.7"), ([], None),
                                                   (["<script>alert(1)</script>"], None), ("6.4.2", None), (["x" * 200], None)])
def test_the_version_is_taken_only_if_it_looks_like_one(extracted, expected):
    raw = tech("t", "Thing Detection")
    raw["extracted-results"] = extracted
    assert en.to_technology(raw, DOMAIN, {})["version"] == expected


def test_a_nuclei_technology_merges_into_the_built_in_list_one_row_best_version_wins():
    builtin = [{"name": "WordPress", "category": "cms", "version": None, "source": "meta", "evidence": "generator", "port": 80},
               {"name": "jQuery", "category": "js", "version": "3.6.0", "source": "script", "evidence": "x", "port": 80}]
    out = process([tech("wp", "wordpress version detection", "6.4.2"), tech("jq", "jQuery Detection", "9.9.9"), tech("new", "Brand New Tech Detection")],
                  idx(("wp", "technologies"), ("jq", "technologies"), ("new", "technologies")), builtin)
    merged = {t["name"]: t for t in detect_tech.merge(builtin, out["technologies"])}
    assert set(merged) == {"WordPress", "jQuery", "Brand New Tech"}                       # the built-in spelling is reused: no duplicates
    assert merged["WordPress"]["version"] == "6.4.2" and merged["WordPress"]["source"] == "nuclei"   # the built-in row had no version
    assert merged["jQuery"]["version"] == "3.6.0" and merged["jQuery"]["source"] == "script"          # the built-in version is kept
    assert merged["Brand New Tech"]["source"] == "nuclei" and merged["Brand New Tech"]["version"] is None


def test_technology_results_about_another_host_or_with_a_bad_id_are_dropped():
    index = idx(("t", "technologies"))
    assert process([tech("t", "X Detection", host="evil.example.org")], index)["technologies"] == []
    assert process([tech("t", "X Detection", host="127.0.0.1")], index)["dropped"] == 1
    assert process([tech("not-in-the-vendored-set", "X Detection")], index)["dropped"] == 1


# --- exposed panels: ONE Info finding, Medium only for sensitive ones --------------------------------------------------------------------------

ORDINARY = [("wordpress-login", "WordPress Login", "/wp-login.php"), ("joomla-panel", "Joomla Admin", "/administrator/"),
            ("typo3-login", "TYPO3 Login", "/typo3/"), ("custom-admin", "Admin Login", "/admin/")]


def ordinary_index():
    return idx(*[(i, "exposed-panels") for i, _, _ in ORDINARY])


def test_four_ordinary_panels_become_one_info_finding_with_the_list_inside():
    out = process([panel(i, n, p) for i, n, p in ORDINARY], ordinary_index())
    [finding] = out["findings"]
    assert finding.title == "Login or admin pages found: 4" and finding.severity == "info" and finding.location == DOMAIN
    assert not finding.scored and finding.confidence == "confirmed" and finding.sources == ["nuclei"] and finding.check_id == "nuclei-panels"
    assert [p["path"] for p in finding.details["panels"]] == ["/wp-login.php", "/administrator/", "/typo3/", "/admin/"]
    assert finding.details["panels"][0] == {"name": "WordPress Login", "path": "/wp-login.php", "template": "wordpress-login"}
    assert "WordPress Login (/wp-login.php)" in finding.evidence and out["panels"] == 4 and out["sensitive_panels"] == 0


def test_no_panels_means_no_panel_finding():
    assert process([], ordinary_index())["findings"] == []


def test_one_panel_is_still_one_info_finding():
    [finding] = process([panel("wordpress-login", "WordPress Login", "/wp-login.php")], ordinary_index())["findings"]
    assert finding.title == "Login or admin pages found: 1"


@pytest.mark.parametrize("template, name", [
    ("phpmyadmin-panel", "phpMyAdmin Panel"), ("adminer-panel", "Adminer Login"), ("pgadmin-exposure", "pgAdmin"), ("redis-commander-exposure", "Redis Commander"),
    ("jenkins-login", "Jenkins Login"), ("grafana-detect", "Grafana Panel"), ("kibana-panel", "Kibana Panel"), ("elasticsearch-head-plugin", "Elasticsearch Head"),
    ("docker-registry", "Docker Registry"), ("portainer-panel", "Portainer"), ("kubernetes-dashboard", "Kubernetes Dashboard"), ("kubelet-exposure", "Kubelet"),
    ("pfsense-login", "pfSense Login"), ("fortinet-fortigate-panel", "FortiGate Panel"), ("cisco-asa-panel", "Cisco ASA"), ("mikrotik-routeros", "RouterOS"),
    ("unknown-thing", "Some Wireless Router Admin"), ("cpanel-login-detect", "cPanel"), ("webmin-panel", "Webmin"), ("rabbitmq-dashboard", "RabbitMQ Management"),
])
def test_sensitive_panels_are_medium_and_reported_on_their_own(template, name):
    out = process([panel(template, name, "/x/")], idx((template, "exposed-panels")))
    [finding] = out["findings"]
    assert finding.severity == "medium" and finding.scored and finding.confidence == "confirmed" and finding.check_id == f"nuclei-panel:{template}"
    assert finding.location == f"{DOMAIN}/x/" and finding.details["sensitive"] and out["sensitive_panels"] == 1
    assert "reachable from the internet" in finding.title


def test_ordinary_and_sensitive_panels_together_one_info_plus_one_medium_each():
    results = [panel(i, n, p) for i, n, p in ORDINARY[:3]] + [panel("phpmyadmin-panel", "phpMyAdmin", "/phpmyadmin/"), panel("jenkins-login", "Jenkins", "/jenkins/")]
    index = idx(*[(i, "exposed-panels") for i, _, _ in ORDINARY[:3]], ("phpmyadmin-panel", "exposed-panels"), ("jenkins-login", "exposed-panels"))
    out = process(results, index)
    by_id = {f.check_id: f for f in out["findings"]}
    assert set(by_id) == {"nuclei-panels", "nuclei-panel:phpmyadmin-panel", "nuclei-panel:jenkins-login"}
    assert by_id["nuclei-panels"].title == "Login or admin pages found: 3" and by_id["nuclei-panels"].details["sensitive_reported_separately"] == 2
    assert [f.severity for f in out["findings"] if f.check_id != "nuclei-panels"] == ["medium", "medium"]
    assert len(by_id["nuclei-panels"].details["panels"]) == 3     # the sensitive ones are not repeated inside the Info list


def test_only_sensitive_panels_means_no_info_group():
    out = process([panel("jenkins-login", "Jenkins", "/")], idx(("jenkins-login", "exposed-panels")))
    assert [f.check_id for f in out["findings"]] == ["nuclei-panel:jenkins-login"]


def test_the_same_panel_twice_is_listed_once_and_foreign_hosts_are_dropped():
    index = ordinary_index()
    out = process([panel("custom-admin", "Admin Login", "/admin/"), panel("custom-admin", "Admin Login", "/admin/"),
                   panel("custom-admin", "Admin Login", "/admin/", host="evil.example.org")], index)
    assert out["panels"] == 1 and out["dropped"] == 1 and out["findings"][0].title == "Login or admin pages found: 1"


def test_the_panel_list_is_capped_but_the_count_is_true():
    rows = [(f"panel-{i}", "exposed-panels") for i in range(130)]
    out = process([panel(f"panel-{i}", f"Panel {i}", f"/p{i}") for i in range(130)], idx(*rows))
    [finding] = out["findings"]
    assert finding.title == "Login or admin pages found: 130" and len(finding.details["panels"]) == en.MAX_PANELS


def test_text_from_a_panel_is_cleaned():
    out = process([panel("custom-admin", "Admin\x00 Login\x1b[31m" + "x" * 500, "/a\x00b")], ordinary_index())
    [item] = out["findings"][0].details["panels"]
    assert "\x00" not in item["name"] and "\x1b" not in item["name"] and len(item["name"]) <= 120 and "\x00" not in item["path"]


# --- the editable sensitive list ----------------------------------------------------------------------------------------------------------------------

def test_the_committed_list_covers_everything_the_owner_named():
    rules = dict(en.load_sensitive())
    flat = " ".join(m for needles in rules.values() for m in needles)
    for needed in ("phpmyadmin", "adminer", "jenkins", "grafana", "kibana", "elasticsearch", "docker", "kubernetes", "router", "firewall", "pfsense", "fortigate", "cpanel"):
        assert needed in flat, needed


def test_the_list_is_editable_without_a_code_change(tmp_path, monkeypatch):
    custom = tmp_path / "sensitive.json"
    custom.write_text(json.dumps({"sensitive": [{"label": "My own rule", "match": ["wordpress-login"]}]}), encoding="utf-8")
    monkeypatch.setattr(sp, "SENSITIVE_PATH", custom)
    out = process([panel("wordpress-login", "WordPress Login", "/wp-login.php")], ordinary_index())
    assert [f.severity for f in out["findings"]] == ["medium"] and out["findings"][0].details["sensitive"] == "My own rule"
    custom.write_text(json.dumps({"sensitive": []}), encoding="utf-8")
    assert process([panel("jenkins-login", "Jenkins", "/")], idx(("jenkins-login", "exposed-panels")))["findings"][0].severity == "info"


@pytest.mark.parametrize("content", ["not json", "[]", '{"sensitive": [{"label": "x"}]}', '{"sensitive": "no"}', ""])
def test_a_broken_list_means_nothing_is_sensitive_and_nothing_crashes(tmp_path, monkeypatch, content):
    broken = tmp_path / "sensitive.json"
    broken.write_text(content, encoding="utf-8")
    monkeypatch.setattr(sp, "SENSITIVE_PATH", broken)
    assert en.load_sensitive() == []
    assert process([panel("jenkins-login", "Jenkins", "/")], idx(("jenkins-login", "exposed-panels")))["findings"][0].severity == "info"


def test_a_missing_list_file_is_harmless(tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "SENSITIVE_PATH", tmp_path / "missing.json")
    assert en.load_sensitive() == []


# --- other categories still become ordinary findings ------------------------------------------------------------------------------------------------

def test_exposures_misconfigurations_and_cves_are_ordinary_findings():
    index = idx(("exposed-thing", "exposures"), ("bad-config", "misconfiguration"), ("CVE-2021-1", "cves"))
    results = [panel("exposed-thing", "Exposed thing", "/x"), panel("bad-config", "Bad config", "/y"), panel("CVE-2021-1", "A CVE", "/")]
    out = process(results, index)
    assert sorted(f.check_id for f in out["findings"]) == ["nuclei:CVE-2021-1", "nuclei:bad-config", "nuclei:exposed-thing"] and out["technologies"] == []


def test_a_result_for_a_template_outside_the_vendored_set_is_ignored():
    out = process([panel("surprise", "Surprise", "/")], idx(("something-else", "exposures")))
    assert out["findings"] == [] and out["dropped"] == 1


def test_the_vendored_set_has_the_expected_shape():
    manifest = en.verify_templates()
    assert len(manifest["templates"]) == 3948 and manifest["commit"].startswith("5442582a") and manifest["licence"] == "MIT"
    counts = {}
    for meta in manifest["index"].values():
        counts[meta["category"]] = counts.get(meta["category"], 0) + 1
    assert counts == {"exposures": 466, "exposed-panels": 1545, "misconfiguration": 814, "technologies": 839, "cves": 284}
    assert (en.TEMPLATES_DIR / "LICENSE.md").read_text(encoding="utf-8").startswith("MIT License")


def test_every_vendored_template_still_passes_the_validator_and_matches_its_manifest():
    from app.services import nuclei_templates as nt
    manifest = en.verify_templates()
    root = en.TEMPLATES_DIR
    failed = [(name, v.reasons) for name in manifest["templates"] if not (v := nt.validate_file(root / name, root)).ok]
    assert failed == []


def test_login_pages_are_not_in_the_equivalents_map_because_they_are_grouped():
    assert "wordpress-login" not in en.load_equivalents()
    assert set(en.load_equivalents()) == {"apache-server-status", "ds-store-file", "backup-directory-listing"}


# --- the trimmed network-device group -------------------------------------------------------------------------------------------------------------------------

def label_of(template_id):
    meta = next(v for v in en.verify_templates()["index"].values() if v["id"] == template_id)
    return sp.sensitive_label(meta["id"], meta["name"] or "")


@pytest.mark.parametrize("template", ["pfsense-login", "opnsense-panel", "fortinet-fortigate-panel", "fortinet-fortios-management-panel", "sonicwall-management-panel",
                                      "sophos-fw-version-detect", "sophos-utm-panel", "mikrotik-routeros", "cisco-asa-panel", "cisco-firepower-panel",
                                      "ubiquiti-edgerouter-panel", "unifi-panel", "juniper-panel", "watchguard-panel", "zyxel-firewall-panel", "asus-router-panel"])
def test_real_network_device_admin_pages_are_sensitive(template):
    assert label_of(template) == "Router, firewall or network device admin"


@pytest.mark.parametrize("template", ["cisco-webex-meetings-panel", "cisco-cm-panel", "cisco-finesse-login", "cisco-unity-panel", "cisco-esa-panel", "cisco-expressway-panel",
                                      "cisco-telepresence-mcu-panel", "fortimail-login", "sophos-mobile-panel", "barracuda-message-panel", "mitel-nupoint-panel",
                                      "paloalto-expedition-panel"])
def test_meeting_collaboration_email_and_voice_apps_are_not_sensitive_and_go_in_the_info_group(template):
    assert label_of(template) is None
    out = process([panel(template, "Some App", "/")], idx((template, "exposed-panels")))
    assert [f.severity for f in out["findings"]] == ["info"] and out["findings"][0].check_id == "nuclei-panels"


def test_unified_is_not_mistaken_for_unifi():
    assert sp.sensitive_label("cisco-unified-thing", "Cisco Unified CM Console") is None
    assert sp.sensitive_label("unifi-panel", "UniFi Network Login Panel") == "Router, firewall or network device admin"


def test_the_trimmed_counts_for_the_vendored_panel_templates():
    from collections import Counter
    rules = sp.load_sensitive()
    counts = Counter(sp.sensitive_label(v["id"], v["name"] or "", rules) or "ordinary" for v in en.verify_templates()["index"].values() if v["category"] == "exposed-panels")
    assert counts["Router, firewall or network device admin"] == 70 and sum(n for k, n in counts.items() if k != "ordinary") == 146 and counts["ordinary"] == 1399


def test_a_nuclei_sensitive_panel_and_the_built_in_login_check_merge_when_they_find_the_same_page():
    from app.services.finding import merge
    from app.services import engine_config as ec
    nuclei = process([panel("jenkins-login", "Jenkins Login", "/jenkins/")], idx(("jenkins-login", "exposed-panels")))["findings"][0]
    assert nuclei.details["equivalent_to"] == "exposed:login-form:/jenkins/"
    builtin = ec.exposed_findings(DOMAIN, [{"key": "/jenkins/", "status": "exposed", "data": {"kind": "admin_login", "signature": "login-form", "http_status": 200}}])[0]
    builtin.location = nuclei.location        # both say "example.com/jenkins/"
    merged = merge([builtin, nuclei])
    assert len(merged) == 1 and merged[0].sources == ["nuclei", "snwebshield"]
