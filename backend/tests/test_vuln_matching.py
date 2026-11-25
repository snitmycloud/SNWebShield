"""NVD / OSV normalization, version matching, and the confirmed-vs-possible rules (false-positive control). No network."""
import pytest

from app.services import engine_vulns as ev, identify_items
from app.services.detect_versions import PortProbe, WebPage

VECTOR_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def nvd_vuln(cve="CVE-2020-0001", status="Analyzed", vector=VECTOR_98, score=9.8, desc="A flaw.", ranges=None, operator="OR",
             vendor="openbsd", product="openssh", tags=None, extra_nodes=0):
    match = [{"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*", **(r)} for r in (ranges or [{"versionEndExcluding": "7.0"}])]
    nodes = [{"operator": "OR", "cpeMatch": match}] + [{"operator": "OR", "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:lts:*:*:*"}]}] * extra_nodes
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": score, "vectorString": vector}}]} if score is not None else {}
    return {"cve": {"id": cve, "vulnStatus": status, "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics,
                    "configurations": [{"operator": operator, "nodes": nodes}], "cveTags": tags or []}}


def nvd(*vulns, total=None):
    return {"totalResults": total if total is not None else len(vulns), "vulnerabilities": list(vulns)}


def item(version="6.6.1p1", key="openssh", ecosystem="cpe", family=None, proxy=False, port=22, text=""):
    found = identify_items.Item(ecosystem, key, ev.identify_items._MAP["products" if ecosystem == "cpe" else "npm"][key]["label"],
                                version, port, f"example.com:{port}", context_text=text)
    found.family, found.proxy = family, proxy
    return found


def finding_for(version, vuln, **kw):
    advisory = ev.normalize_nvd(nvd(vuln), "openbsd", "openssh")["advisories"][0]
    return ev.advisory_finding(item(version, **kw), advisory)


# --- NVD normalization ----------------------------------------------------------------------------------------------

def test_nvd_normalizes_score_ranges_and_description():
    result = ev.normalize_nvd(nvd(nvd_vuln()), "openbsd", "openssh")
    advisory = result["advisories"][0]
    assert advisory["id"] == "CVE-2020-0001" and advisory["score"] == 9.8 and advisory["vector"] == VECTOR_98
    assert advisory["ranges"] == [{"start_including": None, "start_excluding": None, "end_including": None, "end_excluding": "7.0"}]
    assert not advisory["disputed"] and not advisory["and_config"] and result["truncated"] is False


def test_rejected_and_junk_entries_are_skipped_and_never_crash():
    result = ev.normalize_nvd(nvd(nvd_vuln(status="Rejected"), nvd_vuln(desc="** REJECT ** do not use"),
                                  {"cve": {"id": "not-a-cve"}}, "garbage", {"nothing": 1}), "openbsd", "openssh")
    assert result["advisories"] == []


def test_a_malformed_answer_is_an_error_not_an_empty_list():
    for bad in ({}, {"vulnerabilities": "x"}, [], None):
        with pytest.raises(ev.vuln_sources.SourceError):
            ev.normalize_nvd(bad, "openbsd", "openssh")


def test_truncation_is_flagged_so_it_is_never_used_to_say_none():
    assert ev.normalize_nvd(nvd(nvd_vuln(), total=5000), "openbsd", "openssh")["truncated"] is True


def test_exact_versions_with_an_update_field_are_joined():
    vuln = nvd_vuln()
    vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"] = [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"}]
    assert ev.normalize_nvd(nvd(vuln), "openbsd", "openssh")["advisories"][0]["ranges"][0]["exact"] == "6.6.1p1"


def test_other_products_in_the_same_cve_are_ignored():
    vuln = nvd_vuln(vendor="someone", product="else")
    assert ev.normalize_nvd(nvd(vuln), "openbsd", "openssh")["advisories"][0]["ranges"] == []


def test_cvss_v2_only_scores_are_used_when_nothing_newer_exists():
    vuln = nvd_vuln(score=None)
    vuln["cve"]["metrics"] = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}]}
    assert ev.normalize_nvd(nvd(vuln), "openbsd", "openssh")["advisories"][0]["score"] == 5.0


# --- Confirmed vs possible -------------------------------------------------------------------------------------------

def test_vanilla_version_inside_a_verified_range_is_confirmed_with_the_cvss_severity():
    found = finding_for("6.6.1p1", nvd_vuln())
    assert found.confidence == "confirmed" and found.severity == "critical" and found.scored
    assert found.cve_id == "CVE-2020-0001" and found.first_fixed == "7.0" and found.affected_range == "< 7.0"
    assert "Update OpenSSH to version 7.0 or later" in found.how_to_fix and found.caveat is None


def test_ubuntu_package_is_only_possible_and_explains_backports():
    found = finding_for("6.6.1p1", nvd_vuln(), family="ubuntu")
    assert found.confidence == "possible" and not found.scored and found.group == "needs_checking"
    assert "Ubuntu" in found.caveat and "apt changelog openssh-server" in found.caveat and "distro" in found.details["reasons"]
    assert found.severity == "critical"  # the severity is still shown; it just does not count until confirmed


@pytest.mark.parametrize("family", ["debian", "rhel"])
def test_debian_and_red_hat_packages_are_possible_too(family):
    assert finding_for("6.6.1p1", nvd_vuln(), family=family).confidence == "possible"


def test_a_proxy_or_cdn_banner_is_only_possible():
    found = finding_for("6.6.1p1", nvd_vuln(), proxy=True)
    assert found.confidence == "possible" and "proxy or CDN" in found.caveat


def test_range_we_cannot_verify_is_possible():
    assert finding_for("6.6.1p1", nvd_vuln(ranges=[{"versionEndExcluding": "weird-version"}])).confidence == "possible"
    vuln = nvd_vuln()
    vuln["cve"]["configurations"] = []
    found = finding_for("6.6.1p1", vuln)
    assert found.confidence == "possible" and "could not verify" in found.caveat


def test_a_version_outside_the_range_by_our_own_comparison_is_not_confirmed():
    found = finding_for("8.0", nvd_vuln())
    assert found.confidence == "possible"


def test_disputed_and_two_component_cves_are_possible():
    assert finding_for("6.6.1p1", nvd_vuln(desc="** DISPUTED ** maybe")).confidence == "possible"
    assert finding_for("6.6.1p1", nvd_vuln(tags=[{"tags": ["disputed"]}])).confidence == "possible"
    two = finding_for("6.6.1p1", nvd_vuln(operator="AND", extra_nodes=1))
    assert two.confidence == "possible" and "another component" in two.caveat


def test_unscored_cves_are_medium_and_possible():
    found = finding_for("6.6.1p1", nvd_vuln(score=None))
    assert found.severity == "medium" and found.confidence == "possible"


@pytest.mark.parametrize("score, band", [(9.8, "critical"), (7.5, "high"), (5.0, "medium"), (2.0, "low")])
def test_severity_follows_the_score_bands(score, band):
    assert finding_for("6.6.1p1", nvd_vuln(score=score)).severity == band


def test_stale_data_adds_findings_with_its_date_and_never_hides_anything():
    from datetime import datetime, timezone
    advisory = ev.normalize_nvd(nvd(nvd_vuln()), "openbsd", "openssh")["advisories"][0]
    found = ev.advisory_finding(item(), advisory, stale_at=datetime(2026, 11, 1, tzinfo=timezone.utc))
    assert "2026-11-01" in found.caveat and found.details["data_date"] == "2026-11-01"


# --- OSV -----------------------------------------------------------------------------------------------------------------

def osv_vuln(id_="GHSA-aaaa-bbbb-cccc", aliases=("CVE-2019-11358",), events=({"introduced": "0"}, {"fixed": "3.4.0"}), label="MODERATE", vector=None, withdrawn=None):
    out = {"id": id_, "aliases": list(aliases), "summary": "jQuery prototype pollution",
           "affected": [{"package": {"name": "jquery", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": list(events)}]}],
           "database_specific": {"severity": label}}
    if vector:
        out["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if withdrawn:
        out["withdrawn"] = withdrawn
    return out


def test_osv_uses_the_cve_alias_ranges_and_cvss_vector():
    result = ev.normalize_osv({"vulns": [osv_vuln(vector=VECTOR_98)]})
    advisory = result["advisories"][0]
    assert advisory["id"] == "CVE-2019-11358" and advisory["aliases"] == ["GHSA-aaaa-bbbb-cccc"] and advisory["score"] == 9.8
    assert advisory["ranges"] == [{"start_including": None, "end_excluding": "3.4.0"}]


def test_osv_label_only_and_withdrawn():
    result = ev.normalize_osv({"vulns": [osv_vuln(), osv_vuln(id_="GHSA-x", withdrawn="2020-01-01T00:00:00Z")]})
    assert len(result["advisories"]) == 1 and result["advisories"][0]["label"] == "MODERATE"
    found = ev.advisory_finding(item("3.3.1", key="jquery", ecosystem="npm", port=80), result["advisories"][0])
    assert found.severity == "medium" and found.confidence == "confirmed" and found.first_fixed == "3.4.0"


def test_osv_empty_answer_is_valid_and_garbage_is_an_error():
    assert ev.normalize_osv({})["advisories"] == []
    with pytest.raises(ev.vuln_sources.SourceError):
        ev.normalize_osv({"vulns": "no"})


def test_jquery_3_6_0_is_not_flagged_by_a_range_that_ends_at_3_4_0():
    advisory = ev.normalize_osv({"vulns": [osv_vuln()]})["advisories"][0]
    ok, _ = ev.verify("3.6.0", advisory)
    assert ok is False


# --- CPE names and item collection ----------------------------------------------------------------------------------------

def test_cpe_names_split_openssh_updates_only_when_asked():
    assert ev.cpe_for("openbsd", "openssh", "6.6.1p1", True) == "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"
    assert ev.cpe_for("apache", "http_server", "2.4.7", False) == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"
    assert ev.cpe_for("php", "php", "7.4.3", False).startswith("cpe:2.3:a:php:php:7.4.3:")


def test_old_and_new_vendor_names_are_both_queried():
    pairs = identify_items._MAP["products"]
    assert ["f5", "nginx"] in pairs["nginx"]["cpes"] and ["nginx", "nginx"] in pairs["nginx"]["cpes"]
    assert ["oracle", "mysql"] in pairs["mysql"]["cpes"] and ["mysql", "mysql"] in pairs["mysql"]["cpes"]
    assert len(pairs["vsftpd"]["cpes"]) == 2


def page(port, server, **headers):
    return WebPage(port=port, tls=False, status=200, headers={"server": server, **headers}, cookies=[], body="")


def test_items_are_collected_from_banners_headers_and_technologies():
    ssh = PortProbe(port=22, service="ssh", product="OpenSSH", version="6.6.1p1", banner="SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13")
    web = PortProbe(port=80, service="http", product="Apache", version="2.4.7", web=page(80, "Apache/2.4.7 (Ubuntu)"))
    techs = [{"name": "jQuery", "category": "js", "version": "1.12.4", "source": "script", "evidence": "x", "port": 80},
             {"name": "Apache", "category": "server", "version": "2.4.7", "source": "header", "evidence": "x", "port": None},
             {"name": "Cloudflare", "category": "cdn", "version": None, "source": "header", "evidence": "x", "port": 80}]
    found = identify_items.collect("example.com", [ssh, web], techs)
    by_key = {i.key: i for i in found}
    assert set(by_key) == {"openssh", "apache", "jquery"}  # Apache is listed once; unknown products are ignored
    assert by_key["openssh"].family == "ubuntu" and by_key["apache"].family == "ubuntu" and by_key["jquery"].family is None
    assert by_key["openssh"].version == "6.6.1p1"


def test_untrusted_version_text_is_never_used():
    probe = PortProbe(port=22, service="ssh", product="OpenSSH", version="6.6; rm -rf /", banner="x")
    assert identify_items.collect("example.com", [probe], [])[0].version is None


def test_angular_one_is_angularjs_and_later_is_angular():
    assert identify_items.entry_for("Angular", "1.8.2") == ("npm", "angularjs")
    assert identify_items.entry_for("Angular", "15.0.0") == ("npm", "angular")
    assert identify_items.entry_for("Something Else", "1.0") is None


def test_no_disclosed_version_gives_an_info_finding_that_says_we_cannot_check():
    found = ev.hidden_version_finding(item(version=None))
    assert found.severity == "info" and not found.scored and "cannot check" in found.title
    assert "safe" not in found.title.lower()
