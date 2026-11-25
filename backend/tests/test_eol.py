"""End-of-life: tiers, the ambiguity rule, distribution vs vanilla, CDN banners and old data. No network."""
import json
from datetime import date

import pytest

from app.services import engine_eol as eol_engine, identify_items

TODAY = date(2026, 11, 26)
EOL = {"as_of": "2026-11-20", "products": {
    "ubuntu": [{"cycle": "14.04", "eol": "2019-04-02", "extendedSupport": "2024-04-02"},
               {"cycle": "18.04", "eol": "2023-05-31", "extendedSupport": "2028-04-26"},
               {"cycle": "20.04", "eol": "2025-05-31", "extendedSupport": "2030-04-23"},
               {"cycle": "22.04", "eol": "2027-06-01", "extendedSupport": "2032-04-21"}],
    "debian": [{"cycle": "8", "eol": "2020-06-30", "extendedSupport": "2025-06-30"}, {"cycle": "11", "eol": "2026-08-31", "extendedSupport": "2031-06-30"}],
    "centos": [{"cycle": "7", "eol": "2024-06-30"}], "rhel": [{"cycle": "7", "eol": "2024-06-30", "extendedSupport": "2028-06-30"}],
    "php": [{"cycle": "7.4", "eol": "2022-11-28"}, {"cycle": "8.3", "eol": "2027-12-31"}, {"cycle": "5.5", "eol": "2016-07-21"}],
    "nginx": [{"cycle": "1.18", "eol": "2021-04-20"}, {"cycle": "1.2", "eol": False}],
    "apache-http-server": [{"cycle": "2.4", "eol": False}],
}}
HINTS = json.loads((eol_engine.DATA / "eol_hints.json").read_text(encoding="utf-8"))


def item(key, version, family=None, text="", port=22, proxy=False):
    ecosystem_map = identify_items._MAP["products"]
    found = identify_items.Item("cpe", key, ecosystem_map[key]["label"], version, port, f"example.com:{port}", context_text=text)
    found.family, found.proxy = family, proxy
    return found


def evaluate(items, eol=EOL, today=TODAY):
    return eol_engine.evaluate("example.com", items, eol, HINTS, today)


# --- the two tiers and their wording ---------------------------------------------------------------------------------

def test_all_support_ended_is_high_with_the_exact_wording():
    [found] = evaluate([item("openssh", "6.6.1p1", "ubuntu", "SSH Ubuntu-2ubuntu2.13")])
    assert found.severity == "high" and found.confidence == "confirmed" and found.scored
    assert found.check_id == "eol:distro:ubuntu-14.04" and "no longer receives security updates" in found.title
    assert "No longer receives security updates" in found.why and "Only paid extended support remains" not in found.why
    assert found.you_have == "Ubuntu 14.04" and "ended on 2019-04-02" in found.how_to_fix and found.location == "example.com"


def test_only_paid_support_left_is_medium_with_its_own_wording():
    [found] = evaluate([item("openssh", "7.6p1", "ubuntu")])
    assert found.severity == "medium" and found.scored and found.details["tier"] == "paid_only"
    assert "only paid extended support remains" in found.title.lower() and "Only paid extended support remains" in found.why
    assert "No longer receives" not in found.why


def test_a_supported_release_gives_no_finding_even_with_an_old_looking_version():
    assert evaluate([item("openssh", "8.9p1", "ubuntu")]) == []   # Ubuntu 22.04 is supported until 2027
    assert evaluate([item("apache", "2.4.7", "ubuntu", "Apache/2.4.7 (Ubuntu)", 80)])[0].check_id == "eol:distro:ubuntu-14.04"


def test_a_distro_build_is_judged_by_its_release_not_the_upstream_branch():
    # PHP 7.4.3 is an end-of-life PHP branch upstream, but on Ubuntu 20.04 it is a supported (paid-extended) package.
    [found] = evaluate([item("php", "7.4.3", "ubuntu", "PHP/7.4.3-4ubuntu2", 80)])
    assert found.check_id == "eol:distro:ubuntu-20.04" and found.severity == "medium"
    assert not any(f.check_id.startswith("eol:product:") for f in evaluate([item("php", "7.4.3", "ubuntu", "PHP/7.4.3-4ubuntu2", 80)]))


def test_vanilla_software_is_judged_by_its_own_branch():
    [found] = evaluate([item("php", "7.4.33", None, "", 80)])
    assert found.check_id == "eol:product:php-7.4" and found.severity == "high" and found.location == "example.com:80"
    assert evaluate([item("php", "8.3.6")]) == []
    assert evaluate([item("apache", "2.4.58")]) == []


def test_the_longest_matching_branch_wins():
    assert evaluate([item("nginx", "1.24.0")]) == []        # 1.2 (supported row) must not swallow 1.24
    [found] = evaluate([item("nginx", "1.18.0")])
    assert found.check_id == "eol:product:nginx-1.18"


def test_openssh_never_gets_a_branch_end_of_life_only_distribution_based():
    assert evaluate([item("openssh", "5.3")]) == []   # vanilla old OpenSSH: CVEs are shown, no invented cut-off date
    assert evaluate([item("openssh", "9.9")]) == []


# --- ambiguity: never claim end of life unless EVERY candidate release has ended --------------------------------------------

def test_nginx_1_18_0_on_ubuntu_is_ambiguous_and_the_newest_release_decides():
    # 1.18.0 ships on 20.04 AND 22.04; 22.04 is still supported, so nothing is claimed.
    assert evaluate([item("nginx", "1.18.0", "ubuntu", "nginx/1.18.0 (Ubuntu)", 80)]) == []


def test_ambiguity_where_every_candidate_has_ended_is_reported():
    hints = json.loads(json.dumps(HINTS))
    hints["nginx"]["ubuntu"]["1.4.6"] = ["14.04"]
    found = eol_engine.evaluate("example.com", [item("nginx", "1.4.6", "ubuntu", "nginx (Ubuntu)", 80)], EOL, hints, TODAY)
    assert found and found[0].check_id == "eol:distro:ubuntu-14.04"


def test_unknown_version_or_release_gives_no_finding():
    assert evaluate([item("openssh", "6.0p1", "ubuntu")]) == []
    assert evaluate([item("openssh", None, "ubuntu")]) == []


def test_debian_release_is_read_from_the_package_text():
    [found] = evaluate([item("openssh", "6.7p1", "debian", "OpenSSH_6.7p1 Debian-5+deb8u8")])
    assert found.check_id == "eol:distro:debian-8" and found.severity == "high"


def test_red_hat_family_takes_the_most_favourable_candidate_so_paid_rhel_support_is_not_called_ended():
    [found] = evaluate([item("apache", "2.4.6", "rhel", "Apache/2.4.6 (CentOS)", 80)])
    assert found.severity == "medium" and found.details["family"] == "rhel"   # CentOS 7 ended, RHEL 7 still has paid support


# --- one finding per release / branch, CDN banners, old data -----------------------------------------------------------------

def test_two_services_on_the_same_old_os_give_one_finding_that_names_both():
    found = evaluate([item("openssh", "6.6.1p1", "ubuntu"), item("apache", "2.4.7", "ubuntu", "Apache (Ubuntu)", 80)])
    assert len(found) == 1 and "OpenSSH" in found[0].evidence and "Apache" in found[0].evidence


def test_a_version_seen_through_a_proxy_is_only_possible_and_does_not_count():
    [found] = evaluate([item("php", "7.4.33", None, "", 80, proxy=True)])
    assert found.confidence == "possible" and not found.scored and "proxy or CDN" in found.caveat


def test_data_older_than_90_days_is_flagged_on_the_finding():
    old = {**EOL, "as_of": "2026-01-01"}
    [found] = evaluate([item("openssh", "6.6.1p1", "ubuntu")], eol=old)
    assert "2026-01-01" in found.caveat and "newer date may be missing" in found.caveat
    [fresh] = evaluate([item("openssh", "6.6.1p1", "ubuntu")])
    assert fresh.caveat is None


@pytest.mark.parametrize("row, expected", [
    ({"eol": False}, "supported"), ({"eol": "2030-01-01"}, "supported"), ({"eol": "2020-01-01"}, "ended"),
    ({"eol": "2020-01-01", "extendedSupport": "2030-01-01"}, "paid_only"), ({"eol": "2020-01-01", "extendedSupport": "2021-01-01"}, "ended"),
    ({"eol": "2020-01-01", "extendedSupport": False}, "ended"), ({"eol": True}, "ended"), ({}, "unknown"), ({"eol": "garbage"}, "unknown"),
])
def test_status_tiers(row, expected):
    assert eol_engine.status(row, TODAY)[0] == expected


# --- the committed data files --------------------------------------------------------------------------------------------------

def test_the_committed_data_covers_the_releases_the_hints_refer_to():
    eol, hints = eol_engine.load()
    assert eol["as_of"] and eol["source"].startswith("https://endoflife.date")
    for key, families in hints.items():
        if key in ("_help", "slugs"):
            continue
        for family, table in families.items():
            for version, releases in table.items():
                for slug in hints["slugs"]["family"][family]:
                    for release in releases:
                        if slug == "rhel" and release == "8":
                            continue
                        assert eol_engine._row(eol, slug, release), f"{key} {family} {version}: no {slug} {release} in eol.json"


def test_the_real_data_says_ubuntu_14_04_has_no_support_left():
    eol, hints = eol_engine.load()
    [found] = eol_engine.evaluate("example.com", [item("openssh", "6.6.1p1", "ubuntu")], eol, hints, date(2026, 11, 26))
    assert found.severity == "high" and found.check_id == "eol:distro:ubuntu-14.04"
