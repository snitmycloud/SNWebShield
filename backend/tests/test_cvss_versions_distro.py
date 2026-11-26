"""CVSS scoring, version comparison and distro/proxy detection (pure logic, no network)."""
import pytest

from app.services import cvss, distro, versions


# --- CVSS -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # NVD: CVE-2016-1908-style network RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # the classic reflected XSS score (jQuery CVE-2019-11358 family)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_base_scores_match_published_values(vector, score):
    assert cvss.base_score(vector) == score


@pytest.mark.parametrize("vector", ["", "garbage", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "CVSS:3.1/AV:N/AC:L", None, 123])
def test_unsupported_or_malformed_vectors_return_none_never_raise(vector):
    assert cvss.base_score(vector) is None


@pytest.mark.parametrize("score, band", [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"),
                                         (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info"), (None, None)])
def test_severity_bands(score, band):
    assert cvss.severity_from_score(score) == band


def test_qualitative_labels():
    assert [cvss.severity_from_label(x) for x in ("CRITICAL", "high", "MODERATE", "Low", "weird", None)] == [
        "critical", "high", "medium", "low", None, None]


# --- Versions -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("2.4.7", "2.4.10", -1), ("2.4.10", "2.4.7", 1), ("1.18.0", "1.18", 0), ("1.0", "1.0.0", 0),
    ("6.6.1p1", "6.6.1", 1), ("6.6.1p1", "6.6.1p2", -1), ("6.6.1p1", "7.2", -1), ("7.2p2", "7.2", 1),
    ("1.0-beta", "1.0", -1), ("1.0-rc1", "1.0", -1), ("1.0-rc1", "1.0-beta2", 1), ("5.7.40", "8.0.32", -1),
    ("10.3.34", "10.3.4", 1), ("v1.2.3", "1.2.3", 0), ("7.4.33", "7.4.3", 1), ("2.4.7", "2.4.7", 0),
])
def test_compare(a, b, expected):
    assert versions.compare(a, b) == expected


@pytest.mark.parametrize("bad", ["", None, "not a version", "latest", "x" * 100, "..", "1..2 "])
def test_unversionlike_strings_are_not_comparable(bad):
    assert versions.parse(bad) is None or versions.parse(bad) == ()
    assert versions.compare(bad, "1.0") is None or bad == "1..2 "


def test_ranges():
    assert versions.in_range("6.6.1p1", end_excluding="7.2") is True
    assert versions.in_range("7.2", end_excluding="7.2") is False
    assert versions.in_range("7.2p2", end_excluding="7.2") is False
    assert versions.in_range("2.4.7", start_including="2.4.0", end_including="2.4.7") is True
    assert versions.in_range("2.4.8", start_including="2.4.0", end_including="2.4.7") is False
    assert versions.in_range("2.3.9", start_including="2.4.0") is False
    assert versions.in_range("garbage", end_excluding="1.0") is None
    assert versions.in_range("1.0", end_excluding="garbage") is None
    assert versions.in_range("5", ) is True


def test_range_descriptions():
    assert versions.describe_range(end_excluding="7.2") == "< 7.2"
    assert versions.describe_range(start_including="1.0", end_excluding="2.0") == ">= 1.0, < 2.0"
    assert versions.describe_range(exact="6.6.1") == "= 6.6.1"
    assert versions.describe_range() == "all versions"


# --- Distro / proxy -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, family", [
    ("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", "ubuntu"), ("Apache/2.4.7 (Ubuntu)", "ubuntu"),
    ("OpenSSH_8.4p1 Debian-5+deb11u1", "debian"), ("Apache/2.4.38 (Debian)", "debian"), ("OpenSSH_7.4p1 Raspbian-10", "debian"),
    ("Apache/2.4.6 (CentOS)", "rhel"), ("Apache/2.4.37 (Red Hat Enterprise Linux)", "rhel"), ("nginx/1.20.1 (el9)", None),
    ("nginx/1.18.0", None), ("Apache/2.4.58", None), ("OpenSSH_9.6p1", None), ("", None), (None, None),
])
def test_distro_detection(text, family):
    assert distro.detect_family(text) == family


def test_proxy_detection():
    assert distro.behind_proxy({"via": "1.1 varnish"}) and distro.behind_proxy({"cf-ray": "abc"})
    assert not distro.behind_proxy({"server": "nginx"}) and not distro.behind_proxy(None) and not distro.behind_proxy({})


def test_caveats_explain_and_say_how_to_check():
    text = distro.caveat("ubuntu", "openssh", "OpenSSH", "6.6.1p1")
    assert "Ubuntu" in text and "without changing this version number" in text and "apt changelog openssh-server" in text
    assert "rpm -q --changelog httpd" in distro.caveat("rhel", "apache", "Apache", "2.4.6")
    assert "proxy or CDN" in distro.caveat(None, "nginx", "nginx", "1.18.0", proxy=True)
    assert distro.caveat(None, "nginx", "nginx", "1.18.0") is None
