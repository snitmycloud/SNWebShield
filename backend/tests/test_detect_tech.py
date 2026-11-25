"""Technology fingerprints: the editable rule file, every starter technology, versions, hostile pages."""
import json
import time

import pytest

from app.services import detect_tech as dt
from app.services.detect_versions import WebPage

RULES = dt.load_rules()


def page(headers=None, cookies=(), body="", port=443):
    return WebPage(port=port, tls=True, status=200, headers={k.lower(): v for k, v in (headers or {}).items()},
                   cookies=[{"name": n, "secure": False, "httponly": False, "samesite": None} for n in cookies], body=body)


def found(web):
    return {t["name"]: t["version"] for t in dt.detect(RULES, web)}


def test_the_rule_file_loads_cleanly_with_every_starter_technology():
    assert RULES.skipped == 0
    names = {t.name for t in RULES.techs}
    assert names >= {"nginx", "Apache", "IIS", "LiteSpeed", "Cloudflare", "PHP", "ASP.NET", "Node.js / Express", "WordPress",
                     "Joomla", "Drupal", "Shopify", "Wix", "jQuery", "Bootstrap", "React", "Angular", "Vue", "Lodash",
                     "Moment.js", "Google Analytics"}
    for tech in RULES.techs:
        assert tech.name and tech.category and tech.rules


CASES = [
    ("nginx", dict(headers={"Server": "nginx/1.18.0"}), "1.18.0"),
    ("Apache", dict(headers={"Server": "Apache/2.4.41 (Ubuntu)"}), "2.4.41"),
    ("IIS", dict(headers={"Server": "Microsoft-IIS/10.0"}), "10.0"),
    ("LiteSpeed", dict(headers={"Server": "LiteSpeed"}), None),
    ("Cloudflare", dict(headers={"Server": "cloudflare", "CF-RAY": "abc"}), None),
    ("PHP", dict(headers={"X-Powered-By": "PHP/8.1.2"}), "8.1.2"),
    ("PHP", dict(cookies=["PHPSESSID"]), None),
    ("ASP.NET", dict(headers={"X-AspNet-Version": "4.0.30319"}), "4.0.30319"),
    ("Node.js / Express", dict(headers={"X-Powered-By": "Express"}), None),
    ("WordPress", dict(body='<meta name="generator" content="WordPress 6.4.2" />'), "6.4.2"),
    ("WordPress", dict(body='<link href="/wp-content/themes/x/style.css">'), None),
    ("Joomla", dict(body='<meta name="generator" content="Joomla! - Open Source Content Management">'), None),
    ("Drupal", dict(body='<meta name="Generator" content="Drupal 9 (https://www.drupal.org)">'), "9"),
    ("Drupal", dict(headers={"X-Generator": "Drupal 10 (https://www.drupal.org)"}), "10"),
    ("Shopify", dict(headers={"X-ShopId": "123"}), None),
    ("Wix", dict(body='<script src="https://static.wixstatic.com/x.js"></script>'), None),
    ("jQuery", dict(body='<script src="/js/jquery-3.6.0.min.js"></script>'), "3.6.0"),
    ("jQuery", dict(body='<script src="https://cdn.example/ajax/libs/jquery/1.12.4/jquery.min.js"></script>'), "1.12.4"),
    ("Bootstrap", dict(body='<link rel="stylesheet" href="https://cdn.example/bootstrap/4.5.2/css/bootstrap.min.css">'), "4.5.2"),
    ("React", dict(body='<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>'), "18.2.0"),
    ("Angular", dict(body='<app-root ng-version="15.2.1"></app-root>'), "15.2.1"),
    ("Vue", dict(body='<script src="https://cdn.jsdelivr.net/npm/vue@3.2.47/dist/vue.global.js"></script>'), "3.2.47"),
    ("Lodash", dict(body='<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>'), "4.17.21"),
    ("Moment.js", dict(body='<script src="/assets/moment.min.js"></script>'), None),
    ("Moment.js", dict(body='<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js"></script>'), "2.29.4"),
    ("Google Analytics", dict(body='<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>'), None),
]


@pytest.mark.parametrize("name, parts, version", CASES, ids=[f"{n}-{i}" for i, (n, _, _) in enumerate(CASES)])
def test_each_starter_technology_is_detected_with_its_version(name, parts, version):
    result = found(page(**parts))
    assert name in result and result[name] == version


def test_a_plain_page_matches_nothing_and_no_page_matches_nothing():
    assert found(page(body="<html><body>Hello</body></html>")) == {}
    assert dt.detect(RULES, None) == []


def test_results_carry_category_source_and_cleaned_evidence():
    item = dt.detect(RULES, page(headers={"Server": "nginx/1.18.0\x00\x07"}), )[0]
    assert item["category"] == "Web server" and item["source"] == "header" and "\x00" not in item["evidence"]
    assert item["port"] is None or item["port"] == 443


def test_file_rules_use_prefetched_files_and_are_limited():
    web = page(body="<html></html>")
    wanted = dt.file_paths_needed(RULES, set())
    assert 0 < len(wanted) <= dt.MAX_FILE_FETCHES and "/administrator/manifests/files/joomla.xml" in wanted
    result = {t["name"]: t["version"] for t in dt.detect(RULES, web, files={
        "/administrator/manifests/files/joomla.xml": "<extension><version>4.2.9</version></extension>"})}
    assert result["Joomla"] == "4.2.9"
    assert "Joomla" not in {t["name"] for t in dt.detect(RULES, web, files={})}
    assert "/administrator/manifests/files/joomla.xml" not in dt.file_paths_needed(RULES, {"Joomla"})


def test_adding_a_rule_needs_no_code_and_broken_rules_are_skipped(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"technologies": [
        {"name": "MyCMS", "category": "CMS", "rules": [{"where": "header", "name": "x-mycms", "pattern": "v", "version": "v(\\d+)"}]},
        {"name": "BadRegex", "category": "X", "rules": [{"where": "html", "pattern": "(unclosed"}]},
        {"name": "BadWhere", "category": "X", "rules": [{"where": "telepathy", "pattern": "x"}]},
        {"name": "NoRules", "category": "X", "rules": []},
        {"category": "NoName", "rules": [{"where": "html", "pattern": "x"}]},
        "garbage"]}))
    rules = dt.load_rules(path)
    assert [t.name for t in rules.techs] == ["MyCMS"] and rules.skipped == 5
    assert {t["name"]: t["version"] for t in dt.detect(rules, page(headers={"x-mycms": "v7"}))} == {"MyCMS": "7"}
    path.write_text("{ not json")
    assert dt.load_rules(path).techs == [] and dt.load_rules(tmp_path / "missing.json").techs == []


def test_merge_keeps_one_row_per_technology_and_prefers_a_known_version():
    merged = dt.merge([{"name": "nginx", "category": "Web server", "version": None, "source": "header", "evidence": "nginx", "port": 80}],
                      [{"name": "nginx", "category": "Web server", "version": "1.18.0", "source": "header", "evidence": "nginx/1.18.0", "port": 443},
                       {"name": "PHP", "category": "Programming language", "version": None, "source": "cookie", "evidence": "PHPSESSID", "port": 443}])
    assert [(m["name"], m["version"]) for m in merged] == [("nginx", "1.18.0"), ("PHP", None)]


def test_a_hostile_page_is_handled_quickly_and_safely():
    hostile = "<script src=" * 30000 + "<meta name=generator content=" * 5000 + "<<<<" * 50000
    started = time.monotonic()
    result = dt.detect(RULES, page(body=hostile[:300_000]))
    assert time.monotonic() - started < 5 and isinstance(result, list)
    huge_version = page(body='<script src="/jquery-' + "9." * 5000 + '1.min.js"></script>')
    for item in dt.detect(RULES, huge_version):
        assert len(item["version"] or "") <= 30
