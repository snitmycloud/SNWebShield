"""The strict YAML reader and the Nuclei template validator: every rule has a template that breaks it."""
import hashlib
import json

import pytest

from app.services import nuclei_templates as nt, nuclei_yaml
from app.services.nuclei_yaml import YamlError

GOOD = """id: example-exposure
info:
  name: Example exposure
  author: someone
  severity: medium
  description: |
    A file that should not be public.
  tags: exposure,config
http:
  - method: GET
    path:
      - "{{BaseURL}}/secret.txt"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "TOPSECRET"
      - type: status
        status:
          - 200
"""
PATH = "http/exposures/configs/example.yaml"


def check(text, path=PATH):
    return nt.validate(text, path)


def reasons(text, path=PATH):
    return check(text, path).reasons


def variant(old, new):
    assert old in GOOD, old
    return GOOD.replace(old, new)


# --- the YAML reader ---------------------------------------------------------------------------------------------

def test_the_reader_handles_what_templates_use():
    data = nuclei_yaml.parse("""---
# comment
id: x
info:
  name: "Quoted: name"   # trailing comment
  tags: [a, b, 'c d']
  reference:
    - https://example.com/a#frag
list:
- a: 1
  b: true
- plain
folded: >
  one
  two
literal: |
  line1
  line2
empty:
http:
  - path:
      - "{{BaseURL}}/x"
""")
    assert data["id"] == "x" and data["info"]["name"] == "Quoted: name" and data["info"]["tags"] == ["a", "b", "c d"]
    assert data["info"]["reference"] == ["https://example.com/a#frag"]
    assert data["list"] == [{"a": 1, "b": True}, "plain"]
    assert data["folded"] == "one two" and data["literal"] == "line1\nline2" and data["empty"] is None
    assert data["http"][0]["path"] == ["{{BaseURL}}/x"]


@pytest.mark.parametrize("text", [
    "a: &anchor 1\nb: *anchor\n", "a: !!python/object x\n", "\tindented: 1\n", "a: 1\na: 2\n", "<<: {a: 1}\n", "a: {b: 1}\n",
    "a: 1\n---\nb: 2\n", "- - nested\n", "a: 'unterminated\n", "a: \x00\n", "key without colon\n", "a:\n   b: 1\n  c: 2\n",
])
def test_the_reader_fails_closed_on_anything_unusual(text):
    with pytest.raises(YamlError):
        nuclei_yaml.parse(text)


def test_the_reader_refuses_oversized_files():
    with pytest.raises(YamlError):
        nuclei_yaml.parse("a: " + "x" * 200_000 + "\n")


def test_depth_and_size_are_limited():
    deep = "".join("  " * i + "a:\n" for i in range(40)) + "  " * 40 + "b: 1\n"
    with pytest.raises(YamlError):
        nuclei_yaml.parse(deep)


# --- the validator: the good template and each rule ------------------------------------------------------------------------

def test_a_plain_exposure_template_passes_with_its_metadata():
    verdict = check(GOOD)
    assert verdict.ok and verdict.category == "exposures" and verdict.template_id == "example-exposure" and verdict.severity == "medium"


@pytest.mark.parametrize("path, category", [
    ("http/exposures/configs/a.yaml", "exposures"), ("http/exposed-panels/b.yaml", "exposed-panels"),
    ("http/misconfiguration/apache/c.yaml", "misconfiguration"), ("http/technologies/d.yaml", "technologies"),
    ("http/cves/2021/CVE-2021-1.yaml", "cves"), ("http/vulnerabilities/x.yaml", None), ("http/takeovers/y.yaml", None),
])
def test_only_the_five_categories_are_in_scope(path, category):
    assert nt.category_of(path) == category
    if category is None:
        assert "out_of_scope" in reasons(GOOD, path)


@pytest.mark.parametrize("tag", sorted(nt.BANNED_TAGS))
def test_every_banned_tag_is_rejected(tag):
    assert f"banned_tag:{tag}" in reasons(variant("tags: exposure,config", f"tags: exposure,{tag.upper()}"))
    assert f"banned_tag:{tag}" in reasons(variant("tags: exposure,config", f"tags: [exposure, {tag}]"))


def test_the_owner_listed_tags_are_all_banned():
    for tag in ("xss", "lfi", "ssrf", "xxe", "ssti", "oast", "intrusive", "dos", "fuzz", "bruteforce", "rce", "sqli"):
        assert tag in nt.BANNED_TAGS


@pytest.mark.parametrize("block", ["code", "javascript", "headless", "file", "dns", "network", "tcp", "ssl", "whois", "websocket", "workflows", "flow"])
def test_other_protocols_are_rejected(block):
    assert "not_http" in reasons(GOOD + f"{block}:\n  - something: 1\n")


def test_a_template_without_an_http_block_is_rejected():
    assert "not_http" in reasons("id: a\ninfo:\n  name: n\n  severity: info\ndns:\n  - name: x\n")


@pytest.mark.parametrize("key, value", [("raw", "\n      - |\n        GET / HTTP/1.1"), ("payloads", "\n      a: [1]"), ("attack", " clusterbomb"),
                                        ("fuzzing", "\n      - part: query"), ("race", " true"), ("pipeline", " true"), ("unsafe", " true"),
                                        ("digest-username", " admin"), ("race_count", " 5")])
def test_unsafe_request_features_are_rejected(key, value):
    assert f"unsafe_feature:{key}" in reasons(variant("    matchers-condition: and\n", f"    {key}:{value}\n    matchers-condition: and\n"))


def test_self_contained_templates_and_request_bodies_are_rejected():
    assert "unsafe_feature:self-contained" in reasons(GOOD + "self-contained: true\n")
    assert "unsafe_feature:body" in reasons(variant("    matchers-condition: and\n", "    body: a=b\n    matchers-condition: and\n"))


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "post"])
def test_only_get_and_head_are_allowed(method):
    assert "method" in reasons(variant("  - method: GET", f"  - method: {method}"))
    assert reasons(variant("  - method: GET", "  - method: HEAD")) == []


@pytest.mark.parametrize("target", [
    "http://other.example/x", "https://169.254.169.254/latest", "{{Hostname}}/x", "/relative", "{{BaseURL}}/a?u=http://evil.example",
    "{{BaseURL}}/{{interactsh-url}}", "{{BaseURL}}/{{custom}}", "evil.example",
])
def test_every_request_must_target_the_scanned_host_only(target):
    assert "target" in reasons(variant('"{{BaseURL}}/secret.txt"', json.dumps(target)))


def test_rooturl_and_randstr_are_allowed_in_paths():
    assert reasons(variant('"{{BaseURL}}/secret.txt"', '"{{RootURL}}/{{randstr}}.txt"')) == []


@pytest.mark.parametrize("text", ["{{interactsh-url}}", "oast.pro", "{{exec('id')}}", "{{file('/etc/passwd')}}", "{{read_file('x')}}",
                                  "{{sleep(5)}}", "{{wait_for(2)}}", "collaborator"])
def test_dangerous_helpers_are_rejected_anywhere(text):
    assert "banned_helper" in reasons(variant("TOPSECRET", text))
    assert "banned_helper" in reasons(variant("    matchers-condition: and\n", f"    headers:\n      X-A: \"{text}\"\n    matchers-condition: and\n"))


def test_header_variables_outside_the_safe_list_are_rejected():
    assert "banned_helper" in reasons(variant("    matchers-condition: and\n", "    headers:\n      X-A: \"{{payload}}\"\n    matchers-condition: and\n"))


def test_request_count_is_capped():
    many = "".join(f'      - "{{{{BaseURL}}}}/p{i}"\n' for i in range(9))
    assert "too_many_requests" in reasons(variant('      - "{{BaseURL}}/secret.txt"\n', many))


@pytest.mark.parametrize("value, rejected", [(2, False), (3, False), (4, True), (20, True)])
def test_max_redirects_is_capped(value, rejected):
    text = variant("    matchers-condition: and\n", f"    redirects: true\n    max-redirects: {value}\n    matchers-condition: and\n")
    assert ("redirects" in reasons(text)) is rejected


def test_a_template_that_cannot_confirm_anything_is_rejected():
    no_matchers = GOOD[:GOOD.index("    matchers-condition")]
    assert "no_matchers" in reasons(no_matchers)


@pytest.mark.parametrize("old, new", [("id: example-exposure", "id: ../etc/passwd"), ("id: example-exposure", ""), ("  severity: medium", "  severity: apocalyptic"),
                                      ("  name: Example exposure\n", "")])
def test_metadata_must_be_present_and_well_formed(old, new):
    assert "bad_metadata" in reasons(variant(old, new))


def test_unreadable_oversized_and_non_mapping_templates_are_rejected():
    assert reasons("a: &x 1\nb: *x\n") == ["unparseable"] or "unparseable" in reasons("a: &x 1\nb: *x\n")
    assert reasons("x" * 200_000) == ["size"]
    assert "unparseable" in reasons("- just\n- a list\n")
    assert "unparseable" in reasons("")


CVE = GOOD.replace("id: example-exposure", "id: CVE-2021-12345")
CVE_PATH = "http/cves/2021/CVE-2021-12345.yaml"


def test_a_cve_template_with_passive_matchers_passes():
    assert check(CVE, CVE_PATH).ok


@pytest.mark.parametrize("matcher", ["dsl", "binary", "xpath", "time"])
def test_cve_templates_may_only_use_word_status_regex_size(matcher):
    text = CVE.replace("      - type: status\n        status:\n          - 200\n", f"      - type: {matcher}\n        {matcher}:\n          - x\n")
    assert "cve_not_passive" in reasons(text, CVE_PATH)


def test_a_cve_template_needs_a_cve_identity():
    text = GOOD.replace("id: example-exposure", "id: just-a-name")
    assert "bad_metadata" in reasons(text, CVE_PATH)
    with_class = text.replace("  tags: exposure,config\n", "  tags: x\n  classification:\n    cve-id: CVE-2021-12345\n")
    assert "bad_metadata" not in reasons(with_class, CVE_PATH)


def test_the_validator_only_reads_text_and_never_runs_it():
    nasty = GOOD.replace("TOPSECRET", "__import__('os').system('echo hacked')")
    assert check(nasty).ok  # it is just a word to look for; nothing is executed


# --- the vendoring helpers -----------------------------------------------------------------------------------------------------

def test_the_manifest_hash_is_stable_and_sorted():
    files = {"b.yaml": b"2", "a.yaml": b"1"}
    assert list(nt.manifest_hash(files)) == ["a.yaml", "b.yaml"]
    assert nt.manifest_hash(files)["a.yaml"] == hashlib.sha256(b"1").hexdigest()
