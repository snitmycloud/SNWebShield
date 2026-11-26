"""The Nuclei template validator. A template that fails ANY rule here is never vendored and never passed to Nuclei.

Rules (owner-approved list, 2026-11-26), each with a stable reason code:
  size / unparseable      the file must be small and readable by our strict YAML reader (nuclei_yaml.py)
  not_http                only the plain `http` protocol; code, javascript, headless, file, dns, network/tcp, ssl, whois,
                          websocket, workflow(s) and flow are rejected
  banned_tag:<tag>        intrusive dos fuzz bruteforce rce sqli xss lfi ssrf xxe ssti oast (+ dast, fuzzing, default-login)
  unsafe_feature:<key>    raw requests, payloads, attack, fuzzing, race, pipeline, unsafe, self-contained, digest logins, bodies
  method                  GET or HEAD only
  target                  every path must start with {{BaseURL}} or {{RootURL}}; no absolute URLs, no other host
  banned_helper           interactsh / OAST, exec, file and read helpers, sleep-style timing, wait_for
  too_many_requests       at most 8 request paths per template
  redirects               redirects must stay on the same host and `max-redirects` is at most 3
  no_matchers             a template without matchers cannot confirm anything
  bad_metadata            id, info.name and info.severity must be present and well formed
  cve_not_passive         CVE templates may only use word / status / regex / size matchers (no DSL, no timing)
  out_of_scope            not in exposures, exposed-panels, misconfiguration, technologies or CVEs

The validator only reads text. It never runs, fetches or imports anything from a template.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.services import nuclei_yaml

MAX_TEMPLATE_BYTES = 64 * 1024
MAX_PATHS = 8
MAX_REDIRECTS = 3
BANNED_TAGS = {"intrusive", "dos", "fuzz", "bruteforce", "rce", "sqli", "xss", "lfi", "ssrf", "xxe", "ssti", "oast",
               "dast", "fuzzing", "default-login"}
PROTOCOL_KEYS = {"code", "javascript", "headless", "file", "dns", "network", "tcp", "ssl", "whois", "websocket", "workflow",
                 "workflows", "flow", "http2", "requests_legacy"}
UNSAFE_REQUEST_KEYS = {"raw", "payloads", "attack", "fuzzing", "race", "race_count", "pipeline", "unsafe", "self-contained",
                       "digest-username", "digest-password", "threads", "stop-at-first-match-all"}
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
BANNED_TEXT = re.compile(r"interactsh|oast\.|\{\{\s*(?:exec|file|read|read_file|generate_java_gadget|wait_for|sleep|oob)|"
                         r"\bsleep\s*\(|\bwait_for\s*\(|\bexec\s*\(|interact_?sh|collaborator", re.I)
ALLOWED_VARS = {"baseurl", "rooturl", "randstr", "hostname", "host"}   # in headers
PATH_VARS = {"baseurl", "rooturl", "randstr"}                            # in request paths
PATH_START = re.compile(r"^\{\{\s*(BaseURL|RootURL)\s*\}\}")
VAR = re.compile(r"\{\{\s*([A-Za-z0-9_\-]+)")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,120}$")
CATEGORIES = ("exposures", "exposed-panels", "misconfiguration", "technologies", "cves")
CVE_MATCHERS = {"word", "status", "regex", "size"}


@dataclass
class Verdict:
    path: str
    category: str | None = None
    template_id: str | None = None
    severity: str | None = None
    name: str | None = None
    reasons: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.reasons


def category_of(path: str) -> str | None:
    parts = [p.lower() for p in PurePosixPath(path.replace("\\", "/")).parts]
    for marker, name in (("exposures", "exposures"), ("exposed-panels", "exposed-panels"), ("misconfiguration", "misconfiguration"),
                         ("technologies", "technologies"), ("cves", "cves"), ("cve", "cves")):
        if marker in parts[:-1]:
            return name
    return None


def _walk_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value)


def _tags(info: dict) -> set[str]:
    raw = info.get("tags")
    if isinstance(raw, list):
        items = [str(x) for x in raw]
    elif isinstance(raw, str):
        items = raw.split(",")
    else:
        items = []
    return {t.strip().lower() for t in items if t and t.strip()}


def validate(text: str, path: str = "") -> Verdict:
    verdict = Verdict(path=path, category=category_of(path))
    reasons = verdict.reasons

    def reject(code):
        if code not in reasons:
            reasons.append(code)

    if len(text.encode("utf-8", "replace")) > MAX_TEMPLATE_BYTES:
        reject("size")
        return verdict
    try:
        data = nuclei_yaml.parse(text)
    except nuclei_yaml.YamlError:
        reject("unparseable")
        return verdict
    if not isinstance(data, dict):
        reject("unparseable")
        return verdict

    info = data.get("info")
    template_id = data.get("id")
    if not isinstance(template_id, str) or not ID.match(template_id) or not isinstance(info, dict) \
            or not isinstance(info.get("name"), str) or str(info.get("severity", "")).lower() not in SEVERITIES:
        reject("bad_metadata")
    else:
        verdict.template_id, verdict.severity = template_id, str(info["severity"]).lower()
        verdict.name = info["name"][:200]
    if verdict.category is None:
        reject("out_of_scope")
    tags = _tags(info) if isinstance(info, dict) else set()
    for tag in sorted(tags & BANNED_TAGS):
        reject(f"banned_tag:{tag}")

    for key in data:
        if key in PROTOCOL_KEYS:
            reject("not_http")
    requests = data.get("http", data.get("requests"))
    if not isinstance(requests, list) or not requests or not all(isinstance(r, dict) for r in requests):
        reject("not_http")
        return verdict
    for key in ("variables", "flow", "self-contained"):
        if key == "flow" and key in data:
            reject("not_http")
    if data.get("self-contained"):
        reject("unsafe_feature:self-contained")

    total_paths = 0
    any_matcher = False
    matcher_types = set()
    for request in requests:
        for key in request:
            if key in UNSAFE_REQUEST_KEYS:
                reject(f"unsafe_feature:{key}")
        if request.get("body"):
            reject("unsafe_feature:body")
        method = str(request.get("method", "GET")).upper()
        if method not in ("GET", "HEAD"):
            reject("method")
        matchers = request.get("matchers")
        if isinstance(matchers, list) and matchers:
            any_matcher = True
            for matcher in matchers:
                if isinstance(matcher, dict):
                    matcher_types.add(str(matcher.get("type", "")).lower())
        if "raw" in request:
            continue  # already rejected above; a raw request has no `path` to judge
        paths = request.get("path")
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
            reject("target")
            paths = []
        total_paths += len(paths)
        for item in paths:
            start = PATH_START.match(item)
            rest = item[start.end():] if start else ""
            if start is None or "://" in rest or any(v.lower() not in PATH_VARS for v in VAR.findall(rest)):
                reject("target")
        max_redirects = request.get("max-redirects")
        if max_redirects is not None and (not isinstance(max_redirects, int) or max_redirects > MAX_REDIRECTS):
            reject("redirects")
        # `redirects: true` cannot leave the host: Nuclei is always started with same-host redirects only (-fhr).
    if total_paths > MAX_PATHS:
        reject("too_many_requests")
    if not any_matcher:
        reject("no_matchers")
    for value in _walk_strings(data):
        if BANNED_TEXT.search(value):
            reject("banned_helper")
            break
    for request in requests:
        for value in _walk_strings(request.get("headers", {})):
            for name in VAR.findall(value):
                if name.lower() not in ALLOWED_VARS:
                    reject("banned_helper")
    if verdict.category == "cves":
        if not (isinstance(template_id, str) and re.match(r"^CVE-\d{4}-\d{4,}$", template_id, re.I)) \
                and not (isinstance(info, dict) and isinstance(data.get("info", {}).get("classification"), dict)):
            reject("bad_metadata")
        if not matcher_types or not matcher_types <= CVE_MATCHERS:
            reject("cve_not_passive")
    return verdict


def validate_file(path: Path, root: Path) -> Verdict:
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Verdict(path=relative, category=category_of(relative), reasons=["unparseable"])
    return validate(text, relative)


def manifest_hash(files: dict[str, bytes]) -> dict:
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}


def load_manifest(directory: Path) -> dict:
    return json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
