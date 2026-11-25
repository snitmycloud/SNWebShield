"""Technology fingerprinting from what the website already told us: headers, cookies, `<meta>` tags, script and CSS
paths, page markers and a few known files. The rules live in `app/data/fingerprints.json` so more can be added
without a code change. A broken rule is skipped (and counted), never fatal.

Everything matched is untrusted: patterns run only on size-limited text, and evidence and versions are cut short and
stripped of control characters.
"""
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from app.services.netio import clean_text

RULES_FILE = Path(__file__).resolve().parents[1] / "data" / "fingerprints.json"
WHERES = {"header", "cookie", "meta", "html", "script", "css", "file"}
MAX_FILE_FETCHES = 6
MAX_ITEMS = 2000
MAX_HTML = 256 * 1024


@dataclass
class Rule:
    where: str
    pattern: re.Pattern
    name: str | None = None
    path: str | None = None
    version: re.Pattern | None = None


@dataclass
class Tech:
    name: str
    category: str
    rules: list[Rule]


@dataclass
class RuleSet:
    techs: list[Tech] = field(default_factory=list)
    skipped: int = 0


def load_rules(path: Path = RULES_FILE) -> RuleSet:
    result = RuleSet()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = data["technologies"]
    except (OSError, ValueError, KeyError, TypeError):
        result.skipped = 1
        return result
    for entry in entries if isinstance(entries, list) else []:
        try:
            name, category = str(entry["name"])[:80], str(entry["category"])[:60]
            rules = []
            for raw in entry["rules"]:
                where = raw["where"]
                if where not in WHERES:
                    raise ValueError("bad where")
                if where in ("header", "meta") and not raw.get("name"):
                    raise ValueError("name required")
                if where == "file" and not str(raw.get("path", "")).startswith("/"):
                    raise ValueError("path required")
                rules.append(Rule(where=where, pattern=re.compile(raw.get("pattern", "."), re.I),
                                  name=(raw.get("name") or "").lower() or None, path=raw.get("path"),
                                  version=re.compile(raw["version"], re.I) if raw.get("version") else None))
            if not rules:
                raise ValueError("no rules")
            result.techs.append(Tech(name, category, rules))
        except (KeyError, TypeError, ValueError, re.error):
            result.skipped += 1
    return result


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: list[tuple[str, str]] = []
        self.scripts: list[str] = []
        self.styles: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and values.get("name") and len(self.meta) < MAX_ITEMS:
            self.meta.append((values["name"].lower(), values.get("content", "")))
        elif tag == "script" and values.get("src") and len(self.scripts) < MAX_ITEMS:
            self.scripts.append(values["src"])
        elif tag == "link" and "stylesheet" in values.get("rel", "").lower() and len(self.styles) < MAX_ITEMS:
            self.styles.append(values.get("href", ""))


def _first(rule: Rule, text: str):
    match = rule.pattern.search(text)
    if not match:
        return None
    version = None
    if rule.version:
        found = rule.version.search(text)
        if found and found.groups():
            version = clean_text(found.group(1), 30)
    return clean_text(match.group(0), 120), version


def file_paths_needed(rules: RuleSet, detected_with_version: set) -> list[str]:
    """Paths of `file` rules worth fetching (at most MAX_FILE_FETCHES): technologies not yet known with a version."""
    paths: list[str] = []
    for tech in rules.techs:
        if tech.name in detected_with_version:
            continue
        for rule in tech.rules:
            if rule.where == "file" and rule.path not in paths and len(paths) < MAX_FILE_FETCHES:
                paths.append(rule.path)
    return paths


def detect(rules: RuleSet, page, *, files: dict | None = None, port: int | None = None) -> list[dict]:
    """Return the technologies seen on one web page. `files` maps a path to the text already fetched, for `file` rules."""
    found: dict[str, dict] = {}
    html = (page.body or "")[:MAX_HTML] if page else ""
    parsed = _Page()
    try:
        parsed.feed(html)
    except Exception:
        pass
    cookie_names = [c["name"] for c in (page.cookies if page else [])]
    def record(tech: Tech, source: str, evidence: str, version: str | None) -> None:
        item = found.setdefault(tech.name, {"name": tech.name, "category": tech.category, "version": None,
                                            "source": source, "evidence": evidence, "port": port})
        if version and not item["version"]:
            item["version"], item["source"], item["evidence"] = version, source, evidence

    for tech in rules.techs:
        for rule in tech.rules:
            if rule.where == "file":
                body = (files or {}).get(rule.path)
                if body is None or page is None or (tech.name in found and found[tech.name]["version"]):
                    continue
                hit = _first(rule, body[:MAX_HTML]) if body else None
                if hit:
                    record(tech, "file", f"{rule.path}", hit[1])
                continue
            if page is None:
                continue
            candidates: list[str] = []
            if rule.where == "header":
                value = page.headers.get(rule.name or "")
                candidates = [value] if value else []
            elif rule.where == "cookie":
                candidates = cookie_names
            elif rule.where == "meta":
                candidates = [content for name, content in parsed.meta if name == rule.name]
            elif rule.where == "script":
                candidates = parsed.scripts
            elif rule.where == "css":
                candidates = parsed.styles
            elif rule.where == "html":
                candidates = [html]
            for text in candidates:
                hit = _first(rule, text)
                if hit:
                    record(tech, rule.where, hit[0], hit[1])
                    break
    return sorted(found.values(), key=lambda item: item["name"].lower())


def merge(*lists: list[dict]) -> list[dict]:
    """Combine results from several pages (for example ports 80 and 443): one row per technology, best version wins."""
    merged: dict[str, dict] = {}
    for items in lists:
        for item in items:
            current = merged.get(item["name"])
            if current is None:
                merged[item["name"]] = dict(item)
            elif item.get("version") and not current.get("version"):
                merged[item["name"]] = dict(item)
    return sorted(merged.values(), key=lambda item: item["name"].lower())
