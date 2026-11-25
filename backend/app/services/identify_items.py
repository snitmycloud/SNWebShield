"""Turns what DETECT found into the list of 'software items' the IDENTIFY engines look up.

One item = one product (and version, if disclosed) on one place. Servers come from the banners and `Server` /
`X-Powered-By` headers; website software (PHP, WordPress, jQuery, ...) from the technology step. Everything here came
from the scanned server and is untrusted text: it is only compared with our own map and never used as a command or URL.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.services import distro

_MAP = json.loads((Path(__file__).resolve().parent.parent / "data" / "cpe_map.json").read_text(encoding="utf-8"))
_NAMES: dict[str, tuple[str, str]] = {}   # detected name -> (ecosystem, key)
for _key, _entry in _MAP["products"].items():
    for _name in _entry["names"]:
        _NAMES[_name] = ("cpe", _key)
for _key, _entry in _MAP["npm"].items():
    for _name in _entry["names"]:
        _NAMES[_name] = ("npm", _key)
_NAMES["angular"] = ("angular", "angular")
_SAFE_VERSION = re.compile(r"^\d[0-9A-Za-z.\-+~_]{0,40}$")
MAX_ITEMS = 30


@dataclass
class Item:
    ecosystem: str            # "cpe" | "npm"
    key: str                  # key in cpe_map
    display: str
    version: str | None
    port: int | None
    location: str
    context_text: str = ""    # banner / header text that carried the version (for distro detection)
    headers: dict = field(default_factory=dict)
    family: str | None = None
    proxy: bool = False

    @property
    def entry(self) -> dict:
        return _MAP["products" if self.ecosystem == "cpe" else "npm"][self.key]

    @property
    def package(self) -> str:
        return self.entry.get("package", self.key)


def entry_for(name: str | None, version: str | None = None):
    """(ecosystem, key) for a detected product name, or None if we do not know it."""
    found = _NAMES.get((name or "").strip().lower())
    if found is None:
        return None
    if found[0] == "angular":
        major = (version or "").split(".")[0]
        return ("npm", "angularjs") if major == "1" else ("npm", "angular")
    return found


def clean_version(version) -> str | None:
    text = str(version or "").strip()
    return text if _SAFE_VERSION.match(text) else None


def collect(domain: str, probes, technologies) -> list[Item]:
    items: dict[tuple, Item] = {}
    pages = {p.port: p.web for p in probes if p.web}
    web_text = " ".join(f"{page.headers.get('server', '')} {page.headers.get('x-powered-by', '')}" for page in pages.values())
    any_proxy = any(distro.behind_proxy(page.headers) for page in pages.values())

    def add(found, display_name, version, port, context, headers):
        ecosystem, key = found
        item = Item(ecosystem, key, (_MAP["products" if ecosystem == "cpe" else "npm"][key]["label"]), clean_version(version), port,
                    f"{domain}:{port}" if port else domain, context, headers)
        # JavaScript libraries and CMS software are not distribution packages and are served as-is: a server banner that
        # says "Ubuntu" says nothing about the version of jQuery or WordPress on the page.
        packaged = ecosystem == "cpe" and key != "wordpress"
        item.family = distro.detect_family(context) if packaged else None
        item.proxy = distro.behind_proxy(headers) if packaged else False
        slot = (key, item.version, port)
        existing = items.get(slot)
        if existing is None or (item.family and not existing.family):
            items[slot] = item

    for probe in probes:
        found = entry_for(probe.product, probe.version)
        if found is None:
            continue
        page = probe.web
        headers = page.headers if page else {}
        context = f"{probe.banner or ''} {headers.get('server', '')} {headers.get('x-powered-by', '')}"
        add(found, probe.product, probe.version, probe.port, context, headers)
    for tech in technologies:
        found = entry_for(tech["name"], tech.get("version"))
        if found is None:
            continue
        port = tech.get("port")
        headers = pages[port].headers if port in pages else (next(iter(pages.values())).headers if pages else {})
        context = f"{web_text} {tech.get('evidence') or ''}"
        add(found, tech["name"], tech.get("version"), port, context, headers)
        if any_proxy and not headers and found[0] == "cpe" and found[1] != "wordpress":
            items[(found[1], clean_version(tech.get("version")), port)].proxy = True
    # The same product on the same port reported twice (server banner and technology step): keep one, prefer a version.
    final: dict[tuple, Item] = {}
    for item in items.values():
        slot = (item.key, item.port)
        current = final.get(slot)
        if current is None or (item.version and not current.version):
            final[slot] = item
    result = list(final.values())
    # A technology without a port is the same software as a server on a port when product and version agree.
    result = [i for i in result if not (i.port is None and any(o.key == i.key and o.port is not None and
                                                              (o.version == i.version or i.version is None) for o in result))]
    return result[:MAX_ITEMS]
