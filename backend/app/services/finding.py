"""The one finding format every check and engine produces (built-in checks, NVD/OSV, end-of-life, later Nuclei).

Rules:
* `confidence` is "confirmed" (we verified it ourselves) or "possible" (needs a human check, e.g. a distro backport may
  have fixed it). Only confirmed, non-info findings are `scored`. Possible findings go to the "Needs checking" group.
* A finding never means "safe": the absence of findings is "No findings from these checks".
* All text that came from a scanned server or an outside database is untrusted data; it is stored and shown as plain text.
"""
import hashlib
from dataclasses import dataclass, field, asdict

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCES = ("confirmed", "possible")
KINDS = ("config", "vulnerability", "lifecycle", "exposure", "disclosure")
MAX_TEXT = 2000


def _clip(value, limit=MAX_TEXT):
    return None if value is None else str(value)[:limit]


@dataclass
class Finding:
    kind: str
    check_id: str
    title: str
    location: str
    severity: str = "info"
    confidence: str = "confirmed"
    port: int | None = None
    you_have: str | None = None
    you_should_have: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_range: str | None = None
    first_fixed: str | None = None
    why: str | None = None
    how_to_fix: str | None = None
    evidence: str | None = None
    caveat: str | None = None
    sources: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in RANK:
            self.severity = "info"
        if self.confidence not in CONFIDENCES:
            self.confidence = "possible"
        for name in ("title", "location", "you_have", "you_should_have", "affected_range", "first_fixed", "why",
                     "how_to_fix", "evidence", "caveat"):
            setattr(self, name, _clip(getattr(self, name)))
        self.sources = sorted({str(s)[:40] for s in self.sources})

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.check_id}|{self.location}".encode()).hexdigest()

    @property
    def group(self) -> str:
        return "findings" if self.confidence == "confirmed" else "needs_checking"

    @property
    def scored(self) -> bool:
        return self.confidence == "confirmed" and self.severity != "info"

    def as_dict(self) -> dict:
        data = asdict(self)
        data.update(fingerprint=self.fingerprint, group=self.group, scored=self.scored)
        return data


def sort_key(finding: Finding):
    return (RANK[finding.severity], finding.group != "findings", -(finding.cvss_score or 0), finding.title)


def merge(findings: list[Finding]) -> list[Finding]:
    """Remove duplicates: the same issue on the same location reported by several engines.

    Two findings are the same when they share a location and either the same CVE id or the same check id. The merged
    finding unions the sources, takes the stronger confidence, and keeps the more severe rating (a CVSS-based one wins).
    """
    merged: dict[tuple, Finding] = {}
    for item in findings:
        key = (item.location, item.cve_id or item.check_id)
        current = merged.get(key)
        if current is None:
            merged[key] = item
            continue
        current.sources = sorted(set(current.sources) | set(item.sources))
        if item.confidence == "confirmed":
            current.confidence = "confirmed"
            current.caveat = None if not item.caveat else current.caveat
        if RANK[item.severity] < RANK[current.severity] or (item.cvss_score or 0) > (current.cvss_score or 0):
            for name in ("severity", "cvss_score", "cvss_vector"):
                setattr(current, name, getattr(item, name))
        for name in ("you_have", "you_should_have", "first_fixed", "why", "how_to_fix", "affected_range", "evidence"):
            if not getattr(current, name):
                setattr(current, name, getattr(item, name))
    return sorted(merged.values(), key=sort_key)


def counts(findings) -> dict:
    """Counts by severity for the scored findings, and the number needing a check."""
    result = {name: 0 for name in SEVERITIES}
    needs = 0
    for item in findings:
        if item.group == "needs_checking":
            needs += 1
        elif item.severity != "info":
            result[item.severity] += 1
        else:
            result["info"] += 1
    result["needs_checking"] = needs
    return result
