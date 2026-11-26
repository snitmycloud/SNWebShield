"""CVSS v3.x base score from a vector string, and the severity bands used everywhere in the product.

Implemented from the FIRST CVSS v3.1 specification (no extra package). CVSS v2 and v4 vectors are not computed here:
NVD supplies those scores itself, and an unsupported vector returns None so the caller falls back to another source.
Bands (product spec 5.5): >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low, 0 info.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """The v3.1 'Roundup': the smallest number with one decimal that is >= value, robust to float error."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Base score for 'CVSS:3.0/...' or 'CVSS:3.1/...', or None if the vector is not a valid v3 vector."""
    try:
        parts = vector.strip().split("/")
        if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
            return None
        metrics = dict(part.split(":", 1) for part in parts[1:])
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        privileges = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[metrics["UI"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    except (KeyError, ValueError, IndexError, AttributeError):
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(total, 10.0))


def severity_from_score(score) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# Qualitative labels some databases give instead of a score (GitHub advisories use MODERATE).
LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def severity_from_label(label) -> str | None:
    return LABELS.get(str(label or "").strip().upper())
