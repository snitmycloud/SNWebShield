"""The editable list of SENSITIVE login/admin pages (app/data/nuclei/sensitive_panels.json).

Used by the built-in login-page check and by the Nuclei engine, so one list decides what is Medium and what stays Info.
A broken or missing file means "nothing is sensitive": it never crashes a scan and never invents a finding.
"""
import json
from pathlib import Path

SENSITIVE_PATH = Path(__file__).resolve().parent.parent / "data" / "nuclei" / "sensitive_panels.json"


def load_sensitive() -> list[tuple[str, list[str]]]:
    """[(label, [lowercase match texts])]."""
    try:
        rows = json.loads(SENSITIVE_PATH.read_text(encoding="utf-8")).get("sensitive", [])
        return [(str(r["label"]), [str(m).lower() for m in r["match"] if str(m).strip()]) for r in rows if isinstance(r, dict)]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return []


def sensitive_label(template_id: str, name: str, rules=None) -> str | None:
    """The label of the first rule whose text appears in the id or name (case-insensitive), else None."""
    text = f"{template_id} {name}".lower()
    for label, needles in (load_sensitive() if rules is None else rules):
        if any(needle in text for needle in needles):
            return label
    return None
