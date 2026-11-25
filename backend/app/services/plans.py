"""Plan limits, read from the single file `app/plans.json` (edit the numbers there; no code change needed).

The file is re-read whenever it changes on disk, so a running server picks up new numbers without a restart.
A missing or broken file fails closed: no plan is known, so limited actions are refused with a clear message.
"""
import json
from pathlib import Path
from threading import Lock

from fastapi import HTTPException

PLANS_FILE = Path(__file__).resolve().parents[1] / "plans.json"
_cache: dict = {"mtime": None, "data": None}
_lock = Lock()


def load(path: Path = PLANS_FILE) -> dict:
    with _lock:
        mtime = path.stat().st_mtime_ns
        if _cache["mtime"] != mtime or _cache.get("path") != path:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data.get("plans"), dict) or data.get("default_plan") not in data["plans"]:
                raise ValueError("plans.json must define 'plans' and a valid 'default_plan'")
            for name, plan in data["plans"].items():
                if not isinstance(plan.get("max_websites"), int) or plan["max_websites"] < 0:
                    raise ValueError(f"plan '{name}' needs a whole-number max_websites")
            _cache.update(mtime=mtime, data=data, path=path)
        return _cache["data"]


def names() -> list[str]:
    return list(load()["plans"])


def default_plan() -> str:
    return load()["default_plan"]


def get(name: str) -> dict:
    try:
        plans = load()["plans"]
    except (OSError, ValueError) as error:
        raise HTTPException(503, "Plan settings could not be read. Please try again later.") from error
    plan = plans.get(name)
    if plan is None:
        raise HTTPException(503, "Your plan could not be found. Please contact support.")
    return {"name": name, **plan}


def limit_reached(plan: dict, what: str, limit: int) -> HTTPException:
    """The friendly 'upgrade' response the frontend turns into a message with an Upgrade button."""
    return HTTPException(402, {
        "code": "plan_limit",
        "limit": what,
        "max": limit,
        "plan": plan["name"],
        "plan_label": plan["label"],
        "message": f"Your {plan['label']} plan includes up to {limit} {what}. Upgrade to add more.",
    })
