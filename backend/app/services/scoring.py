"""Security score and grade (spec section 7). Weights and grade limits live in settings.

Start at 100. Subtract per OPEN, CONFIRMED finding: Critical 25, High 10, Medium 4, Low 1 (never below 0). "Needs checking"
(possible) findings and Info findings do not count. Grades: A 90+, B 75+, C 60+, D 40+, F below 40.
A score from a scan that did not finish is marked `incomplete`: it can only be too good, never too bad.
"""
from app.core.config import settings


def weights() -> dict:
    return {"critical": settings.score_weight_critical, "high": settings.score_weight_high,
            "medium": settings.score_weight_medium, "low": settings.score_weight_low}


def grade_for(score: int) -> str:
    for letter, limit in (("A", settings.grade_a_min), ("B", settings.grade_b_min), ("C", settings.grade_c_min), ("D", settings.grade_d_min)):
        if score >= limit:
            return letter
    return "F"


def summarize(findings, *, incomplete: bool = False) -> dict:
    """`findings`: objects or dicts with severity, confidence and group. Returns score, grade and the counts."""
    def field(item, name):
        return item.get(name) if isinstance(item, dict) else getattr(item, name)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    needs_checking = 0
    for item in findings:
        severity, confidence = field(item, "severity"), field(item, "confidence")
        if confidence != "confirmed":
            needs_checking += 1
        elif severity in counts:
            counts[severity] += 1
    penalty = sum(weights()[level] * counts[level] for level in weights())
    score = max(0, 100 - penalty)
    return {"score": score, "grade": grade_for(score), "counts": counts, "needs_checking": needs_checking,
            "confirmed": sum(counts[k] for k in ("critical", "high", "medium", "low")), "incomplete": bool(incomplete),
            "weights": weights()}
