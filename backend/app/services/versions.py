"""Version parsing and comparison for the kinds of version strings servers report: 2.4.7, 6.6.1p1, 1.18.0, 7.4.3, 10.0.

A version is split into numbers and letters. Numbers compare numerically; trailing zeros do not matter (1.0 == 1.0.0).
A pre-release marker (alpha, beta, rc, dev, pre) sorts BEFORE the plain version; any other letters (such as the 'p'
of OpenSSH's 6.6.1p1, a portable patch release) sort AFTER it. A string that does not look like a version returns None,
and callers then treat the match as unverified instead of guessing.
"""
import re

_VALID = re.compile(r"^v?\d+(\.\d+)*([._+~-]?[A-Za-z0-9]+)*$")
_TOKENS = re.compile(r"\d+|[A-Za-z]+")
_PRE = {"dev": -4, "snapshot": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "pre": -1, "rc": -1, "preview": -1}
_ZERO = (1, 0, "")


def parse(version) -> tuple | None:
    text = str(version or "").strip().lower()
    if not text or len(text) > 64 or not _VALID.match(text):
        return None
    key = []
    for token in _TOKENS.findall(text.lstrip("v")):
        if token.isdigit():
            key.append((1, int(token), ""))
        elif token in _PRE:
            key.append((0, _PRE[token], ""))
        else:
            key.append((2, 0, token))
    while key and key[-1] == _ZERO:  # 1.0.0 == 1.0
        key.pop()
    return tuple(key)


def compare(a, b) -> int | None:
    left, right = parse(a), parse(b)
    if left is None or right is None:
        return None
    for index in range(max(len(left), len(right))):
        x = left[index] if index < len(left) else _ZERO
        y = right[index] if index < len(right) else _ZERO
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range(version, *, start_including=None, start_excluding=None, end_including=None, end_excluding=None) -> bool | None:
    """True/False if the version is inside the range, None if any version involved cannot be compared."""
    checks = ((start_including, lambda c: c >= 0), (start_excluding, lambda c: c > 0),
              (end_including, lambda c: c <= 0), (end_excluding, lambda c: c < 0))
    for bound, test in checks:
        if bound is None:
            continue
        result = compare(version, bound)
        if result is None:
            return None
        if not test(result):
            return False
    return True


def describe_range(start_including=None, start_excluding=None, end_including=None, end_excluding=None, exact=None) -> str:
    if exact:
        return f"= {exact}"
    parts = []
    if start_including:
        parts.append(f">= {start_including}")
    if start_excluding:
        parts.append(f"> {start_excluding}")
    if end_including:
        parts.append(f"<= {end_including}")
    if end_excluding:
        parts.append(f"< {end_excluding}")
    return ", ".join(parts) or "all versions"
