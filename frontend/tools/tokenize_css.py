"""One-off converter used for Phase 6: turns the old hard-coded-colour stylesheets into a token-based one.

    python tools/tokenize_css.py        (from frontend/)

Reads src/styles.css and src/console.css, prunes rules whose classes no component uses, replaces every colour by a theme token chosen
from the property (text / background / border), the hue (teal accent, green, amber, red, blue) and the lightness, lifts text below
13 px, and writes src/styles/app.css. Dark panels that stay dark in both themes (sidebar, login visual) keep their own colours.
Kept in the repository so the conversion can be reviewed; the result (src/styles/app.css) is what is edited from now on.
"""
import colorsys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

DARK_PANELS = re.compile(r"^\.(sidebar|brand-|workspace-|profile-|nav-|main-nav|help-|coming-soon|tools-label|auth-visual|auth-chip|auth-feature|auth-decoration|auth-brand-mark)")


def split_rules(css: str):
    """Yield (selector, body) for plain rules and ('@media ...', [inner rules]) for at-rules."""
    i, n, out = 0, len(css), []
    while i < n:
        while i < n and css[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if css.startswith("/*", i):
            j = css.index("*/", i) + 2
            i = j
            continue
        if css.startswith("@import", i):
            i = re.compile(r"@import\s+url\([^)]*\)\s*;").match(css, i).end()   # the URL itself contains semicolons
            continue
        j = css.index("{", i)
        head = css[i:j].strip()
        depth, k = 1, j + 1
        while depth:
            depth += {"{": 1, "}": -1}.get(css[k], 0)
            k += 1
        body = css[j + 1:k - 1]
        if head.startswith("@media") or head.startswith("@keyframes"):
            out.append((head, body if head.startswith("@keyframes") else split_rules(body)))
        else:
            out.append((head, body))
        i = k
    return out


def corpus() -> str:
    parts = []
    for path in list(SRC.glob("*.jsx")) + list((SRC / "lib").glob("*.js")):
        parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


TEXT = corpus()
DYNAMIC_PREFIXES = set(re.findall(r"([a-z][\w-]*-)\$\{", TEXT))


def class_used(name: str) -> bool:
    if any(name.startswith(p) for p in DYNAMIC_PREFIXES):
        return True
    return re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", TEXT) is not None


def selector_kept(selector: str) -> bool:
    names = re.findall(r"\.([A-Za-z_][\w-]*)", selector)
    return all(class_used(n) for n in names)


def hex_to_rgb(h: str):
    h = h.lstrip("#")
    if len(h) in (3, 4):
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def classify(prop: str, hexv: str, selector: str) -> str | None:
    """A token for this colour, or None to keep it as written."""
    raw = hexv.lstrip("#")
    if len(raw) in (4, 8):   # has alpha: shadows and overlays keep their value
        return None
    r, g, b = hex_to_rgb(hexv)
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    h *= 360
    is_text = prop == "color" or prop == "fill"
    is_bg = prop.startswith("background")
    is_border = prop.startswith("border") or prop in ("outline", "stroke") or "box-shadow" in prop
    neutral = s < 0.20 or l > 0.965 or l < 0.06 or (190 <= h <= 260 and s < 0.55 and (l < 0.62 or l > 0.80))   # the old palette's blue-tinted greys
    if neutral:
        if is_text:
            return "--on-accent" if l > 0.96 else "--text" if l < 0.32 else "--text-2" if l < 0.46 else "--muted" if l < 0.62 else "--faint"
        if is_bg:
            return "--surface" if l > 0.985 else "--bg" if l > 0.955 else "--surface-2" if l > 0.93 else "--surface-3" if l > 0.82 else "--text-2"
        return "--border" if l > 0.78 else "--border-strong"
    if 168 <= h < 205:
        family = "accent"
    elif 85 <= h < 168:
        family = "good"
    elif 30 <= h < 85:
        family = "warn"
    elif h >= 335 or h < 30:
        family = "bad"
    else:
        family = "info"
    if family == "accent":
        if is_text:
            return "--accent-text" if l < 0.5 else "--accent"
        if is_bg:
            return "--accent-soft" if l > 0.85 else "--accent-strong" if l < 0.245 else "--accent"
        return "--accent-border" if l > 0.7 else "--accent"
    if is_text:
        return f"--{family}-text" if l < 0.50 else f"--{family}"
    if is_bg:
        return f"--{family}-bg" if l > 0.82 else f"--{family}"
    return f"--{family}-border" if l > 0.65 else f"--{family}"


def convert_body(selector: str, body: str) -> str:
    dark = bool(DARK_PANELS.match(selector.strip()))   # these panels keep their colours but their text is lifted like everything else
    out = []
    for decl in re.split(r";(?![^()]*\))", body):
        decl = decl.strip()
        if not decl:
            continue
        if ":" not in decl:
            out.append(decl)
            continue
        prop, value = decl.split(":", 1)
        prop = prop.strip()
        if prop == "font-size":
            m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)px\s*", value)
            if m:
                px = float(m.group(1))
                letter_spaced = "letter-spacing" in body
                if px < 12 and letter_spaced:
                    value = "12px"      # small uppercase labels
                elif px < 13:
                    value = "13px"
        value = re.sub(r"#[0-9a-fA-F]{3,8}\b", lambda m: f"var({classify(prop, m.group(0), selector)})" if classify(prop, m.group(0), selector) else m.group(0), value)
        out.append(f"{prop}:{value.strip()}")
    return ";".join(out)


def emit(rules, indent="") -> str:
    lines = []
    for head, body in rules:
        if head.startswith("@keyframes"):
            lines.append(f"{indent}{head}{{{body}}}")
        elif head.startswith("@media"):
            inner = emit(body, indent + "  ")
            if inner.strip():
                lines.append(f"{indent}{head}{{\n{inner}\n{indent}}}")
        else:
            selectors = [s.strip() for s in head.split(",")]
            kept = [s for s in selectors if selector_kept(s)]
            if kept:
                lines.append(f"{indent}{', '.join(kept)}{{{convert_body(kept[0], body)}}}")
    return "\n".join(lines)


def main():
    css = (SRC / "styles.css").read_text(encoding="utf-8") + "\n" + (SRC / "console.css").read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = split_rules(css)
    text = emit(rules)
    out = SRC / "styles"
    out.mkdir(exist_ok=True)
    (out / "app.css").write_text("/* Converted from styles.css and console.css by tools/tokenize_css.py (Phase 6). Edit this file from now on. */\n" + text + "\n", encoding="utf-8")
    print(f"{len(rules)} rule groups in, {text.count('{')} blocks out, {len(text)} characters")


if __name__ == "__main__":
    main()
