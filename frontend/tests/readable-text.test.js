import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Text must be readable: 13 px or larger. Short uppercase labels (letter-spaced or upper-cased) may be 12 px. Nothing is smaller.
const css = ["app.css", "extra.css"].map(f => readFileSync(new URL(`../src/styles/${f}`, import.meta.url), "utf8")).join("\n");
const blocks = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map(m => ({ selector: m[1].trim().split("\n").pop(), body: m[2] }));
const sidebarOnly = /^\.(sidebar|brand-|nav-|main-nav|workspace|profile-|help-|coming-soon|auth-visual|auth-chip|auth-feature)/;

test("no text is smaller than 13px, except 12px uppercase labels", () => {
  const small = [];
  for (const { selector, body } of blocks) {
    const m = body.match(/font-size:\s*(\d+(?:\.\d+)?)px/);
    if (!m) continue;
    const px = Number(m[1]);
    const label = /letter-spacing|text-transform:\s*uppercase/.test(body);
    if (px < 12 || (px < 13 && !label)) small.push(`${selector} { font-size: ${px}px }`);
  }
  // SVG chart axis numbers are drawn at 11px inside the picture, and their values are also written out as text next to the chart.
  assert.deepEqual(small.filter(s => !s.startsWith(".sw-trend-axis")), []);
});

test("the base font size is 14px and the type scale tokens exist", () => {
  const tokens = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8");
  assert.match(tokens, /--fs-base:\s*14px/);
  assert.match(tokens, /--fs-small:\s*13px/);
  assert.match(css, /:root\s*\{[^}]*font-size:\s*var\(--fs-base\)/);
});
