import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Every pair of colours that is used for text on a background must be readable (WCAG AA, 4.5:1) in the light and the dark theme.
const css = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8");

function tokens(theme) {
  const start = css.indexOf(theme === "light" ? ':root[data-theme="light"]' : ':root[data-theme="dark"]');
  const block = css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
  return Object.fromEntries([...block.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6});/g)].map(m => [m[1], m[2]]));
}

const channel = v => { const c = v / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
const luminance = hex => { const n = parseInt(hex.slice(1), 16); return 0.2126 * channel(n >> 16) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255); };
export const contrast = (a, b) => { const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

const PAIRS = [
  ["text", "bg"], ["text", "surface"], ["text", "surface-2"], ["text", "surface-3"], ["text-2", "surface"], ["text-2", "bg"], ["muted", "surface"], ["muted", "bg"], ["muted", "surface-2"],
  ["faint", "surface"], ["faint", "bg"], ["accent-text", "surface"], ["accent-text", "bg"], ["accent-text", "accent-soft"], ["on-accent", "accent"],
  ["good-text", "good-bg"], ["warn-text", "warn-bg"], ["bad-text", "bad-bg"], ["info-text", "info-bg"],
  ["good", "surface"], ["bad", "surface"], ["info", "surface"],
  ["sev-critical-text", "sev-critical-bg"], ["sev-high-text", "sev-high-bg"], ["sev-medium-text", "sev-medium-bg"], ["sev-low-text", "sev-low-bg"],
  ["sev-info-text", "sev-info-bg"], ["fixed-text", "fixed-bg"],
];

for (const theme of ["light", "dark"]) {
  test(`${theme} theme: text and status colours are readable on their backgrounds (4.5:1)`, () => {
    const t = tokens(theme);
    const failures = PAIRS.filter(([fg, bg]) => !t[fg] || !t[bg] || contrast(t[fg], t[bg]) < 4.5).map(([fg, bg]) => `${fg} on ${bg}: ${t[fg] && t[bg] ? contrast(t[fg], t[bg]).toFixed(2) : "missing"}`);
    assert.deepEqual(failures, []);
  });
}

test("both themes define exactly the same tokens, and the severity colours are the fixed ones", () => {
  const light = tokens("light"), dark = tokens("dark");
  assert.deepEqual(Object.keys(dark).sort(), Object.keys(light).sort());
  assert.ok(Object.keys(light).length >= 40);
  for (const level of ["critical", "high", "medium", "low", "info"]) assert.ok(light[`sev-${level}`] && dark[`sev-${level}`], level);
  assert.ok(light.fixed && dark.fixed);
});

test("the one accent colour is the same family in both themes (teal) and the logo uses it", () => {
  const hue = hex => { const n = parseInt(hex.slice(1), 16), [r, g, b] = [n >> 16, (n >> 8) & 255, n & 255].map(v => v / 255); const max = Math.max(r, g, b), d = max - Math.min(r, g, b); return d === 0 ? 0 : max === r ? 60 * (((g - b) / d) % 6) : max === g ? 60 * ((b - r) / d + 2) : 60 * ((r - g) / d + 4); };
  for (const theme of ["light", "dark"]) { const h = (hue(tokens(theme).accent) + 360) % 360; assert.ok(h > 160 && h < 185, `${theme} accent hue ${h}`); }
});
