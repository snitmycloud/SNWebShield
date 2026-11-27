import { test } from "node:test";
import assert from "node:assert/strict";
import { applyTheme, otherTheme, readStoredTheme, resolveTheme, storeTheme, THEME_KEY } from "../src/lib/theme.js";
import { buildPillars, latestReports, monitorPillar, detectPillar, vulnerabilitiesPillar } from "../src/lib/pillars.js";

const site = (id, over = {}) => ({ id, domain: `site${id}.example.com`, verification_status: "verified", uptime: { status: "up", certificate_days_left: 90 },
  detect: { open_ports: 2, technologies: 3, complete: true }, summary: { score: 80, grade: "B", counts: { critical: 0, high: 1, medium: 2, low: 0 }, needs_checking: 4, scanned_at: `2026-11-2${id}T10:00:00Z` }, ...over });

test("the theme follows the stored choice, else the system, and survives blocked storage", () => {
  assert.equal(resolveTheme("dark", false), "dark");
  assert.equal(resolveTheme("light", true), "light");
  assert.equal(resolveTheme(null, true), "dark");
  assert.equal(resolveTheme("purple", false), "light");
  assert.equal(otherTheme("light"), "dark");
  const memory = { data: {}, getItem(k) { return this.data[k] ?? null; }, setItem(k, v) { this.data[k] = v; } };
  assert.equal(storeTheme("dark", memory), true);
  assert.equal(readStoredTheme(memory), "dark");
  assert.equal(memory.data[THEME_KEY], "dark");
  const blocked = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } };
  assert.equal(readStoredTheme(blocked), null);
  assert.equal(storeTheme("dark", blocked), false);
  const root = { dataset: {}, style: {} };
  applyTheme("dark", root);
  assert.equal(root.dataset.theme, "dark");
  assert.equal(root.style.colorScheme, "dark");
});

test("MONITOR counts sites up and down and lists certificates ending within 14 days, soonest first", () => {
  const p = monitorPillar([site(1), site(2, { uptime: { status: "down", certificate_days_left: 40 } }), site(3, { uptime: { status: "up", certificate_days_left: 9 } }),
    site(4, { uptime: { status: "up", certificate_days_left: 3 } }), site(5, { verification_status: "unverified" })]);
  assert.equal(p.sites, 4);
  assert.equal(p.up, 3); assert.equal(p.down, 1);
  assert.equal(p.headline, "1 down"); assert.equal(p.tone, "bad");
  assert.deepEqual(p.expiring.map(x => [x.id, x.days]), [[4, 3], [3, 9]]);
  assert.deepEqual(p.link, { id: 2, tab: "monitor" });   // a down site is the first thing to look at
  assert.equal(monitorPillar([]).headline, "No verified websites yet");
  assert.equal(monitorPillar([site(1, { uptime: null })]).headline, "Not checked yet");
});

test("DETECT sums open ports and technologies of the latest scans and links to the site with most open ports", () => {
  const p = detectPillar([site(1), site(2, { detect: { open_ports: 7, technologies: 1, complete: false } }), site(3, { detect: null })]);
  assert.equal(p.ports, 9); assert.equal(p.technologies, 4); assert.equal(p.scanned, 2); assert.equal(p.incomplete, 1);
  assert.deepEqual(p.link, { id: 2, tab: "detect" });
  assert.equal(detectPillar([site(1, { detect: null })]).headline, "Not scanned yet");
});

test("VULNERABILITIES sums confirmed findings by severity and links to the worst website", () => {
  const p = vulnerabilitiesPillar([site(1), site(2, { summary: { counts: { critical: 1, high: 0, medium: 0, low: 0 }, needs_checking: 0, scanned_at: "2026-11-22T10:00:00Z" } })]);
  assert.deepEqual(p.counts, { critical: 1, high: 1, medium: 2, low: 0 });
  assert.equal(p.confirmed, 4); assert.equal(p.needsChecking, 4); assert.equal(p.tone, "bad");
  assert.deepEqual(p.link, { id: 2, tab: "vulnerabilities" });
  assert.equal(vulnerabilitiesPillar([site(1, { summary: { counts: { critical: 0, high: 0, medium: 0, low: 0 }, needs_checking: 0 } })]).headline, "No confirmed findings");
  assert.equal(vulnerabilitiesPillar([]).headline, "Not scanned yet");
});

test("REPORT lists each website's latest report, newest first, and the dashboard always has four cards", () => {
  const list = latestReports([site(1), site(3), site(2), site(4, { summary: null })]);
  assert.deepEqual(list.map(r => r.id), [3, 2, 1]);
  assert.deepEqual(buildPillars([site(1)]).map(p => p.key), ["monitor", "detect", "vulnerabilities", "report"]);
  assert.deepEqual(buildPillars(null).map(p => p.key), ["monitor", "detect", "vulnerabilities", "report"]);
  assert.equal(buildPillars([site(1)])[3].link.tab, "report");
});
