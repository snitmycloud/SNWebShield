import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildSite, pricingView, monthsFree, gstNote, planFeatures, APP_PATH } from "../site/pages.js";

const read = p => readFileSync(new URL(p, import.meta.url), "utf-8");
const config = JSON.parse(read("../site/site.config.json"));
const plans = JSON.parse(read("../../backend/app/plans.json"));
const css = read("../src/styles/tokens.css") + read("../site/site.css");
const build = (extra = {}) => buildSite({ config, plans, css, domain: "snwebshield.com", ...extra });
const files = build();
const DRAFT = "DRAFT – needs legal review";

test("landing page has the SEO basics and the sign-up / log-in buttons", () => {
  const html = files["index.html"];
  assert.match(html, /<title>[^<]{10,70}<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{50,200}"/);
  assert.match(html, /<link rel="canonical" href="https:\/\/snwebshield\.com\/">/);
  for (const og of ["og:title", "og:description", "og:image", "og:url", "twitter:card"]) assert.ok(html.includes(og), og);
  assert.ok(html.includes('type="application/ld+json"'));
  assert.ok(html.includes(`href="${APP_PATH}#/signup"`) && html.includes(`href="${APP_PATH}"`));
  assert.match(html, /<html lang="en">/);
  assert.equal((html.match(/<h1>/g) || []).length, 1);
});

test("landing page explains the four pillars, the four steps and the ownership rule", () => {
  const html = files["index.html"];
  for (const pillar of ["MONITOR", "DETECT", "VULNERABILITIES", "REPORT"]) assert.ok(html.includes(`>${pillar}<`), pillar);
  for (const step of ["Sign up", "Add your website", "Verify it is yours", "Read your report"]) assert.ok(html.includes(step), step);
  assert.ok(html.includes("We only scan websites you own"));
  assert.ok(html.includes("Does a good score mean my website is safe?"));
  assert.ok(html.includes("No. A score shows what our automated checks found. It never means a website is safe or secure."));
});

test("pricing comes from plans.json: prices, limits and 2 months free", () => {
  const view = pricingView(plans);
  assert.deepEqual(view.map(p => p.key), Object.keys(plans.plans));
  const html = files["index.html"];
  for (const [key, plan] of Object.entries(plans.plans)) {
    assert.ok(html.includes(`${plan.max_websites} websites`), key);
    assert.ok(html.includes(Number(plan.price.monthly).toLocaleString("en-IN")), key);
    assert.ok(html.includes(Number(plan.price.yearly).toLocaleString("en-IN")), key);
  }
  assert.equal(monthsFree(plans.plans.pro.price), 2);
  assert.equal(monthsFree(plans.plans.business.price), 2);
  assert.equal(monthsFree({ monthly: 0, yearly: 0 }), 0);
  assert.ok(html.includes("2 months free"));
  assert.ok(planFeatures(plans.plans.pro).includes("Full port scan"));
});

test("a changed price in plans.json changes the page (nothing is hard-coded)", () => {
  const copy = JSON.parse(JSON.stringify(plans));
  copy.plans.pro.price = { monthly: 777, yearly: 7000 };
  const html = build({ plans: copy })["index.html"];
  assert.ok(html.includes("₹777") && html.includes("₹7,000") && !html.includes("₹550"));
});

test("GST mode: none shows nothing, exclusive shows + 18% GST, inclusive says includes GST; Free never shows GST", () => {
  assert.equal(gstNote("none"), "");
  assert.equal(gstNote("exclusive"), "+ 18% GST");
  assert.equal(gstNote("inclusive"), "includes GST");
  assert.ok(!files["index.html"].includes("% GST<"));
  const ex = pricingView(plans, "exclusive");
  assert.equal(ex.find(p => p.key === "free").gst, "");
  assert.equal(ex.find(p => p.key === "pro").gst, "+ 18% GST");
  assert.ok(build({ gstMode: "exclusive" })["index.html"].includes("+ 18% GST"));
});

test("the domain is one setting: canonical, sitemap and robots follow it", () => {
  const other = build({ domain: "example.test" });
  for (const f of ["index.html", "sitemap.xml", "robots.txt"]) {
    assert.ok(other[f].includes("example.test"), f);
    assert.ok(!other[f].includes("snwebshield.com"), f);
  }
  assert.match(files["sitemap.xml"], /<loc>https:\/\/snwebshield\.com\/terms\/<\/loc>/);
  assert.match(files["robots.txt"], /Disallow: \/app\//);
});

test("three legal pages exist, are marked DRAFT and are linked from every page footer", () => {
  const pages = Object.entries(files).filter(([n]) => n.endsWith(".html")).map(([, h]) => h);
  for (const [path, title] of [["terms", "Terms of Service"], ["privacy", "Privacy Policy"], ["acceptable-use", "Acceptable Use"]]) {
    const html = files[`${path}/index.html`];
    assert.ok(html, path);
    assert.ok(html.includes(DRAFT), path);
    assert.ok(html.indexOf(DRAFT) < html.indexOf("<h1>"), "banner is above the heading");
    assert.ok(html.includes(title));
    for (const page of pages) assert.ok(page.includes(`href="/${path}/"`), `${path} linked`);
  }
  assert.ok(files["terms/index.html"].includes("[PLACEHOLDER"), "open details are visible placeholders");
});

test("company details come from the config", () => {
  const html = files["index.html"];
  assert.ok(html.includes("SNIT") && html.includes("Dilsukhnagar, Hyderabad, Telangana, India") && html.includes("nalavath08@gmail.com"));
});

test("fast: no framework or external requests, pages stay small", () => {
  for (const [name, html] of Object.entries(files).filter(([n]) => n.endsWith(".html"))) {
    assert.ok(!/<script[^>]+src=/.test(html), `${name}: no external script`);
    assert.ok(!/<link[^>]+rel="stylesheet"/.test(html), `${name}: CSS is inlined`);
    assert.ok(!/https?:\/\/(?!snwebshield\.com|schema\.org|www\.w3\.org)/.test(html), `${name}: no third-party URL`);
    assert.ok(Buffer.byteLength(html) < 60 * 1024, `${name} under 60 KB`);
  }
});

test("both themes use the shared tokens, with a theme switch and a skip link", () => {
  const html = files["index.html"];
  assert.ok(html.includes(':root[data-theme="dark"]') && html.includes("snwebshield-theme"));
  assert.ok(html.includes('id="theme"') && html.includes('class="skip"'));
});

test("text is escaped (a company name cannot inject markup)", () => {
  const html = buildSite({ config: { ...config, company: "<img src=x onerror=alert(1)>" }, plans, css, domain: "snwebshield.com" })["index.html"];
  assert.ok(!html.includes("<img src=x"));
});

test("the page carries the prices it was built with, in a tag the backend checks against plans.json", async () => {
  const { pricesMarker } = await import("../site/pages.js");
  const marker = pricesMarker(plans);
  assert.equal(marker.currency, "INR");
  for (const [key, plan] of Object.entries(plans.plans)) assert.deepEqual(marker.prices[key], [plan.price.monthly, plan.price.yearly]);
  assert.ok(files["index.html"].includes('<meta name="snwebshield-prices" content="'));
  const copy = JSON.parse(JSON.stringify(plans));
  copy.plans.pro.price.monthly = 1;
  assert.notDeepEqual(pricesMarker(copy), marker);
});
