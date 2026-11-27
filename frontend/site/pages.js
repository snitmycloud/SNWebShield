// Builds the public pages (landing, Terms, Privacy, Acceptable Use, robots.txt, sitemap.xml) as plain HTML strings.
// No JavaScript framework and no extra requests: CSS is inlined, the only script is a few lines for the theme and the price switch.
// Pure functions (unit-tested in tests/site.test.js). vite.config.js writes the result into dist/.
import { legalPages, DRAFT_NOTICE } from "./legal.js";

export const APP_PATH = "/app/";
const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const inr = n => "₹" + Number(n).toLocaleString("en-IN");

export const SHIELD = `<svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><path d="M16 2.2 4.5 6.6v8.1c0 7.1 4.8 12.7 11.5 15.1 6.7-2.4 11.5-8 11.5-15.1V6.6L16 2.2Z" fill="var(--accent)"/><path d="m10.6 16.3 3.9 3.9 7-7.7" fill="none" stroke="var(--on-accent)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

const THEME_SCRIPT = `(function(){var t=null;try{t=localStorage.getItem("snwebshield-theme")}catch(e){}if(t!=="light"&&t!=="dark")t=matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";document.documentElement.dataset.theme=t;document.documentElement.style.colorScheme=t})();`;
const PAGE_SCRIPT = `(function(){var d=document,r=d.documentElement;var b=d.getElementById("theme");if(b)b.addEventListener("click",function(){var n=r.dataset.theme==="dark"?"light":"dark";r.dataset.theme=n;r.style.colorScheme=n;try{localStorage.setItem("snwebshield-theme",n)}catch(e){}b.setAttribute("aria-label","Switch to "+(n==="dark"?"light":"dark")+" theme")});var bs=d.querySelectorAll("[data-billing-btn]");for(var i=0;i<bs.length;i++)bs[i].addEventListener("click",function(e){var v=e.currentTarget.getAttribute("data-billing-btn");d.body.setAttribute("data-billing",v);for(var j=0;j<bs.length;j++)bs[j].setAttribute("aria-pressed",bs[j]===e.currentTarget?"true":"false")})})();`;
const MOON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>`;

// ---- pricing, from plans.json ----
export function gstNote(mode, percent = 18) {
  return mode === "exclusive" ? `+ ${percent}% GST` : mode === "inclusive" ? "includes GST" : "";
}

// "2 months free": the months you do not pay for when you choose yearly (12 minus yearly price / monthly price).
export function monthsFree(price) {
  if (!price || !price.monthly || !price.yearly) return 0;
  return Math.max(0, Math.round(12 - price.yearly / price.monthly));
}

export function planFeatures(plan) {
  const every = plan.automatic_scan === "daily" ? "every day" : plan.automatic_scan === "weekly" ? "every week" : plan.automatic_scan;
  const manual = plan.manual_scans_per === "website" ? `${plan.manual_scans_per_day} manual scan per website per day` : `${plan.manual_scans_per_day} manual scans per day`;
  const list = [
    `${plan.max_websites} website${plan.max_websites === 1 ? "" : "s"}`,
    `Automatic scan ${every}`,
    manual,
    `Uptime and certificate monitoring`,
    plan.full_port_scan ? "Full port scan" : "Common ports scan (top 1000)",
    `${plan.history_days} days of history`,
    `${plan.rechecks_per_day} rechecks per day`,
    "Email alerts",
  ];
  if (plan.pdf_report) list.push("PDF reports");
  return list;
}

export function pricingView(plansData, gstMode = "none", gstPercent = 18) {
  const note = gstNote(gstMode, gstPercent);
  return Object.entries(plansData.plans).map(([key, plan]) => {
    const price = plan.price || { monthly: 0, yearly: 0 };
    const free = !price.monthly;
    return {
      key, label: plan.label, free, features: planFeatures(plan), gst: free ? "" : note,
      monthly: inr(price.monthly), yearly: inr(price.yearly), freeMonths: monthsFree(price), featured: key === "pro",
    };
  });
}

// ---- shared page parts ----
function head({ title, description, canonical, siteUrl, ogImage, extra = "", noindex = false }) {
  return `<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(canonical)}">
${noindex ? '<meta name="robots" content="noindex">' : ""}<meta name="theme-color" content="#0f766e">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta property="og:type" content="website"><meta property="og:site_name" content="SNwebshield">
<meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${esc(canonical)}"><meta property="og:image" content="${esc(ogImage)}">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}"><meta name="twitter:image" content="${esc(ogImage)}">
<script>${THEME_SCRIPT}</script>
<style>@@CSS@@</style>${extra}</head>`;
}

function header(c) {
  return `<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="wrap"><a class="brand" href="/">${SHIELD}<span>${esc(c.product)}</span></a>
<nav class="main" aria-label="Main"><a class="link" href="/#how">How it works</a><a class="link" href="/#pricing">Pricing</a><a class="link" href="/#faq">FAQ</a>
<a class="link" href="${APP_PATH}">Log in</a><a class="btn small" href="${APP_PATH}#/signup">Sign up free</a>
<button id="theme" class="theme-btn" type="button" aria-label="Switch theme" title="Switch theme">${MOON}</button></nav></div></header>`;
}

function footer(c, domain) {
  return `<footer><div class="wrap"><div class="cols"><div><strong>${esc(c.product)}</strong> · ${esc(c.tagline)}<br>
${esc(c.company)}, ${esc(c.address)}<br><a href="mailto:${esc(c.contactEmail)}">${esc(c.contactEmail)}</a> · ${esc(domain)}</div>
<nav aria-label="Legal"><a href="/terms/">Terms of Service</a><a href="/privacy/">Privacy Policy</a><a href="/acceptable-use/">Acceptable Use</a></nav></div>
<p>${DRAFT_NOTICE} (legal pages). © ${new Date().getUTCFullYear()} ${esc(c.company)}. ${esc(c.product)} reports what automated checks found; it never promises a website is safe.</p></div></footer>`;
}

const page = (headHtml, body) => `<!doctype html>\n<html lang="en">${headHtml}<body data-billing="monthly">${body}<script>${PAGE_SCRIPT}</script></body></html>\n`;

// ---- landing ----
const PILLARS = [
  ["MONITOR", "Know when it breaks", "Checks that your website answers every few minutes and tells you when it goes down and when it is back. Watches your HTTPS certificate and warns you before it expires."],
  ["DETECT", "See what you expose", "Finds the open ports and the technologies your website shows to the internet, so you know exactly what an outsider sees."],
  ["VULNERABILITIES", "Find real weaknesses", "Runs safe, checked tests for common problems, sorted from Critical to Low. Each finding says what it is and how to fix it, and a recheck confirms the fix."],
  ["REPORT", "Share a clear report", "A score and plain-language report for every scan, with what is new, fixed or unchanged since last time. Download it as a PDF."],
];
const STEPS = [
  ["Sign up", "Create a free account with your email."],
  ["Add your website", "Enter your domain. Nothing is scanned yet."],
  ["Verify it is yours", "Add a DNS record, upload a file or add a meta tag. Only then does the first scan start."],
  ["Read your report", "Get your score, your findings and alerts when something changes."],
];
const FAQ = [
  ["Do you scan any website I type in?", "No. We only scan websites you own. You must prove ownership first (a DNS record, a file or a meta tag), and we check it again before every scan. If you lose control of the website, scans stop. Nothing is scanned just because you registered."],
  ["Does a good score mean my website is safe?", "No. A score shows what our automated checks found. It never means a website is safe or secure. If a check fails or times out, we say “could not check”, never “clean”."],
  ["Will a scan harm or slow down my website?", "Scans are gentle and rate-limited, run from one fixed address, and stop automatically if something goes wrong. They only touch the website you verified."],
  ["What do you check?", "Open ports, the technologies your site shows, security headers, HTTPS and certificates, exposed files, and known weaknesses in the software we can identify. Uptime and certificate expiry are watched all the time."],
  ["Do I need to install anything?", "No. Everything runs from your browser. You only add a DNS record, a small file or a meta tag to prove ownership."],
  ["What does the Free plan include?", "Up to 5 websites with a weekly automatic scan, uptime and certificate monitoring, reports and email alerts. No card needed."],
  ["What happens if I cancel or a payment fails?", "You return to the Free plan. Your data is kept. Websites above the Free limit become read-only (no new scans or monitoring) and are never deleted. You choose which ones stay active."],
  ["Who can see my results?", "Only you. We do not sell data. See the Privacy Policy for details."],
];

function jsonLd(c, base, view) {
  return `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org", "@type": "SoftwareApplication", name: c.product, applicationCategory: "SecurityApplication", operatingSystem: "Web",
    url: base + "/", description: "Monitors, detects, validates and protects the security of websites you own.",
    publisher: { "@type": "Organization", name: c.company },
    offers: view.map(p => ({ "@type": "Offer", name: p.label, price: String(p.monthly.replace(/[^\d]/g, "")), priceCurrency: "INR" })),
  }).replace(/</g, "\\u003c")}</script>`;
}

function landingBody(c, domain, view, gstMode) {
  const cards = PILLARS.map(([tag, title, text]) => `<article class="card"><span class="pillar-tag">${tag}</span><h3>${title}</h3><p>${text}</p></article>`).join("");
  const steps = STEPS.map(([title, text], i) => `<article class="card"><div class="step-num" aria-hidden="true">${i + 1}</div><h3>${title}</h3><p>${text}</p></article>`).join("");
  const plans = view.map(p => `<article class="card plan${p.featured ? " featured" : ""}"><h3>${esc(p.label)}</h3>
<p class="price"><span class="monthly">${p.monthly}</span><span class="yearly">${p.yearly}</span> <small><span class="monthly">${p.free ? "forever" : "/ month"}</span><span class="yearly">${p.free ? "forever" : "/ year"}</span></small></p>
<p class="saving yearly-note">${p.freeMonths ? `<span class="yearly">${p.freeMonths} months free</span><span class="monthly">or ${p.yearly} / year (${p.freeMonths} months free)</span>` : ""}</p>
<p class="gst">${esc(p.gst)}</p>
<ul>${p.features.map(f => `<li>${esc(f)}</li>`).join("")}</ul>
<a class="btn${p.featured ? "" : " secondary"}" href="${APP_PATH}#/signup">${p.free ? "Start free" : `Choose ${esc(p.label)}`}</a></article>`).join("");
  const faq = FAQ.map(([q, a]) => `<details><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join("");
  return `${header(c)}<main id="main">
<section class="hero"><div class="wrap"><div class="eyebrow">${esc(c.tagline)}</div>
<h1>Know how secure your website really is</h1>
<p class="lead">${esc(c.product)} watches your websites, finds what is exposed, checks for real weaknesses and gives you a clear report. In plain language, for websites you own.</p>
<div class="cta"><a class="btn" href="${APP_PATH}#/signup">Sign up free</a><a class="btn secondary" href="${APP_PATH}">Log in</a></div>
<p class="promise">We only scan websites you own. Ownership is verified before every scan.</p></div></section>
<section class="block alt" id="pillars"><div class="wrap"><div class="section-head"><h2>Four things, done well</h2><p>One place to watch, detect, validate and report on your website’s security.</p></div><div class="grid four">${cards}</div></div></section>
<section class="block" id="how"><div class="wrap"><div class="section-head"><h2>How it works</h2><p>From sign-up to your first report in a few minutes.</p></div><div class="grid steps">${steps}</div></div></section>
<section class="block alt" id="pricing"><div class="wrap"><div class="section-head"><h2>Simple pricing</h2><p>Start free. Upgrade when you need more websites or daily scans.</p></div>
<div class="billing" role="group" aria-label="Billing period"><button type="button" data-billing-btn="monthly" aria-pressed="true">Monthly</button><button type="button" data-billing-btn="yearly" aria-pressed="false">Yearly · 2 months free</button></div>
<div class="grid plans">${plans}</div>
<p class="fine">Prices in Indian rupees.${gstMode === "none" ? "" : ` ${esc(gstNote(gstMode) || "")}.`} Cancel any time. Paid plans open when payments go live.</p></div></section>
<section class="block" id="faq"><div class="wrap"><div class="section-head"><h2>Questions</h2></div><div style="max-width:760px;margin:0 auto">${faq}</div>
<div class="owners" style="margin-top:24px"><strong>We only scan websites you own.</strong> That is the one rule, and the service enforces it.</div></div></section>
<section class="block alt"><div class="wrap section-head" style="margin-bottom:0"><h2>See your website the way an outsider does</h2><p>Free for up to 5 websites. No card needed.</p><div class="cta" style="margin-top:16px"><a class="btn" href="${APP_PATH}#/signup">Sign up free</a></div></div></section>
</main>${footer(c, domain)}`;
}

function legalBody(c, domain, doc) {
  const body = doc.sections.map(([h, paras]) => {
    const items = doc.path !== "terms" && /^2\./.test(h) && paras.length > 1;
    return `<h2>${esc(h)}</h2>${items ? `<ul>${paras.map(t => `<li>${esc(t)}</li>`).join("")}</ul>` : paras.map(t => `<p>${esc(t)}</p>`).join("")}`;
  }).join("");
  return `${header(c)}<main id="main"><div class="wrap legal"><div class="draft" role="note">${DRAFT_NOTICE}</div><h1>${esc(doc.title)}</h1>
<p class="meta">${esc(c.company)} · ${esc(c.product)} · Effective date: ${esc(c.placeholders.effectiveDate)}</p>${body}
<div class="draft" role="note">${DRAFT_NOTICE}: this text is a draft and has not been reviewed by a lawyer.</div></div></main>${footer(c, domain)}`;
}

// ---- everything ----
export function buildSite({ config, domain, plans, css, gstMode = "none", gstPercent = 18, scheme = "https" }) {
  const base = `${scheme}://${domain}`;
  const og = `${base}/og-image.png`;
  const view = pricingView(plans, gstMode, gstPercent);
  const finish = html => html.replace("@@CSS@@", () => css);
  const files = {};
  files["index.html"] = finish(page(head({
    title: `${config.product} | Website security you can understand`,
    description: `${config.product} monitors your website, detects what is exposed, finds real weaknesses and gives you a clear report. We only scan websites you own. Free plan available.`,
    canonical: base + "/", siteUrl: base, ogImage: og, extra: jsonLd(config, base, view),
  }), landingBody(config, domain, view, gstMode)));
  const legal = legalPages(config, domain);
  for (const doc of Object.values(legal)) {
    files[`${doc.path}/index.html`] = finish(page(head({
      title: `${doc.title} (draft) | ${config.product}`, description: doc.description, canonical: `${base}/${doc.path}/`, siteUrl: base, ogImage: og,
    }), legalBody(config, domain, doc)));
  }
  files["robots.txt"] = `User-agent: *\nAllow: /\nDisallow: ${APP_PATH}\nDisallow: /api/\n\nSitemap: ${base}/sitemap.xml\n`;
  const urls = ["/", ...Object.values(legal).map(d => `/${d.path}/`)];
  files["sitemap.xml"] = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map(u => `  <url><loc>${base}${u}</loc></url>`).join("\n")}\n</urlset>\n`;
  return files;
}
