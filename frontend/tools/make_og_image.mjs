// Renders public/og-image.png (1200x630, the preview image for links) once. Run from frontend/:  node tools/make_og_image.mjs
import { chromium } from "@playwright/test";
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1200, height: 630 } });
await p.setContent(`<body style="margin:0;width:1200px;height:630px;background:#0a111f;font-family:Segoe UI,Arial,sans-serif;color:#e9eff9;display:flex;flex-direction:column;justify-content:center;padding:0 90px;box-sizing:border-box">
<div style="display:flex;align-items:center;gap:22px"><svg width="96" height="96" viewBox="0 0 32 32"><path d="M16 2.2 4.5 6.6v8.1c0 7.1 4.8 12.7 11.5 15.1 6.7-2.4 11.5-8 11.5-15.1V6.6L16 2.2Z" fill="#2dd4bf"/><path d="m10.6 16.3 3.9 3.9 7-7.7" fill="none" stroke="#04201d" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span style="font-size:76px;font-weight:800">SNwebshield</span></div>
<div style="font-size:46px;font-weight:700;margin-top:36px;line-height:1.25">Know how secure your website really is</div>
<div style="font-size:28px;color:#5eead4;margin-top:28px;letter-spacing:4px;font-weight:700">MONITORS. DETECTS. VALIDATES. PROTECTS.</div></body>`);
await p.screenshot({ path: new URL("../public/og-image.png", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1") });
await b.close();
