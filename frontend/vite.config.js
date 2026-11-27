import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { buildSite } from "./site/pages.js";

// / and the legal pages are plain static HTML built from site/ (fast, crawlable, no framework); the app lives at /app/.
const here = dirname(fileURLToPath(import.meta.url));
const read = p => readFileSync(resolve(here, p), "utf-8");

// One place for the domain: SITE_DOMAIN (environment variable, else the SITE_DOMAIN line of backend/.env, else the placeholder).
// Only the named lines are read from backend/.env; nothing else in it is touched or printed.
function setting(name, fallback) {
  if (process.env[name]) return process.env[name];
  const envFile = resolve(here, "../backend/.env");
  if (existsSync(envFile)) {
    const line = read("../backend/.env").split(/\r?\n/).find(l => l.startsWith(name + "="));
    if (line) return line.slice(name.length + 1).trim().replace(/^["']|["']$/g, "") || fallback;
  }
  return fallback;
}

function pages() {
  const make = () => {
    const domain = setting("SITE_DOMAIN", "snwebshield.com");
    const local = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(domain);
    return buildSite({
      config: JSON.parse(read("site/site.config.json")), plans: JSON.parse(read("../backend/app/plans.json")),
      domain, scheme: local ? "http" : "https", gstMode: setting("GST_MODE", "none"), gstPercent: Number(setting("GST_PERCENT", "18")) || 18,
      css: read("src/styles/tokens.css") + read("site/site.css"),
    });
  };
  const type = f => (f.endsWith(".xml") ? "application/xml" : f.endsWith(".txt") ? "text/plain" : "text/html");
  return {
    name: "snwebshield-public-pages",
    generateBundle() {
      for (const [fileName, source] of Object.entries(make())) this.emitFile({ type: "asset", fileName, source });
    },
    configureServer(server) {   // `npm run dev`: serve the same pages
      server.middlewares.use((req, res, next) => {
        const path = (req.url || "").split("?")[0];
        const key = path === "/" ? "index.html" : path.replace(/^\//, "").replace(/\/?$/, path.includes(".") ? "" : "/index.html");
        const files = make();
        if (!files[key]) return next();
        res.setHeader("Content-Type", type(key) + "; charset=utf-8");
        res.end(files[key]);
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), pages()],
  build: { rollupOptions: { input: { app: resolve(here, "app/index.html") } } },
});
