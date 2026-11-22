import { defineConfig } from "@playwright/test";
import path from "node:path";

const python = process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python";

export default defineConfig({
  testDir: "./tests/e2e",
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:15173",
    browserName: "chromium",
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {},
    timezoneId: "Asia/Kolkata",
    trace: "off", // Authenticated request traces can contain bearer tokens.
    screenshot: "off",
    video: "off",
  },
  webServer: [
    {
      command: `"${python}" tests/e2e_server.py`,
      cwd: path.resolve(process.cwd(), "../backend"),
      url: "http://127.0.0.1:18000/api/v1/health",
      reuseExistingServer: false,
      timeout: 60000,
    },
    {
      command: "npm run dev -- --port 15173 --strictPort",
      url: "http://127.0.0.1:15173",
      env: { VITE_API_BASE_URL: "http://127.0.0.1:18000/api/v1" },
      reuseExistingServer: false,
    },
  ],
});
