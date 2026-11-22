import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";

const syntheticImage = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAIAAAAC64paAAAAHUlEQVR4nGP8//8/A7mAiWydo5pHNY9qHtVMFc0AnKADJXYG/XsAAAAASUVORK5CYII=", "base64");

const API = "http://127.0.0.1:18000/api/v1";
const credentials = { email: "browser-test@example.com", password: "Synthetic-browser-password-123!" };

async function signIn(page) {
  await page.goto("/");
  await page.getByLabel("Email address").fill(credentials.email);
  await page.getByLabel("Password", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "Workspace summary" })).toBeVisible();
}

async function asset(request, { approved = false, startsIn = -3600000, endsIn = 3600000, noRequest = false } = {}) {
  const key = randomUUID();
  const login = await request.post(`${API}/auth/login`, { data: credentials });
  expect(login.status()).toBe(200);
  const headers = { Authorization: `Bearer ${(await login.json()).access_token}` };
  const client = await request.post(`${API}/clients`, { headers, data: {
    company_name: `Browser client ${key}`, primary_contact_name: "Synthetic Contact", email: `${key}@example.com`,
  } });
  expect(client.status()).toBe(201);
  const site = await request.post(`${API}/websites`, { headers, data: {
    client_id: (await client.json()).id, name: `Browser website ${key}`, url: `https://${key}.example.com`, environment: "staging",
  } });
  expect(site.status()).toBe(201);
  const website = await site.json();
  if (noRequest) return { website, headers };
  const authorization = await request.post(`${API}/authorizations`, { headers, data: {
    website_id: website.id, authorization_reference: `BROWSER-${key}`,
    authorized_by: "Synthetic Contact", authorized_domains: [`${key}.example.com`],
    permitted_methods: ["passive_reconnaissance"],
    valid_from: new Date(Date.now() + startsIn).toISOString(),
    valid_until: new Date(Date.now() + endsIn).toISOString(),
  } });
  expect(authorization.status()).toBe(201);
  const record = await authorization.json();
  if (approved) {
    const uploaded = await request.post(`${API}/authorizations/${record.id}/evidence`, {
      headers: { ...headers, "X-Evidence-Filename": "signed.png", "Content-Type": "application/octet-stream" }, data: syntheticImage,
    });
    expect(uploaded.status()).toBe(201);
    const evidenceId = (await uploaded.json()).id;
    expect((await request.get(`${API}/evidence/${evidenceId}/download`, { headers })).status()).toBe(200);
    const evidence = await request.get(`${API}/authorizations/${record.id}/evidence`, { headers });
    const reviewed = await request.post(`${API}/authorizations/${record.id}/evidence/reviews`, { headers, data: {
      revision: (await evidence.json()).revision, decision: "accepted", inspected: true,
      comment: "Inspected the synthetic signed document and the complete approved scope.",
    } });
    expect(reviewed.status()).toBe(201);
    const decision = await request.post(`${API}/authorizations/${record.id}/approve`, { headers, data: {
      evidence_reviewed: true, review_note: "Reviewed synthetic permission and the exact domain scope.",
    } });
    expect(decision.status()).toBe(200);
  }
  return { website, record, headers };
}

async function openRecord(page, record) {
  await page.getByRole("button", { name: "Authorizations", exact: true }).click();
  await page.getByPlaceholder("Search reference, domain, client or contact").fill(record.authorization_reference);
  await page.getByRole("row").filter({ hasText: record.authorization_reference }).getByRole("button").click();
  await expect(page.getByRole("dialog")).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => {
    if (message.type() === "error" && !message.text().includes("Failed to load resource")) errors.push(message.text());
  });
  page.testErrors = errors;
});

test.afterEach(async ({ page }) => {
  expect(page.testErrors).toEqual([]);
});

test("incorrect password, valid login, restore and logout", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Email address").fill(credentials.email);
  await page.getByLabel("Password", { exact: true }).fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("alert")).toContainText("Incorrect email or password");
  await page.getByLabel("Password", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Sign in securely" }).click();
  await expect(page.getByRole("heading", { name: "Workspace summary" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Workspace summary" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
});

test("approve with evidence, see audit, revoke and refresh website status", async ({ page, request }) => {
  const { record, website } = await asset(request);
  await signIn(page);
  await openRecord(page, record);
  await expect(page.getByRole("button", { name: "Approve request", exact: true })).toBeDisabled();
  await page.getByLabel("Upload permission document", { exact: true }).setInputFiles({ name: "signed.png", mimeType: "image/png", buffer: syntheticImage });
  await page.getByRole("button", { name: "Preview signed.png", exact: true }).click();
  await expect(page.getByAltText("Permission document preview")).toBeVisible();
  await page.getByLabel("Evidence review comments").fill("Inspected synthetic signed permission, its signatory, dates and exact scope.");
  await page.getByLabel("I inspected all current documents and checked the signatory, domains, methods and dates.").check();
  await page.getByRole("button", { name: "Record evidence review", exact: true }).click();
  await page.getByRole("button", { name: "Approve request", exact: true }).click();
  await expect(page.getByRole("button", { name: "Confirm approval" })).toBeDisabled();
  await page.locator(".authz-evidence-check input").check();
  await page.locator(".authz-action-form textarea").fill("Reviewed synthetic permission and verified the exact domain scope.");
  await page.getByRole("button", { name: "Confirm approval" }).click();
  await expect(page.locator(".authz-event-title strong").filter({ hasText: "APPROVED" })).toBeVisible();
  await page.getByRole("button", { name: "Revoke approval" }).click();
  await page.locator(".authz-action-form textarea").fill("Synthetic permission withdrawn by the test signatory.");
  await page.getByRole("button", { name: "Confirm revocation" }).click();
  await expect(page.locator(".authz-event-title strong").filter({ hasText: "REVOKED" })).toBeVisible();
  await page.getByRole("button", { name: "Close authorization details" }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: /^Websites/ }).click();
  await expect(page.getByRole("row").filter({ hasText: website.name })).toContainText("Revoked");
});

test("expired pending request cannot be approved but can be rejected", async ({ page, request }) => {
  const { record } = await asset(request, { startsIn: -7200000, endsIn: -3600000 });
  await signIn(page); await openRecord(page, record);
  await expect(page.getByRole("button", { name: "Approve request", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Reject request", exact: true }).click();
  await page.locator(".authz-action-form textarea").fill("Synthetic permission validity period has already expired.");
  await page.getByRole("button", { name: "Confirm rejection" }).click();
  await expect(page.locator(".authz-event-title strong").filter({ hasText: "REJECTED" })).toBeVisible();
});

test("future approval is scheduled and a website without requests is labelled accurately", async ({ page, request }) => {
  const scheduled = await asset(request, { approved: true, startsIn: 3600000, endsIn: 7200000 });
  const empty = await asset(request, { noRequest: true });
  await signIn(page);
  await page
  .getByRole("navigation", { name: "Main navigation" })
  .getByRole("button", { name: /^Websites/ })
  .click();
  await expect(page.getByRole("row").filter({ hasText: scheduled.website.name })).toContainText("Scheduled");
  await expect(page.getByRole("row").filter({ hasText: empty.website.name })).toContainText("Not requested");
});

test("idle token expiry returns to login and clears the token", async ({ page }) => {
  await page.clock.install();
  await signIn(page);
  await page.clock.fastForward("20:01");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page.getByText("Your session has expired. Please sign in again.")).toBeVisible();
});

test("API outage displays Offline and retry recovers", async ({ page }) => {
  await signIn(page);
  await page.route(`${API}/**`, route => route.abort());
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Could not load SNWebShield data");
  await expect(page.locator(".stat-card").filter({ hasText: "API status" })).toContainText("Offline");
  await page.unroute(`${API}/**`);
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.locator(".api-indicator")).toContainText("API connected");
});


test("invalid uploads and rejected evidence cannot enable approval", async ({ page, request }) => {
  const { record } = await asset(request);
  await signIn(page); await openRecord(page, record);
  await page.getByLabel("Upload permission document", { exact: true }).setInputFiles({ name: "invalid.pdf", mimeType: "application/pdf", buffer: Buffer.from("not a pdf") });
  await expect(page.getByRole("alert")).toContainText("Use a valid PDF");
  await page.getByLabel("Upload permission document", { exact: true }).setInputFiles({ name: "rejected.png", mimeType: "image/png", buffer: syntheticImage });
  await page.getByRole("button", { name: "Preview rejected.png", exact: true }).click();
  await expect(page.getByAltText("Permission document preview")).toBeVisible();
  await page.getByLabel("Evidence review decision").selectOption("rejected");
  await page.getByLabel("Evidence review comments").fill("The synthetic document does not contain sufficient signed permission.");
  await page.getByLabel("I inspected all current documents and checked the signatory, domains, methods and dates.").check();
  await page.getByRole("button", { name: "Record evidence review", exact: true }).click();
  await expect(page.getByRole("button", { name: "Approve request", exact: true })).toBeDisabled();
});


test("monitoring requires separate consent, runs through the shared engine, and can be revoked", async ({ page, request }) => {
  const { website } = await asset(request, { approved: true });
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Monitoring", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Website monitoring", exact: true })).toBeVisible();
  const websiteRow = page.getByRole("row").filter({ hasText: website.name });
  await expect(websiteRow).toContainText("not configured");
  await page.getByLabel("Monitoring website", { exact: true }).selectOption(String(website.id));
  await expect(page.getByRole("button", { name: "Save monitoring configuration", exact: true })).toBeDisabled();
  await expect(page.getByLabel("Reviewed permission document").locator("option")).toHaveCount(2);
  await page.getByLabel("Reviewed permission document").selectOption({ index: 1 });
  await page.getByLabel("Monitoring agreement reference").fill("BROWSER-SYNTHETIC-MONITORING-CONSENT");
  await page.getByLabel(/^I reviewed this document and confirm/).check();
  await page.getByRole("button", { name: "Save monitoring configuration", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Configuration saved disabled");
  await expect(websiteRow).toContainText("disabled");
  await page.getByRole("button", { name: "enable", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("enable request accepted");
  // The test server supplies a synthetic outcome through the real engine.
  await expect(async () => {
    await page.getByRole("button", { name: "Refresh monitoring", exact: true }).click();
    await expect(websiteRow).toContainText("42.5 ms");
  }).toPass({ timeout: 15000 });
  await expect(page.getByRole("img", { name: "Recent monitoring response times in milliseconds" })).toBeVisible();
  await page.getByLabel("Monitoring history type").selectOption("jobs");
  await expect(page.locator(".monitor-page")).toContainText("completed");
  await page.getByRole("button", { name: "disable", exact: true }).click();
  await expect(websiteRow).toContainText("disabled");
  await page.getByRole("button", { name: "revoke consent", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("revoke-consent request accepted");
  await page.getByRole("button", { name: "enable", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Monitoring consent or evidence is invalid");
  await page.getByLabel("Monitoring history type").selectOption("consents");
  await expect(page.locator(".monitor-page")).toContainText("Revoked");
});
