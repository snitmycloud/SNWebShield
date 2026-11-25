import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

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

async function asset(request, { approved = false, startsIn = -3600000, endsIn = 3600000, noRequest = false, assessmentMethod = false, portDiscovery = false } = {}) {
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
    authorized_by: "Synthetic Contact", authorized_domains: [`${key}.example.com`, ...(portDiscovery ? ["8.8.8.8"] : [])],
    permitted_methods: [assessmentMethod || portDiscovery ? "automated_non_intrusive_scanning" : "passive_reconnaissance", ...(portDiscovery ? ["tcp_port_discovery"] : [])],
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
    // Overview and history are separate requests; a job may commit between them.
    await expect(page.getByRole("img", { name: "Recent monitoring response times in milliseconds" })).toBeVisible();
  }).toPass({ timeout: 15000 });
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

async function openAssessmentForm(page, website, record, note, blocked = false) {
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Assessments", exact: true }).click();
  await page.getByLabel("Assessment website", { exact: true }).selectOption(String(website.id));
  await page.getByLabel("Note (optional)", { exact: true }).fill(note);
  if (blocked) return;
  await expect(page.getByTestId("permission-status")).toContainText("Permission: valid");
  await page.getByRole("button", { name:"3. Run assessment", exact: true }).click();
}

test("assessment explicitly queues a preflight and cancellation is audited", async ({ page, request }) => {
  const { website, record } = await asset(request, { approved: true, assessmentMethod: true });
  await openAssessmentForm(page, website, record, "Browser synthetic permission preflight, no network execution.");
  await expect(page.getByRole("status")).toContainText("Permission preflight queued");
  const details = page.getByRole("article", { name: "Assessment details" });
  await expect(details).toContainText("queued");
  await page.getByLabel("Assessment cancellation reason").fill("Cancel this synthetic browser preflight request.");
  await page.getByRole("button", { name: "Cancel assessment request", exact: true }).click();
  await expect(details).toContainText("assessment cancelled");
  await expect(page.getByRole("status")).toContainText("Assessment request cancelled");
});

test("assessment profile rejects passive reconnaissance permission", async ({ page, request }) => {
  const { website, record } = await asset(request, { approved: true });
  await openAssessmentForm(page, website, record, "Browser synthetic request with insufficient permitted methods.", true);
  await expect(page.getByTestId("permission-status")).toContainText("does not permit the methods this profile needs");
  await expect(page.getByRole("button", { name: "3. Run assessment", exact: true })).toBeDisabled();
  await expect(page.getByTestId("run-blocked-reason")).toContainText("does not permit the methods");
  await expect(page.getByRole("button", { name: "Cancel assessment request", exact: true })).toHaveCount(0);
});

test("assessment worker result is labelled preflight without scan findings", async ({ page, request }) => {
  const { website, record } = await asset(request, { approved: true, assessmentMethod: true });
  await openAssessmentForm(page, website, record, "BROWSER_COMPLETE synthetic permission preflight only.");
  const details = page.getByRole("article", { name: "Assessment details" });
  await expect(async () => {
    await page.getByRole("button", { name: "Refresh assessments", exact: true }).click();
    await expect(details).toContainText("permission preflight passed");
  }).toPass({ timeout: 15000 });
  await expect(page.getByRole("row").filter({ hasText: new URL(website.url).hostname })).toContainText("Preflight completed");
  await expect(details).toContainText("No scanner execution");
});


test("assessment refresh removes revoked approval and updates queued request details", async ({ page, request }) => {
  const { website, record, headers } = await asset(request, { approved: true, assessmentMethod: true });
  await openAssessmentForm(page, website, record, "Browser synthetic refresh and revocation preflight.");
  const details = page.getByRole("article", { name: "Assessment details" });
  await expect(details).toContainText("queued");
  const revoked = await request.post(`${API}/authorizations/${record.id}/revoke`, { headers, data: {
    reason: "Withdraw synthetic permission to test assessment refresh.",
  } });
  expect(revoked.status()).toBe(200);
  await page.getByRole("button", { name: "Refresh assessments", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Assessment data refreshed");
  await expect(page.getByTestId("permission-status")).toContainText("no approved authorisation");
  await expect(details).toContainText("cancelled");
  await expect(details).toContainText("authorization revoked");
  await expect(page.getByRole("button", { name:"3. Run assessment", exact: true })).toBeDisabled();
});


test("local HTTP assessment requires separate consent and displays reviewable observations", async ({ page, request }) => {
  const {website,record}=await asset(request,{approved:true,assessmentMethod:true});
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Assessments",exact:true}).click();
  await page.getByLabel("Assessment website",{exact:true}).selectOption(String(website.id));
  await page.getByLabel("Assessment profile",{exact:true}).selectOption("local-http-headers-v1");
  await page.getByLabel("Note (optional)",{exact:true}).fill("BROWSER_LOCAL synthetic network broker fixture, no real website traffic.");
  const queue=page.getByRole("button",{name:"3. Run assessment",exact:true});
  await expect(queue).toBeDisabled();
  await page.getByLabel(/^I inspected genuine written permission/).check();
  await queue.click();
  const details=page.getByRole("article",{name:"Assessment details"});
  await expect(async()=>{
    await page.getByRole("button",{name:"Refresh assessments",exact:true}).click();
    await expect(details).toContainText("header assessment completed");
    await expect(page.getByRole("region",{name:"Header observations"})).toContainText("human validation required");
  }).toPass({timeout:15000});
  await expect(details).toContainText("Suggested severity:");
  const downloadPromise=page.waitForEvent("download");
  await page.getByRole("button",{name:"Download private assessment report"}).click();
  const download=await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^assessment-.*\.json$/);
});

test("Azure header analysis displays execution usage and cleanup", async ({ page, request }) => {
  const {website,record}=await asset(request,{approved:true,assessmentMethod:true});
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Assessments",exact:true}).click();
  await page.getByLabel("Assessment website",{exact:true}).selectOption(String(website.id));
  await page.getByLabel("Assessment profile",{exact:true}).selectOption("remote-docker-headers-v1");
  await page.getByLabel("Note (optional)",{exact:true}).fill("BROWSER_REMOTE simulated SSH and Docker; no external requests.");
  const queue=page.getByRole("button",{name:"3. Run assessment",exact:true});
  await expect(queue).toBeDisabled();
  await page.getByLabel(/^I inspected genuine written permission/).check();
  await queue.click();
  const details=page.getByRole("article",{name:"Assessment details"});
  await expect(async()=>{
    await page.getByRole("button",{name:"Refresh assessments",exact:true}).click();
    await expect(details).toContainText("header assessment completed");
    await expect(details).toContainText("Container execution: 40 ms");
    await expect(details).toContainText("Cleanup: confirmed");
  }).toPass({timeout:15000});
  await expect(details).toContainText("Analyzer CPU: 0.01 s");
  await expect(details).toContainText("Container isolation: verified by the runner before start");
  await expect(details).toContainText("TLS: TLSv1.3");
  await expect(details).toContainText("remote docker execution finished");
});

test("analyst reviews track remediation, revisions and private reviewed exports", async ({ page, request }) => {
  test.setTimeout(60000);
  const {website,record}=await asset(request,{approved:true,assessmentMethod:true});
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Assessments",exact:true}).click();
  await page.getByLabel("Assessment website",{exact:true}).selectOption(String(website.id));
  await page.getByLabel("Assessment profile",{exact:true}).selectOption("remote-docker-headers-v1");
  await page.getByLabel("Note (optional)",{exact:true}).fill("BROWSER_REMOTE synthetic analyst review acceptance; no website traffic.");
  await page.getByLabel(/^I inspected genuine written permission/).check();
  await page.getByRole("button",{name:"3. Run assessment",exact:true}).click();
  await expect(async()=>{
    await page.getByRole("button",{name:"Refresh assessments",exact:true}).click();
    await expect(page.getByRole("region",{name:"Analyst review and remediation"})).toBeVisible();
  }).toPass({timeout:15000});
  const panel=page.getByRole("region",{name:"Analyst review and remediation"});
  await expect(panel).toContainText("0 of 9 observations reviewed");
  await expect(panel.getByRole("button",{name:"Export reviewed report",exact:true})).toBeDisabled();
  await panel.getByText("CSP: Awaiting analyst review",{exact:true}).click();
  const csp=panel.getByRole("form",{name:"CSP analyst review",exact:true});
  await csp.getByRole("combobox",{name:"CSP disposition",exact:true}).selectOption("confirmed");
  await csp.getByLabel("CSP review notes",{exact:true}).fill("Analyst confirmed a synthetic configuration issue after reviewing staging evidence.");
  await csp.getByLabel("CSP supporting evidence",{exact:true}).fill("Synthetic configuration review evidence and source report checksum inspected.");
  await csp.getByRole("combobox",{name:"CSP analyst severity",exact:true}).selectOption("medium");
  await csp.getByLabel("CSP recommended fix",{exact:true}).fill("Prepare a reviewed policy for the synthetic staging application and retest it.");
  await csp.getByLabel("CSP remediation owner",{exact:true}).fill("Staging operations");
  await csp.getByRole("combobox",{name:"CSP resolution status",exact:true}).selectOption("in_progress");
  await expect(csp.getByRole("button",{name:"Save CSP review",exact:true})).toBeDisabled();
  await csp.getByLabel(/^I personally reviewed/).check();
  await csp.getByRole("button",{name:"Save CSP review",exact:true}).click();
  await expect(panel).toContainText("1 of 9 observations reviewed");
  await panel.getByText("CSP: confirmed · in progress · revision 1",{exact:true}).click();
  await csp.getByRole("combobox",{name:"CSP resolution status",exact:true}).selectOption("ready_for_retest");
  await csp.getByLabel(/^I personally reviewed/).check();
  await csp.getByRole("button",{name:"Save CSP review",exact:true}).click();
  await panel.getByText("CSP: confirmed · ready for retest · revision 2",{exact:true}).click();
  await panel.getByRole("button",{name:"Show CSP review history",exact:true}).click();
  await expect(panel.getByRole("region",{name:"CSP review history",exact:true})).toContainText("Revision 1");
  for (const title of ["HSTS","X-Frame-Options","CSP frame-ancestors","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","Server disclosure","HTTPS in use"]) {
    await panel.getByText(`${title}: Awaiting analyst review`,{exact:true}).click();
    const form=panel.getByRole("form",{name:`${title} analyst review`,exact:true});
    await form.getByRole("combobox",{name:`${title} disposition`,exact:true}).selectOption("dismissed");
    await form.getByLabel(`${title} review notes`,{exact:true}).fill("Synthetic analyst reviewed the observation and dismissed it with a documented rationale.");
    await form.getByLabel(`${title} supporting evidence`,{exact:true}).fill("Synthetic supporting evidence and reviewed configuration references recorded.");
    await form.getByLabel(/^I personally reviewed/).check();
    await form.getByRole("button",{name:`Save ${title} review`,exact:true}).click();
    await expect(panel.getByText(`${title}: dismissed · not applicable · revision 1`,{exact:true})).toBeVisible();
  }
  await expect(panel).toContainText("9 of 9 observations reviewed");
  const downloading=page.waitForEvent("download");
  await panel.getByRole("button",{name:"Export reviewed report",exact:true}).click();
  const downloaded=await downloading;
  expect(downloaded.suggestedFilename()).toMatch(/^reviewed-assessment-.*\.json$/);
  const snapshot=JSON.parse(await readFile(await downloaded.path(),"utf8"));
  expect(snapshot.summary.analyst_confirmed).toBe(1);
  expect(snapshot.summary.reviewed).toBe(9);
  expect(snapshot.analyst_reviews.find(item=>item.check_id==="csp").revision).toBe(2);
  expect(snapshot.source_report.content.analysis.confirmed_findings).toBe(0);
  await expect(panel.getByRole("region",{name:"Reviewed report exports"})).toBeVisible();
});

test("findings filter confirmed issues, track deadlines and open source reviews", async ({ page, request }) => {
  test.setTimeout(60000);
  const {website,record,headers}=await asset(request,{approved:true,assessmentMethod:true});
  const queued=await request.post(`${API}/assessments`,{headers,data:{website_id:website.id,authorization_id:record.id,
    profile_id:"remote-docker-headers-v1",idempotency_key:randomUUID(),explicitly_requested:true,network_permission_confirmed:true,
    note:"BROWSER_REMOTE synthetic central findings acceptance; no target traffic."}});
  expect(queued.status()).toBe(201);
  const assessment=await queued.json();
  await expect.poll(async()=>{
    const result=await request.get(`${API}/assessments/${assessment.id}`,{headers});
    return (await result.json()).job.status;
  },{timeout:15000}).toBe("completed");
  const reviewed=await request.post(`${API}/assessments/${assessment.id}/reviews/csp`,{headers,data:{
    expected_revision:0,human_validation_confirmed:true,disposition:"confirmed",severity:"high",
    notes:"Analyst confirmed the synthetic issue using inspected staging configuration.",
    supporting_evidence:"Synthetic inspection evidence and source report were reviewed by the analyst.",
    recommendation:"Prepare a reviewed policy and validate it on the synthetic staging application.",
    owner:"Browser remediation owner",remediation_status:"open"}});
  expect(reviewed.status()).toBe(201);
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Findings",exact:true}).click();
  await expect(page.getByRole("heading",{name:"Findings and remediation",exact:true})).toBeVisible();
  await page.getByLabel("Findings website",{exact:true}).selectOption(String(website.id));
  await page.getByRole("button",{name:"Apply finding filters",exact:true}).click();
  const row=page.getByRole("row").filter({hasText:website.name});
  await expect(row).toContainText("Browser remediation owner");
  await expect(row).toContainText("high");
  await row.getByRole("button",{name:"Open finding",exact:true}).click();
  const detail=page.getByRole("article",{name:"Finding details",exact:true});
  await expect(detail).toContainText("Synthetic inspection evidence");
  const due=detail.getByRole("form",{name:"Finding deadline",exact:true});
  await due.getByLabel("Finding due date",{exact:true}).fill("2020-01-01");
  await due.getByLabel("Due-date change note",{exact:true}).fill("Synthetic overdue deadline used for dashboard acceptance.");
  await due.getByRole("button",{name:"Save due date",exact:true}).click();
  await expect(row).toContainText("Overdue");
  await expect(detail.getByRole("region",{name:"Finding due-date history"})).toContainText("Revision 1");
  await detail.getByText("CSP: confirmed · open · revision 1",{exact:true}).click();
  const form=detail.getByRole("form",{name:"CSP analyst review",exact:true});
  await form.getByLabel("CSP remediation owner",{exact:true}).fill("Updated remediation owner");
  await form.getByRole("combobox",{name:"CSP resolution status",exact:true}).selectOption("in_progress");
  await form.getByLabel(/^I personally reviewed/).check();
  await form.getByRole("button",{name:"Save CSP review",exact:true}).click();
  await expect(row).toContainText("Updated remediation owner");
  await expect(row).toContainText("in progress");
  await page.getByLabel("Finding severity",{exact:true}).selectOption("high");
  await page.getByLabel("Finding status",{exact:true}).selectOption("in_progress");
  await page.getByLabel("Overdue findings only",{exact:true}).check();
  await page.getByRole("button",{name:"Apply finding filters",exact:true}).click();
  await expect(row).toBeVisible();
  await page.getByLabel("Finding owner",{exact:true}).fill("Does not match any owner");
  await page.getByRole("button",{name:"Apply finding filters",exact:true}).click();
  await expect(page.getByText("No analyst-confirmed findings match these filters.",{exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Clear finding filters",exact:true}).click();
  await row.getByRole("button",{name:"Open finding",exact:true}).click();
  await detail.getByRole("button",{name:"Open source assessment and reports",exact:true}).click();
  await expect(page.getByRole("article",{name:"Assessment details",exact:true})).toContainText(assessment.id);
  await expect(page.getByRole("region",{name:"Analyst review and remediation"})).toContainText("CSP: confirmed · in progress · revision 2");
});

test("restricted Nmap profile requires consent and displays port observations", async ({ page, request }) => {
  const {website,record}=await asset(request,{approved:true,portDiscovery:true});
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Assessments",exact:true}).click();
  await page.getByLabel("Assessment website",{exact:true}).selectOption(String(website.id));
  await page.getByLabel("Assessment profile",{exact:true}).selectOption("remote-nmap-web-ports-v1");
  await page.getByLabel("Note (optional)",{exact:true}).fill("BROWSER_NMAP synthetic two-port TCP profile; no target traffic.");
  const queue=page.getByRole("button",{name:"3. Run assessment",exact:true});
  await expect(queue).toBeDisabled();
  await page.getByLabel(/^I inspected genuine written permission to discover TCP ports/).check();
  await queue.click();
  const details=page.getByRole("article",{name:"Assessment details"});
  await expect(async()=>{
    await page.getByRole("button",{name:"Refresh assessments",exact:true}).click();
    await expect(details).toContainText("tcp port assessment completed");
    await expect(page.getByRole("region",{name:"Port observations"})).toContainText("tcp port 80: open");
  }).toPass({timeout:15000});
  await expect(details).toContainText("tcp port 443: closed");
  await expect(details).toContainText("Scanner CPU: 0.01 s");
  await expect(details).toContainText("Cleanup: confirmed");
  await expect(page.getByRole("region",{name:"Analyst review and remediation"})).toContainText("0 of 2 observations reviewed");
});

test("Nmap rejects a web-only approval", async ({ page, request }) => {
  const {website,record}=await asset(request,{approved:true,assessmentMethod:true});
  await signIn(page);
  await page.getByRole("navigation",{name:"Main navigation"}).getByRole("button",{name:"Assessments",exact:true}).click();
  await page.getByLabel("Assessment website",{exact:true}).selectOption(String(website.id));
  await page.getByLabel("Assessment profile",{exact:true}).selectOption("remote-nmap-web-ports-v1");
  await page.getByLabel("Note (optional)",{exact:true}).fill("BROWSER_NMAP denied synthetic web-only authorisation.");
  await page.getByLabel(/^I inspected genuine written permission to discover TCP ports/).check();
  await expect(page.getByTestId("permission-status")).toContainText("does not permit the methods this profile needs");
  await expect(page.getByRole("button",{name:"3. Run assessment",exact:true})).toBeDisabled();
});

test("VM housekeeping report is explicit, read-only and flags leftover containers", async ({ page }) => {
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Assessments", exact: true }).click();
  await expect(page.getByTestId("orphan-report")).toHaveCount(0); // never runs on page load
  await page.getByRole("button", { name: "Check VM for leftover containers", exact: true }).click();
  const report = page.getByTestId("orphan-report");
  await expect(report).toContainText("1 leftover container found");
  await expect(report).toContainText("No leftover containers");
  await expect(report).toContainText("Nothing was removed");
  await expect(page.getByRole("status")).toContainText("Nothing was changed");
});

test("website lifecycle shows the four pillars and routes the next step", async ({ page, request }) => {
  const { website } = await asset(request, { approved: true, assessmentMethod: true });
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Website lifecycle", exact: true }).click();
  await page.getByLabel("Lifecycle website", { exact: true }).selectOption(String(website.id));
  for (const key of ["monitors", "detects", "validates", "protects"]) await expect(page.getByTestId(`pillar-${key}`)).toBeVisible();
  await expect(page.getByTestId("pillar-detects")).toContainText("Permission is valid for an assessment.");
  const next = page.getByTestId("next-step");
  await expect(next).toHaveAttribute("data-code", "set_up_monitoring"); // monitoring comes first
  await next.getByRole("button", { name: "Open Monitoring", exact: true }).click();
  await expect(page.getByRole("heading", { name: /monitoring/i }).first()).toBeVisible();
});

test("port watch is enabled and disabled only by explicit, attested actions", async ({ page, request }) => {
  const { website } = await asset(request, { approved: true, portDiscovery: true });
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Monitoring", exact: true }).click();
  const panel = page.getByRole("region", { name: "Port watch", exact: true });
  await panel.getByLabel("Port watch website", { exact: true }).selectOption(String(website.id));
  await expect(panel.getByTestId("port-watch-state")).toHaveAttribute("data-state", "off");
  const enable = panel.getByRole("button", { name: "Enable port watch", exact: true });
  await expect(enable).toBeDisabled(); // nothing starts without the written-permission attestation
  await panel.getByLabel(/^I inspected genuine written permission for recurring TCP 80 and 443/).check();
  await enable.click();
  await expect(panel.getByRole("status")).toContainText("Port watch enabled");
  await expect(panel.getByTestId("port-watch-state")).toHaveAttribute("data-state", "active");
  await expect(panel).toContainText("Every 6 hours");
  await panel.getByLabel("Port watch disable reason", { exact: true }).fill("Scanning window ended for this client.");
  await panel.getByRole("button", { name: "Disable port watch", exact: true }).click();
  await expect(panel.getByRole("status")).toContainText("Port watch disabled");
  await expect(panel.getByTestId("port-watch-state")).toHaveAttribute("data-state", "off");
});

test("port watch explains exactly why it cannot be enabled", async ({ page, request }) => {
  const { website } = await asset(request, { approved: true, assessmentMethod: true }); // web scanning only, no TCP discovery
  await signIn(page);
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Monitoring", exact: true }).click();
  const panel = page.getByRole("region", { name: "Port watch", exact: true });
  await panel.getByLabel("Port watch website", { exact: true }).selectOption(String(website.id));
  await expect(panel.getByTestId("port-watch-blocked")).toContainText("does not permit the methods this profile needs");
  await panel.getByLabel(/^I inspected genuine written permission for recurring TCP 80 and 443/).check();
  await expect(panel.getByRole("button", { name: "Enable port watch", exact: true })).toBeDisabled();
});
