import test from "node:test";
import assert from "node:assert/strict";
import { describeIsolation, describeOrphanReport, describeRedirect, describeTls } from "../src/lib/scanner.js";

test("redirects are described from fixed categories and never echo target text", () => {
  assert.equal(describeRedirect({ redirect: { is_redirect: false, location: null, followed: false } }), null);
  assert.equal(describeRedirect({}), null);
  assert.match(describeRedirect({ redirect: { is_redirect: true, location: "different_host_not_followed" } }), /not followed \(different host\)/);
  const hostile = describeRedirect({ redirect: { is_redirect: true, location: "<img src=x onerror=alert(1)>" } });
  assert.match(hostile, /unclassified destination/);
  assert.doesNotMatch(hostile, /onerror/);
});

test("TLS version is shown only from the expected vocabulary", () => {
  assert.equal(describeTls({ tls_verified: false }), "TLS: not used");
  assert.equal(describeTls({ tls_verified: true, tls_version: "TLSv1.3" }), "TLS: TLSv1.3");
  assert.equal(describeTls({ tls_verified: true, tls_version: "SSLv3<script>" }), "TLS: verified");
  assert.equal(describeTls({ tls_verified: true }), "TLS: verified");
});

test("isolation attestation is reported honestly for old and new runners", () => {
  assert.equal(describeIsolation(null), null);
  assert.match(describeIsolation({ isolation_attested: true }), /verified by the runner/);
  assert.match(describeIsolation({}), /not attested/);
  assert.match(describeIsolation({ isolation_attested: "true" }), /not attested/);
});

test("orphan report text is built from fixed categories and counts, never remote text", () => {
  const rows = describeOrphanReport({ sections: [
    { scanner: "nmap", status: "ok", containers: [{ status: "orphaned", name: "<img onerror=x>" }, { status: "recent" }] },
    { scanner: "header analysis", status: "unavailable", error: "ssh_unreachable<script>" },
    { scanner: "x", status: "disabled", containers: [] }, { scanner: "y", status: "unsupported" }, { scanner: "z", status: "weird" }] });
  assert.match(rows[0].text, /1 leftover container found, 1 recent\. Review and remove manually/);
  assert.equal(rows[0].orphaned, 1);
  assert.doesNotMatch(JSON.stringify(rows), /onerror|<script>/);
  assert.match(rows[1].text, /could not be checked \(ssh_unreachablescript\)/);
  assert.match(rows[2].text, /VM was not contacted/);
  assert.match(rows[3].text, /Redeploy the runner/);
  assert.equal(rows[4].text, "Status unavailable.");
  assert.deepEqual(describeOrphanReport(null), []);
  assert.match(describeOrphanReport({ sections: [{ scanner: "n", status: "ok", containers: [] }] })[0].text, /No leftover containers\./);
});

test("isolation text covers verified and not-attested runners", () => {
  assert.match(describeIsolation({ isolation_attested: true }), /verified by the runner/);
  assert.match(describeIsolation({ isolation_attested: false }), /not attested/);
});
