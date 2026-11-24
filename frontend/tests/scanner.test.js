import test from "node:test";
import assert from "node:assert/strict";
import { describeIsolation, describeRedirect, describeTls } from "../src/lib/scanner.js";

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
