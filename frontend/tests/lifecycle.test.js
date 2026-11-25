import test from "node:test";
import assert from "node:assert/strict";
import { STEP_PAGES, pillars, stepTarget } from "../src/lib/lifecycle.js";

const view = {
  monitor: { state: "stale", last_checked_at: null },
  detect: { latest: { status: "completed" }, total_assessments: 3, can_run: false, blocked_reason: "The authorisation is expired or not yet valid (UTC dates)." },
  validate: { awaiting_review: 4, confirmed: 2, false_positive: 1, not_applicable: 0 },
  protect: { confirmed: 2, unresolved: 1, awaiting_signoff: 1, latest_report: { status: "approved", revision: 2 } },
};

test("every server next-step code maps to a page or to nothing", () => {
  for (const code of ["set_up_monitoring", "run_assessment", "fix_permission", "wait_for_assessment", "review_findings", "sign_off_fix",
    "wait_for_retest", "request_retest", "track_remediation", "generate_report", "all_clear"]) assert.ok(code in STEP_PAGES, code);
  assert.deepEqual(stepTarget({ code: "review_findings" }), { page: "workbench", label: "Open the analyst workbench" });
  assert.equal(stepTarget({ code: "all_clear" }), null);
  assert.equal(stepTarget({ code: "something_new" }), null);
  assert.equal(stepTarget(null), null);
});

test("pillars describe the four stages from counts and fixed text", () => {
  const cards = pillars(view);
  assert.deepEqual(cards.map(c => c.title), ["MONITORS", "DETECTS", "VALIDATES", "PROTECTS"]);
  assert.match(cards[0].lines[0], /stopped reporting/);
  assert.match(cards[1].lines.join(" "), /Latest assessment: completed.*3 assessment.*authorisation is expired/);
  assert.match(cards[2].lines[0], /4 observation\(s\) awaiting/);
  assert.match(cards[3].lines.join(" "), /2 confirmed finding\(s\), 1 unresolved.*1 fix\(es\) awaiting second-person.*approved \(revision 2\)/);
  assert.deepEqual(pillars(null), []);
});

test("unknown monitor states and empty history never show raw or undefined text", () => {
  const text = JSON.stringify(pillars({ ...view, monitor: { state: "<script>x</script>" }, detect: { latest: null, total_assessments: 0, can_run: true },
    protect: { confirmed: 0, unresolved: 0, awaiting_signoff: 0, latest_report: null } }));
  assert.doesNotMatch(text, /script|undefined/);
  assert.match(text, /No assessment has been run/);
  assert.match(text, /No report yet/);
});
