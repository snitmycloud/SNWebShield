"""The common finding format, de-duplication and the engine wrapper (no network)."""
import asyncio

import pytest

from app.services import engines
from app.services.finding import Finding, counts, merge
from app.services.scan_guard import ScanStopped


def make(**kw):
    base = dict(kind="vulnerability", check_id="cve:CVE-2020-0001", title="t", location="example.com:22", severity="high",
                confidence="confirmed", cvss_score=7.5, sources=["nvd"])
    base.update(kw)
    return Finding(**base)


def test_confirmed_non_info_findings_are_scored_and_possible_ones_are_not():
    assert make().scored and make().group == "findings"
    assert not make(confidence="possible").scored and make(confidence="possible").group == "needs_checking"
    assert not make(severity="info").scored


def test_bad_values_fail_safe():
    item = make(severity="catastrophic", confidence="sure")
    assert item.severity == "info" and item.confidence == "possible" and not item.scored


def test_long_text_is_cut_and_fingerprint_is_stable():
    item = make(why="x" * 10_000)
    assert len(item.why) == 2000
    assert make().fingerprint == make(title="other").fingerprint != make(location="example.com:80").fingerprint


def test_merge_removes_duplicates_unions_sources_and_keeps_the_stronger_view():
    nvd = make(confidence="possible", severity="medium", cvss_score=5.0, sources=["nvd"], caveat="check")
    osv = make(confidence="confirmed", severity="high", cvss_score=7.5, sources=["osv"], caveat=None)
    merged = merge([nvd, osv])
    assert len(merged) == 1
    item = merged[0]
    assert item.sources == ["nvd", "osv"] and item.confidence == "confirmed" and item.severity == "high" and item.cvss_score == 7.5


def test_merge_keeps_different_locations_and_cves_apart_and_sorts_by_severity():
    a = make(location="example.com:22")
    b = make(location="example.com:80")
    c = make(cve_id="CVE-2020-0002", check_id="cve:CVE-2020-0002", severity="critical", cvss_score=9.8)
    low = make(check_id="header:csp-missing", cve_id=None, severity="low", cvss_score=None)
    merged = merge([low, a, b, c])
    assert len(merged) == 4 and merged[0].severity == "critical" and merged[-1].severity == "low"


def test_the_same_cve_reported_with_cve_id_set_matches_across_engines():
    one = make(cve_id="CVE-2020-0001")
    two = make(cve_id="CVE-2020-0001", check_id="nuclei:cve-2020-0001", sources=["nuclei"])
    assert len(merge([one, two])) == 1


def test_counts_separate_needs_checking_and_info():
    items = [make(severity="critical"), make(severity="high", confidence="possible"), make(severity="info"), make(severity="low")]
    result = counts(items)
    assert result["critical"] == 1 and result["high"] == 0 and result["low"] == 1 and result["info"] == 1 and result["needs_checking"] == 1


# --- the engine wrapper ------------------------------------------------------------------------------------------

class Guard:
    def check(self):
        pass


def run(engine, timeout=None):
    return asyncio.run(engines.run_engine(engine, None, None, Guard(), timeout=timeout))


def test_a_crashing_engine_is_could_not_check_never_ok():
    class Boom(engines.Engine):
        async def run(self, ctx, state, guard):
            raise RuntimeError("secret internals")
    result = run(Boom())
    assert result.state == "could_not_check" and result.detail == {"reason": "unexpected_error"} and result.findings == []


def test_a_slow_engine_times_out_as_could_not_check():
    class Slow(engines.Engine):
        async def run(self, ctx, state, guard):
            await asyncio.sleep(5)
    assert run(Slow(), timeout=0.1).detail == {"reason": "timed_out"}


def test_a_bad_result_is_could_not_check_and_non_findings_are_dropped():
    class Bad(engines.Engine):
        async def run(self, ctx, state, guard):
            return "ok"

    class Mixed(engines.Engine):
        async def run(self, ctx, state, guard):
            return engines.EngineResult("ok", [make(), {"title": "not a finding"}], {})
    assert run(Bad()).state == "could_not_check"
    assert len(run(Mixed()).findings) == 1


def test_a_stop_is_never_swallowed():
    class Stopped(engines.Engine):
        async def run(self, ctx, state, guard):
            raise ScanStopped("website_removed")
    with pytest.raises(ScanStopped):
        run(Stopped())


def test_registry_rejects_duplicates_and_new_engines_plug_in():
    class Extra(engines.Engine):
        name = "extra-test"
    engines.register(Extra())
    try:
        assert "extra-test" in [e.name for e in engines.registered()]
        with pytest.raises(ValueError):
            engines.register(Extra())
    finally:
        engines.unregister("extra-test")
    assert "extra-test" not in [e.name for e in engines.registered()]
    from app.services import identify
    identify.register_builtin()
    identify.register_builtin()  # registering twice changes nothing
    assert [e.name for e in engines.registered()].count("configuration") == 1
    assert {"configuration", "vulnerabilities", "lifecycle"} <= {e.name for e in engines.registered()}


def test_the_merged_finding_keeps_the_most_trusted_sources_identity_whatever_order_engines_finish_in():
    import itertools
    builtin = make(kind="exposure", check_id="exposed:index-of:/backup/", title="A folder's contents are listed publicly", location="example.com/backup/",
                   cve_id=None, severity="medium", sources=["snwebshield"])
    nuclei = make(kind="exposure", check_id="nuclei:backup-directory-listing", title="Directory listing", location="example.com/backup/",
                  cve_id=None, severity="medium", sources=["nuclei"])
    nuclei.details["equivalent_to"] = "exposed:index-of:/backup/"
    for order in itertools.permutations([builtin, nuclei]):
        [one] = merge([Finding(**{**x.__dict__}) for x in order])
        assert one.check_id == "exposed:index-of:/backup/" and one.sources == ["nuclei", "snwebshield"] and one.fingerprint == builtin.fingerprint
    nvd = make(check_id="cve:CVE-2017-9788", cve_id="CVE-2017-9788", sources=["nvd"])
    nuc = make(check_id="nuclei:CVE-2017-9788", cve_id="CVE-2017-9788", sources=["nuclei"])
    for order in itertools.permutations([nvd, nuc]):
        [one] = merge([Finding(**{**x.__dict__}) for x in order])
        assert one.check_id == "cve:CVE-2017-9788"
