"""Pure header analysis. No network, file access, subprocesses or third-party code."""
ALLOWED = {"strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy", "server", "x-powered-by"}


def analyze(data):
    if not isinstance(data, dict) or set(data) != {"https", "status", "headers"}:
        raise ValueError("invalid_analysis_input")
    headers = data["headers"]
    if (type(data["https"]) is not bool or type(data["status"]) is not int
        or not 200 <= data["status"] <= 599 or not isinstance(headers, dict)
        or not set(headers) <= ALLOWED or any(not isinstance(v,str) or len(v)>2048 for v in headers.values())):
        raise ValueError("invalid_analysis_input")
    if any(any(ord(c)<32 or ord(c)==127 for c in v) for v in headers.values()):
        raise ValueError("invalid_analysis_input")
    hsts = headers.get("strict-transport-security", "").lower()
    age = [v.strip().partition("=")[2] for v in hsts.split(";") if v.strip().partition("=")[0]=="max-age"]
    positive = len(age)==1 and age[0].isascii() and age[0].isdigit() and len(age[0])<=12 and int(age[0])>0
    csp = headers.get("content-security-policy", "").lower()
    directives = {v.strip().split()[0] for v in csp.split(";") if v.strip()}
    referrer = headers.get("referrer-policy", "").lower()
    known_referrers = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "unsafe-url"}
    checks = [
        ("csp", bool(csp), "medium", "Policy presence does not prove an effective CSP."),
        ("hsts", positive if data["https"] else None, "low", "HSTS applies to HTTPS; includeSubDomains/preload need scope review."),
        ("x_frame_options", headers.get("x-frame-options", "").lower() in {"deny","sameorigin"}, "low", "CSP frame-ancestors may provide an alternative."),
        ("csp_frame_ancestors", "frame-ancestors" in directives, "informational", "Directive presence does not validate its source list."),
        ("x_content_type_options", headers.get("x-content-type-options", "").lower()=="nosniff", "low", "Check behaviour for the actual content types."),
        ("referrer_policy", referrer.split(",")[-1].strip() in known_referrers, "low", "A recognized value may still disclose more information than intended."),
        ("permissions_policy", bool(headers.get("permissions-policy")), "informational", "Presence only; feature allowlists require analyst review."),
        ("server_disclosure", not bool(headers.get("server") or headers.get("x-powered-by")), "informational", "Disclosure is not proof of an exploitable software version."),
    ]
    return {"schema_version":1, "http_status":data["status"], "confirmed_findings":0,
        "observations":[{"check":name, "observed":value, "severity_suggestion":severity if value is False else "informational",
            "requires_human_validation":True, "confirmed_vulnerability":False,
            "evidence_ref":"response.headers."+name, "explanation":explanation} for name,value,severity,explanation in checks],
        "limitations":["one_HEAD_only", "no_redirect_or_body", "headers_are_not_a_security_rating", "no_raw_header_values_retained"]}


if __name__ == "__main__":
    import sys, json, importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location("local_limits",Path(__file__).with_name("assessment_limits.py"))
    limits=importlib.util.module_from_spec(spec);spec.loader.exec_module(limits);limits.child_limits()
    raw=sys.stdin.buffer.readline(32769)
    if len(raw)>32768:raise SystemExit(2)
    print(json.dumps(analyze(json.loads(raw)),separators=(",",":")),flush=True)
