"""Developer tool: run the Nuclei template validator over a directory of templates and report per category.

    python tools/validate_templates.py <templates-dir> [--json report.json] [--vendor <dest-dir>]

Without --vendor nothing is written except the optional JSON report. With --vendor, ONLY templates that pass are copied (with
the licence file and a MANIFEST.json of SHA-256 hashes), and only after the owner has reviewed the report.
"""
import argparse
import hashlib
import json
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services import nuclei_templates as nt  # noqa: E402

REPORT_ORDER = ("exposures", "exposed-panels", "misconfiguration", "technologies", "cves")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--json")
    parser.add_argument("--vendor")
    parser.add_argument("--version", default="10.5.2")
    args = parser.parse_args()
    root = Path(args.directory)
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in (".yaml", ".yml") and p.is_file())
    verdicts = [nt.validate_file(path, root) for path in files]
    scoped = [v for v in verdicts if v.category]
    per = defaultdict(lambda: {"passed": 0, "rejected": 0, "reasons": Counter()})
    for verdict in scoped:
        bucket = per[verdict.category]
        if verdict.ok:
            bucket["passed"] += 1
        else:
            bucket["rejected"] += 1
            for reason in verdict.reasons:
                bucket["reasons"][reason] += 1
    print(f"Templates read: {len(files)} | in the five categories: {len(scoped)} | outside them (not considered): {len(files) - len(scoped)}")
    print(f"{'category':18}{'in scope':>9}{'passed':>8}{'rejected':>10}")
    total_pass = total_rej = 0
    for name in REPORT_ORDER:
        bucket = per[name]
        total_pass += bucket["passed"]
        total_rej += bucket["rejected"]
        print(f"{name:18}{bucket['passed'] + bucket['rejected']:>9}{bucket['passed']:>8}{bucket['rejected']:>10}")
        for reason, count in bucket["reasons"].most_common(6):
            print(f"      {count:>5}  {reason}")
    print(f"{'TOTAL':18}{total_pass + total_rej:>9}{total_pass:>8}{total_rej:>10}")
    overall = Counter(reason for v in scoped if not v.ok for reason in v.reasons)
    print("Top rejection reasons overall (a template can have several):")
    for reason, count in overall.most_common(12):
        print(f"  {count:>5}  {reason}")
    only = Counter(v.reasons[0] for v in scoped if not v.ok)
    print("First reason per rejected template:")
    for reason, count in only.most_common(10):
        print(f"  {count:>5}  {reason}")
    if args.json:
        Path(args.json).write_text(json.dumps({"scoped": len(scoped), "per_category": {k: {"passed": v["passed"], "rejected": v["rejected"], "reasons": dict(v["reasons"])} for k, v in per.items()},
                                               "overall": dict(overall)}, indent=1), encoding="utf-8")
    if args.vendor:
        dest = Path(args.vendor)
        dest.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for verdict in scoped:
            if not verdict.ok:
                continue
            data = (root / verdict.path).read_bytes()
            target = dest / verdict.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            manifest[verdict.path] = hashlib.sha256(data).hexdigest()
        for licence in ("LICENSE.md", "LICENSE", "LICENSE.txt"):
            if (root / licence).is_file():
                shutil.copyfile(root / licence, dest / "LICENSE.md")
                break
        (dest / "MANIFEST.json").write_text(json.dumps({"source": "projectdiscovery/nuclei-templates", "version": args.version,
                                                        "licence": "MIT", "templates": manifest}, indent=1, sort_keys=True), encoding="utf-8")
        print(f"Vendored {len(manifest)} templates to {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
