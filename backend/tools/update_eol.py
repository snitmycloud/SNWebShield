"""Developer tool: refresh app/data/eol.json from endoflife.date (MIT-licensed project, https://endoflife.date).

Run by a developer, never by a scan: scans make NO network call for end-of-life data, they read the committed file.
It sends no scan or user data (only fixed product names), waits between requests, and writes the file only if every
request worked. Review the diff, then commit.

    python tools/update_eol.py
"""
import json
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path

PRODUCTS = ("ubuntu", "debian", "centos", "rhel", "almalinux", "rocky-linux", "php", "apache-http-server", "nginx", "mysql",
            "mariadb", "wordpress", "tomcat", "nodejs", "postgresql", "windows-server")
OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "eol.json"
KEEP = ("cycle", "releaseDate", "eol", "extendedSupport", "support", "lts", "latest")


def fetch(slug: str):
    request = urllib.request.Request(f"https://endoflife.date/api/{slug}.json",
                                     headers={"User-Agent": "SNWebShield-data-update/1.0 (developer tool)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read(2_000_000))


def main() -> int:
    products, failed = {}, []
    for slug in PRODUCTS:
        try:
            rows = fetch(slug)
            products[slug] = [{k: row[k] for k in KEEP if k in row} for row in rows]
            print(f"{slug}: {len(rows)} releases")
        except Exception as error:
            failed.append(slug)
            print(f"{slug}: FAILED ({type(error).__name__})")
        time.sleep(1.5)
    if failed:
        print("Not written: some products failed:", ", ".join(failed))
        return 1
    OUT.write_text(json.dumps({"as_of": date.today().isoformat(), "source": "https://endoflife.date (MIT licence)", "products": products},
                              indent=1, sort_keys=True), encoding="utf-8")
    print("Wrote", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
