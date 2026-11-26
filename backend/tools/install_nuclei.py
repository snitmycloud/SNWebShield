"""Developer/admin tool: install the ONE pinned Nuclei binary, verified by SHA-256.

    python tools/install_nuclei.py [--platform windows_amd64|linux_amd64] [--record]

* downloads the pinned release zip from GitHub into a NEW EMPTY temporary folder (the zip is untrusted data);
* refuses it unless the zip's SHA-256 equals the pin in app/data/engines.lock.json;
* extracts ONLY the one expected file name (no paths from the archive are used, so a hostile archive cannot write elsewhere);
* hashes the extracted binary: with --record it writes that hash into the lock file (a reviewed, committed change);
  without it, the hash must already equal the pinned one, otherwise the install is refused;
* installs into `settings.nuclei_dir/nuclei-<version>/` (outside the repository) and never runs the binary.
Nothing from the scanned world is involved; only the fixed URL in the lock file is contacted.
"""
import argparse
import json
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services import nuclei_lock  # noqa: E402

MAX_ZIP_BYTES = 120 * 1024 * 1024


def download(url: str, target: Path) -> None:
    if not url.startswith("https://github.com/projectdiscovery/nuclei/releases/download/"):
        raise SystemExit("Refusing a download URL outside the pinned Nuclei release location.")
    request = urllib.request.Request(url, headers={"User-Agent": "SNWebShield-installer/1.0"})
    size = 0
    with urllib.request.urlopen(request, timeout=120) as response, open(target, "wb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ZIP_BYTES:
                raise SystemExit("The download is larger than expected; refused.")
            out.write(chunk)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default=None)
    parser.add_argument("--record", action="store_true", help="write the extracted binary's SHA-256 into the lock file")
    parser.add_argument("--no-install", action="store_true", help="verify and hash only; do not install (used for the other platform)")
    args = parser.parse_args()

    lock_raw = json.loads(nuclei_lock.LOCK_PATH.read_text(encoding="utf-8"))
    lock = lock_raw["nuclei"]
    key = args.platform or nuclei_lock.platform_key()
    entry = lock["platforms"][key]
    work = Path(tempfile.mkdtemp(prefix="snwebshield-nuclei-"))
    try:
        archive = work / "download.zip"
        print(f"Downloading {entry['url']}")
        download(entry["url"], archive)
        got = nuclei_lock.sha256_file(archive)
        print("zip sha256:", got)
        if got != entry["zip_sha256"]:
            print("REFUSED: the zip does not match the pinned SHA-256.")
            return 1
        extracted = work / "extracted"
        extracted.mkdir()
        with zipfile.ZipFile(archive) as bundle:
            names = [n for n in bundle.namelist() if n == entry["binary"]]
            if len(names) != 1:
                print("REFUSED: the archive does not contain the expected single binary.")
                return 1
            info = bundle.getinfo(names[0])
            if info.file_size > 400 * 1024 * 1024:
                print("REFUSED: the binary is larger than expected.")
                return 1
            with bundle.open(info) as src, open(extracted / entry["binary"], "wb") as dst:
                shutil.copyfileobj(src, dst)
        binary_hash = nuclei_lock.sha256_file(extracted / entry["binary"])
        print("binary sha256:", binary_hash)
        if entry.get("binary_sha256") and entry["binary_sha256"] != binary_hash:
            print("REFUSED: the binary does not match the pinned binary SHA-256.")
            return 1
        if not entry.get("binary_sha256"):
            if not args.record:
                print("The binary hash is not pinned yet. Review it, then run again with --record.")
                return 1
            entry["binary_sha256"] = binary_hash
            nuclei_lock.LOCK_PATH.write_text(json.dumps(lock_raw, indent=2) + "\n", encoding="utf-8")
            print("Recorded in", nuclei_lock.LOCK_PATH)
        if args.no_install:
            return 0
        destination = nuclei_lock.install_dir(lock)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / entry["binary"]
        shutil.copyfile(extracted / entry["binary"], target)
        if not entry["binary"].endswith(".exe"):
            target.chmod(0o755)
        print("Installed:", target)
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
