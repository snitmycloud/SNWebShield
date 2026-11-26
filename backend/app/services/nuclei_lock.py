"""The pinned Nuclei binary: where it lives, which exact build it must be, and how to check it.

`app/data/engines.lock.json` pins the version and SHA-256 hashes. The installer (`tools/install_nuclei.py`) only installs a
download whose hash matches; the engine re-hashes the installed file before EVERY run and refuses on any difference, so
a replaced or tampered binary is never executed.
"""
import hashlib
import json
import platform
from pathlib import Path

from app.core.config import settings

LOCK_PATH = Path(__file__).resolve().parent.parent / "data" / "engines.lock.json"


class LockError(Exception):
    """The binary cannot be trusted or is not installed. `code` is a short reason safe to store and show."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))["nuclei"]


def platform_key() -> str:
    system = {"windows": "windows", "linux": "linux"}.get(platform.system().lower())
    machine = platform.machine().lower()
    if system is None or machine not in ("amd64", "x86_64"):
        raise LockError("unsupported_platform")
    return f"{system}_amd64"


def install_dir(lock: dict | None = None) -> Path:
    lock = lock or load_lock()
    return Path(settings.nuclei_dir) / f"nuclei-{lock['version']}"


def binary_path(lock: dict | None = None) -> Path:
    lock = lock or load_lock()
    return install_dir(lock) / lock["platforms"][platform_key()]["binary"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_binary() -> Path:
    """The installed binary, but only if its hash equals the pinned one. Raises LockError otherwise."""
    lock = load_lock()
    entry = lock["platforms"][platform_key()]
    path = binary_path(lock)
    if not entry.get("binary_sha256"):
        raise LockError("binary_not_pinned")
    if not path.is_file():
        raise LockError("binary_not_installed")
    if sha256_file(path) != entry["binary_sha256"]:
        raise LockError("binary_hash_mismatch")
    return path
