"""The minimal certificate reader: correct fields from a real certificate, and never an exception on hostile input."""
import random
import ssl
from datetime import datetime, timezone

from app.services.x509_lite import parse_certificate
from netfixtures import CERT


def der() -> bytes:
    return ssl.PEM_cert_to_DER_cert(CERT.read_text())


def test_reads_subject_issuer_dates_and_names():
    cert = parse_certificate(der())
    assert cert["subject_cn"] == "test.snwebshield.example" and "O=SNWebShield Tests" in cert["subject"]
    assert cert["issuer_cn"] == "test.snwebshield.example"
    assert cert["self_signed"] is True
    assert cert["san"] == ["test.snwebshield.example", "alt.snwebshield.example"]
    assert datetime.fromisoformat(cert["not_before"]) <= datetime.now(timezone.utc) < datetime.fromisoformat(cert["not_after"])


def test_malformed_input_returns_none_and_never_raises():
    data = der()
    assert parse_certificate(b"") is None and parse_certificate(None) is None
    assert parse_certificate(b"\x30\x82\xff\xff" + b"A" * 20) is None
    assert parse_certificate(b"\x04\x03abc") is None
    assert parse_certificate(b"\x00" * 70000) is None  # larger than any certificate we accept
    for cut in range(0, len(data), 7):  # every truncation
        parse_certificate(data[:cut])
    rng = random.Random(7)
    for _ in range(300):  # random corruption
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        parse_certificate(bytes(mutated))
    for _ in range(100):  # pure noise
        parse_certificate(bytes(rng.randrange(256) for _ in range(rng.randint(1, 400))))


def test_text_from_a_certificate_is_cleaned():
    # Same length (17 bytes), so the certificate stays well-formed; the control character must still be removed.
    cert = parse_certificate(der().replace(b"SNWebShield Tests", b"SNWebShield\x07Tests"))
    assert cert is not None and "\x07" not in cert["subject"] and "SNWebShieldTests" in cert["subject"]
