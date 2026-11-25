"""A minimal, defensive reader for the few fields of an X.509 certificate that a scan records:
subject, issuer, validity dates, DNS names (SAN) and whether it is self-signed.

The input is untrusted (it comes from the scanned server), so every read is bounds-checked and any malformed
input returns None instead of raising. No signature or chain validation happens here; it only reads fields.
"""
from datetime import datetime, timezone

from app.services.netio import clean_text

OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}
SAN_OID = "2.5.29.17"
MAX_DEPTH_BYTES = 64 * 1024


class _Bad(Exception):
    pass


def _tlv(buf: bytes, pos: int):
    """Return (tag, start_of_content, end_of_content) for the element at pos."""
    if pos + 2 > len(buf):
        raise _Bad
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(buf):
            raise _Bad
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(buf):
        raise _Bad
    return tag, pos, end


def _children(buf: bytes, start: int, end: int):
    pos = start
    while pos < end:
        tag, cs, ce = _tlv(buf, pos)
        yield tag, cs, ce, pos
        pos = ce


def _oid(buf: bytes, start: int, end: int) -> str:
    data = buf[start:end]
    if not data:
        raise _Bad
    parts = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return raw.decode("utf-32-be", "replace")
    return raw.decode("utf-8", "replace")


def _name(buf: bytes, start: int, end: int):
    """Return ('CN=a, O=b', cn) for a Name."""
    parts, cn = [], None
    for _, rs, re_, _ in _children(buf, start, end):          # RDN (SET)
        for tag, as_, ae, _ in _children(buf, rs, re_):        # AttributeTypeAndValue (SEQUENCE)
            items = list(_children(buf, as_, ae))
            if len(items) < 2:
                continue
            oid = _oid(buf, items[0][1], items[0][2])
            value = clean_text(_string(items[1][0], buf[items[1][1]:items[1][2]]), 200)
            label = OIDS.get(oid, oid)
            parts.append(f"{label}={value}")
            if label == "CN" and cn is None:
                cn = value
    return ", ".join(parts), cn


def _time(tag: int, raw: bytes) -> str | None:
    text = raw.decode("ascii", "replace")
    try:
        if tag == 0x17:
            year = int(text[:2])
            stamp = datetime.strptime(("19" if year >= 50 else "20") + text[:12], "%Y%m%d%H%M%S")
        elif tag == 0x18:
            stamp = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
        else:
            return None
    except ValueError:
        return None
    return stamp.replace(tzinfo=timezone.utc).isoformat()


def parse_certificate(der: bytes) -> dict | None:
    try:
        if not der or len(der) > MAX_DEPTH_BYTES:
            return None
        tag, cs, ce = _tlv(der, 0)
        if tag != 0x30:
            return None
        tbs_tag, ts, te = _tlv(der, cs)
        if tbs_tag != 0x30:
            return None
        items = list(_children(der, ts, te))
        index = 1 if items and items[0][0] == 0xA0 else 0     # skip the optional version
        # items[index] serial, +1 signature algorithm, +2 issuer, +3 validity, +4 subject
        issuer_item, validity, subject_item = items[index + 2], items[index + 3], items[index + 4]
        issuer, issuer_cn = _name(der, issuer_item[1], issuer_item[2])
        subject, subject_cn = _name(der, subject_item[1], subject_item[2])
        times = list(_children(der, validity[1], validity[2]))
        not_before = _time(times[0][0], der[times[0][1]:times[0][2]])
        not_after = _time(times[1][0], der[times[1][1]:times[1][2]])
        san: list[str] = []
        for tag_, s, e, _ in items[index + 5:]:
            if tag_ != 0xA3:
                continue
            ext_seq = next(_children(der, s, e))
            for _, es, ee, _ in _children(der, ext_seq[1], ext_seq[2]):
                parts = list(_children(der, es, ee))
                if _oid(der, parts[0][1], parts[0][2]) != SAN_OID:
                    continue
                octets = parts[-1]
                inner_tag, is_, ie = _tlv(der, octets[1])  # the OCTET STRING wraps a SEQUENCE of GeneralNames
                for gtag, gs, ge, _ in _children(der, is_, ie):
                    if gtag == 0x82 and len(san) < 50:
                        san.append(clean_text(der[gs:ge], 255).lower())
        return {"subject": subject, "subject_cn": subject_cn, "issuer": issuer, "issuer_cn": issuer_cn,
                "not_before": not_before, "not_after": not_after, "san": san,
                "self_signed": der[subject_item[3]:subject_item[2]] == der[issuer_item[3]:issuer_item[2]]}
    except (_Bad, IndexError, StopIteration, ValueError):
        return None
