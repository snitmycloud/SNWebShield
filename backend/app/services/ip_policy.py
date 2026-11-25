"""Which addresses SNWebShield may ever contact (fail closed).

Refused: private, loopback, link-local, multicast, carrier-grade NAT, cloud-metadata and other special-purpose
ranges, IPv4-mapped/translated IPv6, and this server's own addresses.
"""
import ipaddress
import socket

from app.core.config import settings

PROHIBITED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001::/23", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8", "3fff::/20",
))
# Cloud instance-metadata endpoints (most are also link-local; listed so the intent is explicit).
METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
))


class Blocked(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def server_addresses() -> set:
    found = set()
    for item in (part.strip() for part in settings.server_public_ips.split(",")):
        if item:
            try:
                found.add(ipaddress.ip_address(item))
            except ValueError:
                pass
    try:
        for *_, address in socket.getaddrinfo(socket.gethostname(), None):
            found.add(ipaddress.ip_address(address[0].split("%")[0]))
    except (OSError, ValueError):
        pass
    return found


def refusal_reason(ip, own=None) -> str | None:
    """None when the address may be contacted, otherwise a reason code."""
    ip = ipaddress.ip_address(ip) if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip
    if ip in METADATA_ADDRESSES:
        return "cloud_metadata_address"
    if any(ip in network for network in PROHIBITED_NETWORKS if network.version == ip.version):
        return "private_or_reserved_address"
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return "private_or_reserved_address"
    if ip.version == 6 and ip not in ipaddress.ip_network("2000::/3"):
        return "private_or_reserved_address"
    if ip in (server_addresses() if own is None else own):
        return "server_own_address"
    return None


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve once. Every answer must be allowed, otherwise the whole host is refused (no partial trust)."""
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as error:
        raise Blocked("dns_lookup_failed") from error
    addresses = []
    own = server_addresses()
    for *_, address in records:
        ip = ipaddress.ip_address(address[0].split("%")[0])
        reason = refusal_reason(ip, own)
        if reason:
            raise Blocked(reason)
        if str(ip) not in addresses:
            addresses.append(str(ip))
    if not addresses or len(addresses) > 32:
        raise Blocked("dns_lookup_failed")
    # Prefer IPv4 for a stable, single address per scan.
    return sorted(addresses, key=lambda a: ipaddress.ip_address(a).version)
