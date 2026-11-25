"""Which ports a scan checks.

* standard scan (every plan): the fixed top-1,000 TCP ports (`top_ports.py`, from Nmap's `nmap-services`) plus the
  database ports the product spec calls out as risky but Nmap's default top 1,000 omits (6379 Redis, 27017 MongoDB).
* full scan (Pro and above): every port from 1 to 65535.
"""
from app.data.top_ports import SERVICE_NAMES as _NMAP_NAMES, TOP_TCP_PORTS

EXTRA_RISKY_PORTS = tuple(p for p in (6379, 27017) if p not in TOP_TCP_PORTS)
STANDARD_PORTS = tuple(TOP_TCP_PORTS) + EXTRA_RISKY_PORTS
FULL_PORTS = tuple(range(1, 65536))
SERVICE_NAMES = {**_NMAP_NAMES, 6379: "redis", 27017: "mongodb"}


def ports_for(scan_type: str) -> tuple[int, ...]:
    return FULL_PORTS if scan_type == "full" else STANDARD_PORTS
