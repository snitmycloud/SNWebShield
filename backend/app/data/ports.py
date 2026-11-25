"""Which ports a scan checks.

* standard scan (every plan): the fixed top-1,000 TCP ports (`top_ports.py`, from Nmap's `nmap-services`) plus the
  risky-service ports that Nmap's default top 1,000 omits:
    - 6379  Redis and 27017 MongoDB: database ports the product spec (section 5.5) lists as risky;
    - 11211 Memcached, 2375/2376 Docker API, 5984 CouchDB, 5601 Kibana, 2379 etcd, 10250 kubelet, 15672 RabbitMQ
      management and 9300 Elasticsearch transport: commonly exposed by mistake, added on review.
  (9200 Elasticsearch and the other risky services in the spec are already in Nmap's list.)
* full scan (Pro and above): every port from 1 to 65535.
"""
from app.data.top_ports import SERVICE_NAMES as _NMAP_NAMES, TOP_TCP_PORTS

RISKY_PORT_NAMES = {
    6379: "redis", 27017: "mongodb",                                  # the spec's risky database ports
    11211: "memcached", 2375: "docker", 2376: "docker-tls",           # added on review
    5984: "couchdb", 5601: "kibana", 2379: "etcd", 10250: "kubelet",
    15672: "rabbitmq-management", 9300: "elasticsearch-transport",
}
EXTRA_RISKY_PORTS = tuple(p for p in RISKY_PORT_NAMES if p not in TOP_TCP_PORTS)
STANDARD_PORTS = tuple(TOP_TCP_PORTS) + EXTRA_RISKY_PORTS
FULL_PORTS = tuple(range(1, 65536))
SERVICE_NAMES = {**_NMAP_NAMES, **RISKY_PORT_NAMES}


def ports_for(scan_type: str) -> tuple[int, ...]:
    return FULL_PORTS if scan_type == "full" else STANDARD_PORTS
