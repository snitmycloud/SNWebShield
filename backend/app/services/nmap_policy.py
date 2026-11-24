"""Fixed Nmap contract shared with the reviewed scanner image; no networking here."""
import ipaddress
import re

VERSION = "ssh-nmap-web-ports-v1"
PORTS = (80, 443)
LIMITS = {"memory_bytes": 134217728, "cpus": 0.5, "pids": 16, "timeout_seconds": 12}


def public_ipv4(value):
    if not isinstance(value, str): raise ValueError("invalid_ipv4")
    ip = ipaddress.ip_address(value)
    if (ip.version != 4 or str(ip) != value or not ip.is_global or ip.is_multicast
            or ip in ipaddress.ip_network("192.0.0.0/24") or ip in ipaddress.ip_network("192.88.99.0/24")):
        raise ValueError("prohibited_destination")
    return value


def target(value):
    if not isinstance(value, dict) or set(value) != {"ip", "host", "dns_addresses"}:
        raise ValueError("invalid_target_contract")
    public_ipv4(value["ip"])
    host = value["host"]
    if (not isinstance(host, str) or len(host) > 253 or "." not in host
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))
            or host.endswith((".local", ".internal", ".localhost"))):
        raise ValueError("invalid_hostname")
    try: ipaddress.ip_address(host)
    except ValueError: pass
    else: raise ValueError("hostname_required")
    addresses = value["dns_addresses"]
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 32 or value["ip"] not in addresses:
        raise ValueError("invalid_dns_snapshot")
    for address in addresses: public_ipv4(address)
    return value


def command(ip):
    public_ipv4(ip)
    return ["/usr/bin/nmap", "--unprivileged", "-sT", "-Pn", "-n", "--disable-arp-ping",
            "-p", "80,443", "-r", "--max-retries", "0", "--max-parallelism", "1",
            "--scan-delay", "500ms", "--initial-rtt-timeout", "1s", "--max-rtt-timeout", "1s",
            "--host-timeout", "5s", "-oX", "-", ip]


def analysis(states):
    if not isinstance(states, dict) or set(states) != {"80", "443"} or any(v not in {"open", "closed", "filtered"} for v in states.values()):
        raise ValueError("invalid_port_result")
    return {"schema_version": 1, "confirmed_findings": 0,
        "observations": [{"check": "tcp_port_" + str(port), "observed": None, "port_state": states[str(port)],
            "severity_suggestion": "informational", "requires_human_validation": True, "confirmed_vulnerability": False,
            "evidence_ref": "nmap.tcp." + str(port),
            "explanation": "TCP port %s is %s. Reachability alone does not establish a vulnerability; validate expected exposure." % (port, states[str(port)])}
            for port in PORTS],
        "limitations": ["two_tcp_ports_one_ipv4", "no_service_or_version_detection", "no_scripts_or_os_detection",
            "no_host_discovery_or_dns", "no_application_requests", "short_timeouts_can_misclassify_filtered_ports",
            "shared_hosting_or_cdn_ip_may_not_represent_origin", "ports_are_not_a_security_rating"]}


def parse_result(raw, ip):
    import xml.etree.ElementTree as ET
    public_ipv4(ip)
    if len(raw) > 32768: raise ValueError("nmap_output_limit")
    root = ET.fromstring(raw)
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success": raise ValueError("nmap_failed")
    hosts = root.findall("host")
    if len(hosts) != 1: raise ValueError("one_host_required")
    address = hosts[0].find("address")
    if address is None or address.get("addr") != ip or address.get("addrtype") != "ipv4": raise ValueError("target_mismatch")
    states = {}
    for port in hosts[0].findall("ports/port"):
        number, state = port.get("portid"), port.find("state")
        if number in states or number not in {"80", "443"} or port.get("protocol") != "tcp" or state is None:
            raise ValueError("unexpected_port_result")
        states[number] = state.get("state")
    missing = {"80", "443"} - set(states)
    extras = hosts[0].findall("ports/extraports")
    if extras:
        if len(extras) != 1 or not missing or extras[0].get("count") != str(len(missing)): raise ValueError("ambiguous_port_summary")
        states.update({port: extras[0].get("state") for port in missing})
    analysis(states)
    return states
