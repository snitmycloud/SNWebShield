"""Trusted namespace policy helper. Root/NET_ADMIN confined to its own container."""
import importlib.util
import json
import signal
import subprocess
import sys
import time

signal.alarm(35)
spec = importlib.util.spec_from_file_location("nmap_policy", "/app/nmap_policy.py")
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
raw = sys.stdin.buffer.readline(1025)
if len(raw) > 1024: raise SystemExit(2)
data = json.loads(raw)
if not isinstance(data, dict) or set(data) != {"ip"}: raise SystemExit(2)
ip = policy.public_ipv4(data["ip"])
rules = ["*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT DROP [0:0]"]
for port in policy.PORTS:
    rules += [f"-A OUTPUT -p tcp -d {ip}/32 --dport {port} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
              f"-A INPUT -p tcp -s {ip}/32 --sport {port} -m conntrack --ctstate ESTABLISHED -j ACCEPT"]
rules += ["COMMIT", ""]
subprocess.run(["/usr/sbin/iptables-restore", "--wait", "2"], input="\n".join(rules).encode(), check=True, timeout=4)
subprocess.run(["/usr/sbin/ip6tables-restore", "--wait", "2"],
    input=b"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n", check=True, timeout=4)
print('{"ready":true}', flush=True)
# There are no listeners, host mounts or arbitrary commands. Exit independently
# even if Windows or the SSH runner disappears. The scanner has a shorter alarm.
time.sleep(30)
