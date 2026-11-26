"""Is a reported software version a distribution's package (Ubuntu, Debian, Red Hat family) or behind a proxy/CDN?

Both make an 'old-looking' version unreliable for vulnerability matching:
* Linux distributions routinely fix security problems in their package WITHOUT changing the upstream version number
  ("backporting"), so "Apache 2.4.7 (Ubuntu)" or "OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" may already be patched;
* a proxy or CDN may report its own version, not the origin server's.
Findings for such items are therefore only ever `possible`, with the caveat below, and never count in the score.
"""
import re

FAMILIES = (
    ("ubuntu", re.compile(r"ubuntu", re.I)),
    ("debian", re.compile(r"debian|\+deb\d+u\d+|~deb\d+u\d+|raspbian", re.I)),
    ("rhel", re.compile(r"centos|red hat|redhat|rhel|\.el\d|fedora|alma ?linux|rocky|oracle linux|amzn|amazon linux", re.I)),
)
PROXY_HEADERS = ("via", "cf-ray", "x-served-by", "x-cache", "x-amz-cf-id")

CHECK_HELP = {
    "ubuntu": "On the server run `ubuntu-security-status`, or `apt changelog {package} | grep CVE-` to see which CVEs your installed package already fixes.",
    "debian": "On the server run `apt changelog {package} | grep CVE-`, or check the Debian security tracker (security-tracker.debian.org) for your release.",
    "rhel": "On the server run `rpm -q --changelog {package} | grep CVE-`, or `yum updateinfo list cves`, to see which CVEs your installed package already fixes.",
}
NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "Red Hat / CentOS"}
PACKAGES = {"openssh": "openssh-server", "apache": "apache2", "nginx": "nginx", "php": "php", "mysql": "mysql-server",
            "mariadb": "mariadb-server", "proftpd": "proftpd-basic", "vsftpd": "vsftpd", "exim": "exim4", "postfix": "postfix",
            "dovecot": "dovecot-core", "lighttpd": "lighttpd", "sendmail": "sendmail"}


def detect_family(*texts) -> str | None:
    """'ubuntu' | 'debian' | 'rhel' | None, from the banner or header text that carried the version."""
    blob = " ".join(str(t) for t in texts if t)
    for family, pattern in FAMILIES:
        if pattern.search(blob):
            return family
    return None


def behind_proxy(headers: dict | None) -> bool:
    return bool(headers) and any(name in headers for name in PROXY_HEADERS)


def caveat(family: str | None, product: str, display: str, version: str, proxy: bool = False) -> str | None:
    if family:
        package = PACKAGES.get(product, product)
        if family == "rhel":
            package = {"apache": "httpd", "openssh": "openssh-server"}.get(product, package)
        return (f"Your server reports {display} {version} as a {NAMES[family]} package. {NAMES[family]} often fixes security "
                f"problems without changing this version number, so these issues may already be fixed. "
                + CHECK_HELP[family].format(package=package))
    if proxy:
        return (f"The version {display} {version} may belong to a proxy or CDN in front of your server rather than to your "
                "server itself, so we cannot be sure these issues apply.")
    return None
