"""Turn whatever the owner typed into one canonical host name, or refuse it with a plain reason."""
import ipaddress
import re

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# Names that only exist inside private networks or are reserved for documentation and testing.
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".private",
                     ".localdomain", ".home.arpa", ".arpa", ".test", ".example", ".invalid", ".onion")


class DomainError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip()
    if not value or len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise DomainError("Enter a website address, for example www.example.com.")
    value = value.lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)  # http://, https://
    value = re.split(r"[/?#\\]", value, maxsplit=1)[0]   # paths, query strings, trailing slashes
    if "@" in value:
        raise DomainError("Enter only the website address, without a username or password.")
    if value.startswith("["):
        raise DomainError("Enter a domain name, not an IP address.")
    host, _, port = value.rpartition(":") if value.count(":") == 1 else (value, "", "")
    if port and not port.isdigit():
        raise DomainError("That does not look like a website address.")
    host = (host or value).rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise DomainError("Enter a domain name, not an IP address.")
    if ":" in host:
        raise DomainError("Enter a domain name, not an IP address.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise DomainError("That domain name contains characters that are not allowed.") from error
    if re.fullmatch(r"[0-9.]+", host):
        raise DomainError("Enter a domain name, not an IP address.")
    if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
        raise DomainError("That is an internal name. Enter your public website address.")
    labels = host.split(".")
    if len(labels) < 2:
        raise DomainError("Enter the full domain name, for example example.com.")
    if len(host) > 253 or not all(LABEL.match(label) for label in labels):
        raise DomainError("That does not look like a valid domain name.")
    if not (labels[-1].isalpha() or labels[-1].startswith("xn--")):
        raise DomainError("That does not look like a valid domain name.")
    return host


def parents(domain: str) -> list[str]:
    """Parent domains, nearest first, excluding the bare top-level label: a.b.example.com -> b.example.com, example.com."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def covers(verified: str, domain: str) -> bool:
    """Verifying example.com covers its subdomains; verifying www.example.com covers only that host."""
    if verified == domain:
        return True
    return not verified.startswith("www.") and domain.endswith("." + verified)
