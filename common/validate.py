"""Input validators/normalizers shared by the tools.

Kept deliberately small and dependency-free. Functions normalize and validate;
they raise ``ValueError`` with a short message on bad input so tools can turn
that straight into a clean CLI error.
"""

from __future__ import annotations

import ipaddress
import re

# A registrable domain / hostname label check. Not a full RFC parser — good
# enough to reject junk before it hits an API.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def domain(value: str) -> str:
    """Normalize and validate a domain name.

    Strips a scheme, path, port, leading ``*.`` and trailing dot, and lowercases.
    ``"HTTPS://Sub.Example.com:443/x"`` -> ``"sub.example.com"``.

    Raises:
        ValueError: If the result is not a plausible domain.
    """
    v = value.strip().lower()
    v = re.sub(r"^[a-z]+://", "", v)      # scheme
    v = v.split("/", 1)[0]               # path
    v = v.split("?", 1)[0]
    v = v.split(":", 1)[0]               # port
    v = v.lstrip("*.").rstrip(".")       # wildcard / trailing dot
    if not v or not _DOMAIN_RE.match(v):
        raise ValueError(f"not a valid domain: {value!r}")
    return v


def is_subdomain_of(host: str, parent: str) -> bool:
    """True if ``host`` equals or is a subdomain of ``parent`` (case-insensitive)."""
    host, parent = host.strip(".").lower(), parent.strip(".").lower()
    return host == parent or host.endswith("." + parent)


def ip(value: str) -> str:
    """Validate an IPv4/IPv6 address, returning its normalized form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"not a valid IP address: {value!r}") from exc
