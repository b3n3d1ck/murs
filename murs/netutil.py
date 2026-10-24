"""URL normalization, DNS/IP validation (SSRF defence), and scope enforcement.

The policy fails closed: anything that cannot be parsed or resolved to a
provably global (public) address is treated as out of scope and not requested.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, quote

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str

    @property
    def origin(self) -> str:
        if (self.scheme, self.port) in (("http", 80), ("https", 443)):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return self.origin + (self.path or "/")


def normalize_url(raw: str, default_scheme: str = "https") -> Target:
    """Accept a URL with or without a scheme (and with or without 'www').

    Raises ValueError on input that has no usable host.
    """
    if raw is None:
        raise ValueError("empty URL")
    s = raw.strip()
    if not s:
        raise ValueError("empty URL")
    if "://" not in s:
        # bare host or host/path — give it a scheme so urlsplit sees a netloc
        s = f"{default_scheme}://{s}"
    parts = urlsplit(s)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme: {scheme!r}")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"no host in URL: {raw!r}")
    port = parts.port or DEFAULT_PORTS[scheme]
    path = parts.path or "/"
    return Target(scheme=scheme, host=host, port=port, path=path)


def join_in_scope(base: Target, href: str) -> Target | None:
    """Resolve a link against the base; return a Target or None if unusable."""
    href = (href or "").strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    from urllib.parse import urljoin

    absolute = urljoin(base.url, href)
    try:
        return normalize_url(absolute)
    except ValueError:
        return None


# --------------------------------------------------------------------------- IP

def ip_is_disallowed(ip_text: str) -> bool:
    """True if an address is not a provably-global public address.

    Covers loopback, private (RFC1918), link-local / cloud metadata, CGNAT,
    reserved, multicast, unspecified, and IPv4-mapped IPv6. Fails closed.
    """
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    # unwrap IPv4-mapped / 6to4-ish embeddings to their v4 form
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    try:
        if not ip.is_global:
            return True
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_host(host: str) -> list[str]:
    """Resolve a host to the list of IP strings it maps to (A + AAAA)."""
    out: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in out:
                out.append(ip)
    except socket.gaierror:
        return []
    return out


@dataclass(frozen=True)
class HostCheck:
    allowed: bool
    reason: str
    ips: tuple[str, ...] = ()


def check_host_safe(host: str) -> HostCheck:
    """Resolve + validate a host against the SSRF policy."""
    # a literal IP?
    try:
        ipaddress.ip_address(host)
        if ip_is_disallowed(host):
            return HostCheck(False, "literal IP is private/reserved", (host,))
        return HostCheck(True, "ok (literal public IP)", (host,))
    except ValueError:
        pass
    ips = resolve_host(host)
    if not ips:
        return HostCheck(False, "host does not resolve")
    bad = [ip for ip in ips if ip_is_disallowed(ip)]
    if bad:
        return HostCheck(False, f"resolves to non-global address: {bad[0]}", tuple(ips))
    return HostCheck(True, "ok", tuple(ips))


# ------------------------------------------------------------------------- scope

def in_scope(target: Target, allowed_hosts: set[str], allowed_ports: set[int],
             allowed_schemes: set[str]) -> tuple[bool, str]:
    """Pure scope check (no network). Host must be explicitly allowed."""
    if target.scheme not in allowed_schemes:
        return False, f"scheme {target.scheme} not in scope"
    if target.host not in allowed_hosts:
        return False, f"host {target.host} not in scope"
    if target.port not in allowed_ports:
        return False, f"port {target.port} not in scope"
    return True, "in scope"


def safe_path(path: str) -> str:
    """Percent-encode a path for a request line, keeping common URL chars."""
    return quote(path, safe="/-._~!$&'()*+,;=:@%?#[]")
