"""URL normalization, DNS/IP validation (SSRF defence), and scope enforcement.

The policy fails closed: anything that cannot be parsed or resolved to a
provably global (public) address is treated as out of scope and not requested.
"""

from __future__ import annotations

import ipaddress
import re
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
    query: str = ""

    @property
    def authority(self) -> str:
        """host[:port] with IPv6 literals bracketed; omits default ports."""
        h = f"[{self.host}]" if ":" in self.host else self.host
        if (self.scheme, self.port) in (("http", 80), ("https", 443)):
            return h
        return f"{h}:{self.port}"

    @property
    def host_header(self) -> str:
        """Value for the HTTP Host header (bracketed IPv6, non-default port)."""
        return self.authority

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def request_target(self) -> str:
        """Path plus query — never the fragment — for the request line."""
        p = self.path or "/"
        return f"{p}?{self.query}" if self.query else p

    @property
    def url(self) -> str:
        return self.origin + self.request_target


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
    # preserve the query; the fragment is intentionally dropped (never sent).
    return Target(scheme=scheme, host=host, port=port, path=path, query=parts.query)


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


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def ip_is_loopback(ip_text: str) -> bool:
    """True only for loopback addresses (127.0.0.0/8, ::1, ::ffff:127.0.0.0/8)."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def resolve_and_pin(host: str, lab_private_ok: bool = False) -> tuple[str | None, str, tuple[str, ...]]:
    """Resolve + validate a host and return (pinned_ip, reason, all_ips).

    pinned_ip is the single address the caller must connect to; it is None when
    the host is blocked. Fails closed.

    The lab exception (`lab_private_ok`, set only for explicitly approved local
    targets) is deliberately narrow: it permits **loopback addresses only**. An
    approved hostname that resolves to anything other than loopback — a LAN
    address, link-local, or the cloud metadata service — is still refused, and
    every resolved address must be loopback (no mixed answers). Approval of a
    hostname is never taken as blanket trust in whatever DNS returns.
    """
    if is_ip_literal(host):
        if lab_private_ok:
            if ip_is_loopback(host):
                return host, "approved loopback literal", (host,)
            if ip_is_disallowed(host):
                return None, "approved host is not loopback (lab exception is loopback-only)", (host,)
            return host, "ok (public literal)", (host,)
        if ip_is_disallowed(host):
            return None, "literal IP is private/reserved", (host,)
        return host, "ok (public literal)", (host,)
    ips = resolve_host(host)
    if not ips:
        return None, "host does not resolve", ()
    if lab_private_ok:
        # every resolved address must be loopback, or we fail closed.
        non_loopback = [ip for ip in ips if not ip_is_loopback(ip)]
        if non_loopback:
            return None, (f"approved host resolved to non-loopback address "
                          f"{non_loopback[0]} (lab exception is loopback-only)"), tuple(ips)
        return ips[0], "approved loopback host", tuple(ips)
    # mixed answers: if ANY resolved address is non-global, refuse (rebinding).
    bad = [ip for ip in ips if ip_is_disallowed(ip)]
    if bad:
        return None, f"resolves to non-global address: {bad[0]}", tuple(ips)
    return ips[0], "ok", tuple(ips)


_SECRET_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|token|passwd|password|secret|api[_-]?key|session)"
    r"(\s*[:=]\s*)([^\s;,&\"']{4,})"
)
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")


def redact_secrets(text: str, limit: int = 600) -> str:
    """Mask credential-like values before anything is logged or reported."""
    if not text:
        return ""
    t = text[:limit]
    t = _SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", t)
    t = _LONG_B64.sub("[REDACTED]", t)
    return t
