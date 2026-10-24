"""A scope-bound, SSRF-guarded HTTP client built on the standard library.

Safety properties:
  * Scope (host/port/scheme) is checked before any connection.
  * The host is resolved, every resolved address is validated against the SSRF
    policy, and the socket is then **pinned to a validated IP** — the hostname
    is never re-resolved during connect, so a DNS-rebinding answer cannot swap
    in a private address. Mixed public/private answers fail closed.
  * TLS keeps the original hostname for SNI and certificate verification.
  * Redirects are followed manually with correct per-status-code method/body
    semantics; each hop is re-validated, and credentials are dropped when the
    host changes.
  * Bodies are capped; a global request budget and a rate limit bound activity.

Private/loopback targets are refused unless the host is in `private_hosts`
(explicitly approved local labs) — there is no global private-network bypass.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field

from .netutil import (
    Target, normalize_url, in_scope, resolve_and_pin,
)

_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization"}


@dataclass
class Response:
    url: str
    method: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: int = 0
    history: list[tuple[str, int]] = field(default_factory=list)
    error: str | None = None
    blocked: bool = False
    reason: str = ""
    truncated: bool = False
    pinned_ip: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and not self.blocked and self.status != 0

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class RequestBudgetExceeded(Exception):
    pass


# --------------------------------------------------------- pinned connections

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        # connect to the already-validated IP; self.host stays the hostname so
        # the Host header is correct and no re-resolution happens.
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, pinned_ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        # SNI + certificate verification use the hostname, not the pinned IP.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class HttpClient:
    def __init__(
        self,
        allowed_hosts: set[str],
        allowed_ports: set[int],
        allowed_schemes: set[str],
        *,
        timeout: float = 10.0,
        retries: int = 2,
        max_response_bytes: int = 512 * 1024,
        rate_limit_per_sec: float = 8.0,
        max_requests: int = 300,
        allow_private: bool = False,
        private_hosts: set[str] | None = None,
        auth_headers: dict[str, str] | None = None,
        user_agent: str = "MURS/1.0 (+authorized-research)",
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = allowed_ports
        self.allowed_schemes = allowed_schemes
        self.timeout = timeout
        self.retries = max(0, retries)
        self.max_response_bytes = max_response_bytes
        self.min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec > 0 else 0.0
        self.max_requests = max_requests
        # scope the private bypass: only these hosts skip the SSRF policy.
        if private_hosts is not None:
            self.private_hosts = {h.lower() for h in private_hosts}
        elif allow_private:
            self.private_hosts = {h.lower() for h in allowed_hosts}
        else:
            self.private_hosts = set()
        # user-supplied auth (e.g. a test session cookie); sent only in scope,
        # never stored on responses or written to reports.
        self.auth_headers = dict(auth_headers or {})
        self.user_agent = user_agent
        self.count = 0
        self._last_ts = 0.0

    # ------------------------------------------------------------------ public
    def get(self, target: Target, *, follow: bool = True, max_redirects: int = 5) -> Response:
        return self.request("GET", target, follow=follow, max_redirects=max_redirects)

    def request(
        self,
        method: str,
        target: Target,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        follow: bool = True,
        max_redirects: int = 5,
    ) -> Response:
        current = target
        # auth headers are attached here (not in _single) so a host change in a
        # redirect drops them, never forwarding credentials to another host.
        hdrs = dict(headers or {})
        hdrs.update(self.auth_headers)
        strip_keys = _SENSITIVE_HEADERS | {k.lower() for k in self.auth_headers}
        sent_body = body
        history: list[tuple[str, int]] = []
        for _ in range(max_redirects + 1):
            resp = self._single(method, current, headers=hdrs, body=sent_body)
            resp.history = list(history)
            if not resp.ok or not follow or not (300 <= resp.status < 400):
                return resp
            loc = resp.header("location")
            if not loc:
                return resp
            nxt = _resolve_redirect(current, loc)
            if nxt is None:
                resp.reason = "redirect target unparseable; not followed"
                return resp
            ok, why = in_scope(nxt, self.allowed_hosts, self.allowed_ports, self.allowed_schemes)
            if not ok:
                resp.reason = f"redirect left scope ({why}); not followed"
                return resp
            history.append((current.url, resp.status))
            method, sent_body, hdrs = _redirect_next(resp.status, method, sent_body, hdrs,
                                                      current.host, nxt.host, strip_keys)
            current = nxt
        resp.reason = "too many redirects"
        return resp

    # ----------------------------------------------------------------- private
    def _single(self, method, target, *, headers=None, body=None) -> Response:
        out = Response(url=target.url, method=method)

        ok, why = in_scope(target, self.allowed_hosts, self.allowed_ports, self.allowed_schemes)
        if not ok:
            out.blocked, out.reason = True, f"out of scope: {why}"
            return out

        private_ok = target.host.lower() in self.private_hosts
        pinned_ip, reason, _all = resolve_and_pin(target.host, private_ok=private_ok)
        if pinned_ip is None:
            out.blocked, out.reason = True, f"ssrf guard: {reason}"
            return out
        out.pinned_ip = pinned_ip

        if self.count >= self.max_requests:
            out.blocked, out.reason = True, "request budget exceeded"
            raise RequestBudgetExceeded(target.url)

        self._throttle()
        self.count += 1

        req_headers = {
            "Host": target.host,
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
        # auth is injected by request() into `headers`, so it is dropped on a
        # host change rather than re-added here on every hop.
        if headers:
            req_headers.update(headers)

        last_err = None
        started = time.monotonic()
        for attempt in range(self.retries + 1):
            started = time.monotonic()
            conn = None
            try:
                if target.scheme == "https":
                    ctx = ssl.create_default_context()
                    conn = _PinnedHTTPSConnection(target.host, target.port, pinned_ip,
                                                  self.timeout, ctx)
                else:
                    conn = _PinnedHTTPConnection(target.host, target.port, pinned_ip,
                                                 self.timeout)
                conn.request(method, target.path or "/", body=body, headers=req_headers)
                r = conn.getresponse()
                out.status = r.status
                raw_headers: dict[str, str] = {}
                for k, v in r.getheaders():
                    lk = k.lower()
                    if lk == "set-cookie":
                        out.set_cookies.append(v)
                    raw_headers[lk] = v
                out.headers = raw_headers
                data = r.read(self.max_response_bytes + 1)
                if len(data) > self.max_response_bytes:
                    out.truncated = True
                    data = data[: self.max_response_bytes]
                out.body = data
                out.elapsed_ms = int((time.monotonic() - started) * 1000)
                return out
            except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                last_err = f"{type(e).__name__}: {e}"
                time.sleep(min(0.5 * (2**attempt), 2.0))
            finally:
                if conn is not None:
                    conn.close()
        out.error = last_err or "request failed"
        out.elapsed_ms = int((time.monotonic() - started) * 1000)
        return out

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        wait = self.min_interval - (now - self._last_ts)
        if wait > 0:
            time.sleep(wait)
        self._last_ts = time.monotonic()


def _redirect_next(status, method, body, headers, old_host, new_host, strip_keys):
    """Apply correct per-code redirect semantics and strip creds across hosts."""
    method = method.upper()
    if status in (301, 302):
        if method not in ("GET", "HEAD"):
            method, body = "GET", None
    elif status == 303:
        if method != "HEAD":
            method, body = "GET", None
    # 307 / 308: preserve method and body verbatim
    hdrs = dict(headers or {})
    if new_host.lower() != old_host.lower():
        hdrs = {k: v for k, v in hdrs.items() if k.lower() not in strip_keys}
    return method, body, hdrs


def _resolve_redirect(base: Target, location: str) -> Target | None:
    from urllib.parse import urljoin

    try:
        return normalize_url(urljoin(base.url, location.strip()))
    except ValueError:
        return None
