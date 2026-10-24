"""A scope-bound, SSRF-guarded HTTP client built on the standard library.

Design choices that matter for safety:
  * Every request is checked against the scope (host/port/scheme) first.
  * The target host is resolved and validated against the SSRF policy before a
    request is sent; private/reserved destinations are refused.
  * Redirects are NOT followed automatically — each hop is re-validated.
  * Bodies are read up to a hard cap; the socket is closed past it.
  * A global request budget and a rate limit bound total activity.

`allow_private=True` is an explicit opt-in used only by the bundled localhost
lab and the test fixtures. External assessments always run with it False.
"""

from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass, field

from .netutil import Target, normalize_url, in_scope, check_host_safe


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
        self.allow_private = allow_private
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
        history: list[tuple[str, int]] = []
        current = target
        for _ in range(max_redirects + 1):
            resp = self._single(method, current, headers=headers, body=body)
            resp.history = list(history)
            if not resp.ok or not follow or not (300 <= resp.status < 400):
                return resp
            loc = resp.header("location")
            if not loc:
                return resp
            history.append((current.url, resp.status))
            nxt = _resolve_redirect(current, loc)
            if nxt is None:
                resp.reason = "redirect target unparseable; not followed"
                return resp
            ok, why = in_scope(nxt, self.allowed_hosts, self.allowed_ports, self.allowed_schemes)
            if not ok:
                resp.reason = f"redirect left scope ({why}); not followed"
                return resp
            # subsequent hops become GET without the original body (standard)
            method, current, body = "GET", nxt, None
        # too many redirects
        resp.reason = "too many redirects"
        return resp

    # ----------------------------------------------------------------- private
    def _single(self, method, target, *, headers=None, body=None) -> Response:
        out = Response(url=target.url, method=method)

        ok, why = in_scope(target, self.allowed_hosts, self.allowed_ports, self.allowed_schemes)
        if not ok:
            out.blocked, out.reason = True, f"out of scope: {why}"
            return out

        if not self.allow_private:
            chk = check_host_safe(target.host)
            if not chk.allowed:
                out.blocked, out.reason = True, f"ssrf guard: {chk.reason}"
                return out

        if self.count >= self.max_requests:
            out.blocked, out.reason = True, "request budget exceeded"
            raise RequestBudgetExceeded(target.url)

        self._throttle()
        self.count += 1

        last_err = None
        for attempt in range(self.retries + 1):
            started = time.monotonic()
            conn = None
            try:
                if target.scheme == "https":
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        target.host, target.port, timeout=self.timeout, context=ctx
                    )
                else:
                    conn = http.client.HTTPConnection(
                        target.host, target.port, timeout=self.timeout
                    )
                req_headers = {
                    "Host": target.host,
                    "User-Agent": self.user_agent,
                    "Accept": "*/*",
                    "Connection": "close",
                }
                if headers:
                    req_headers.update(headers)
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


def _resolve_redirect(base: Target, location: str) -> Target | None:
    from urllib.parse import urljoin

    try:
        return normalize_url(urljoin(base.url, location.strip()))
    except ValueError:
        return None
