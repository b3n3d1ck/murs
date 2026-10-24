"""Active discovery engine: crawl, forms, directory probing, fingerprinting.

Discovery is bounded by the HttpClient's scope, request budget and rate limit.
Requests are issued serially under the rate limit; the `concurrency` config
value is reserved and documented as not yet parallelised (see README).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Callable

from .config import ScanConfig, wordlist_lines
from .forms import Form, parse_html
from .httpclient import HttpClient, RequestBudgetExceeded
from .netutil import Target, normalize_url, join_in_scope, in_scope

Emit = Callable[[str, str], None]

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

FALLBACK_WORDS = [
    "admin", "login", "upload", "uploads", "files", "config", ".env",
    "robots.txt", "api", "api/upload", "backup", "test", "wp-login.php",
    "wp-content/uploads",
]


@dataclass
class Endpoint:
    url: str
    method: str
    status: int
    classification: str
    content_type: str = ""
    length: int = 0
    discovered_from: str = ""
    note: str = ""
    elapsed_ms: int = 0


@dataclass
class DiscoveredForm:
    page_url: str
    action_url: str
    method: str
    enctype: str
    file_fields: list[str]
    is_upload: bool


@dataclass
class DiscoveryResult:
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    server: str = ""
    missing_security_headers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def upload_forms(self) -> list[DiscoveredForm]:
        return [f for f in self.forms if f.is_upload]


@dataclass
class _SoftNotFound:
    status: int
    length: int
    body_hash: str

    def matches(self, status: int, body: bytes) -> bool:
        if status == 404:
            return True
        if status != self.status:
            return False
        if hashlib.sha1(body[:400]).hexdigest() == self.body_hash:
            return True
        # otherwise treat as the same fallback page only when the lengths are
        # genuinely close — both a small absolute delta and a tight ratio.
        shorter, longer = sorted((len(body), self.length))
        if longer == 0:
            return True
        return (longer - shorter) <= 24 and longer <= shorter * 1.25


def _classify(status: int, softs, body: bytes) -> str:
    # `softs` may be None, a single signature, or a list of signatures.
    if softs is None:
        softs = []
    elif isinstance(softs, _SoftNotFound):
        softs = [softs]
    if status == 0:
        return "error"
    if status == 429:
        return "rate-limited"
    if status in (401, 403):
        return "auth-required"
    if status == 404:
        return "not-found"
    if 300 <= status < 400:
        return "redirect"
    if any(sig.matches(status, body) for sig in softs):
        return "not-found"
    if 200 <= status < 300:
        return "normal"
    return "ambiguous"


class DiscoveryEngine:
    def __init__(self, config: ScanConfig, client: HttpClient, emit: Emit | None = None):
        self.cfg = config
        self.client = client
        self.emit = emit or (lambda kind, msg: None)
        self.result = DiscoveryResult(base_url=config.base_url)
        self._visited: set[str] = set()
        self._softs: list[_SoftNotFound] = []

    def run(self) -> DiscoveryResult:
        base = normalize_url(self.cfg.base_url)
        self._calibrate_soft_404(base)
        try:
            self._crawl(base)
            if self.cfg.mode in ("discovery", "assessment"):
                self._wordlist(base)
        except RequestBudgetExceeded:
            self.result.notes.append("request budget reached; discovery stopped early")
            self.emit("warn", "request budget reached; stopping discovery")
        return self.result

    # ---------------------------------------------------------------- internals
    def _calibrate_soft_404(self, base: Target) -> None:
        # two probes: one without an extension and one with, because some servers
        # (e.g. PHP's built-in server) route extension-less unknown paths to the
        # directory index while returning a real 404 for extensioned ones.
        rnd = secrets.token_hex(6)
        for suffix in ("", ".htm"):
            try:
                probe = normalize_url(base.origin + f"/murs-{rnd}{suffix}")
            except ValueError:
                continue
            r = self.client.get(probe, follow=False)
            if r.ok:
                sig = _SoftNotFound(
                    status=r.status, length=len(r.body),
                    body_hash=hashlib.sha1(r.body[:400]).hexdigest(),
                )
                self._softs.append(sig)
                self.emit("info", f"soft-404 signature: status={sig.status} len={sig.length}")

    def _record(self, r, discovered_from: str, method="GET", is_seed=False) -> Endpoint:
        # the explicitly-targeted seed is never downgraded to not-found
        cls = _classify(r.status, [] if is_seed else self._softs, r.body)
        ep = Endpoint(
            url=r.url, method=method, status=r.status, classification=cls,
            content_type=r.header("content-type"), length=len(r.body),
            discovered_from=discovered_from, elapsed_ms=r.elapsed_ms,
            note=r.reason,
        )
        self.result.endpoints.append(ep)
        return ep

    def _fingerprint(self, r) -> None:
        if not self.result.server:
            self.result.server = r.header("server")
            if self.result.server:
                self.result.technologies.append(f"Server: {self.result.server}")
            powered = r.header("x-powered-by")
            if powered:
                self.result.technologies.append(f"X-Powered-By: {powered}")
            self.result.missing_security_headers = [
                label for key, label in SECURITY_HEADERS.items() if key not in r.headers
            ]
        low = r.text.lower()
        if ("wp-content" in low or "wp-includes" in low) and "WordPress" not in self.result.technologies:
            self.result.technologies.append("WordPress")

    def _crawl(self, base: Target) -> None:
        queue: list[tuple[Target, int]] = [(base, 0)]
        seed_url = base.url
        while queue:
            target, depth = queue.pop(0)
            if target.url in self._visited:
                continue
            self._visited.add(target.url)
            r = self.client.get(target, follow=True)
            if r.blocked:
                continue
            ep = self._record(r, discovered_from="crawl", is_seed=(target.url == seed_url))
            self.emit("endpoint", f"{ep.status} {ep.classification:<13} {ep.url}")
            if not r.ok:
                continue
            self._fingerprint(r)
            if "html" not in ep.content_type and not r.text.lstrip().startswith("<"):
                continue
            page = parse_html(r.text)
            for g in page.generators:
                if g not in self.result.technologies:
                    self.result.technologies.append(g)
            for form in page.forms:
                self._add_form(target, form)
            if depth >= self.cfg.max_depth:
                continue
            for href in page.links:
                nxt = join_in_scope(target, href)
                if nxt is None:
                    continue
                ok, _ = in_scope(nxt, self.cfg.allowed_hosts, self.cfg.allowed_ports,
                                 self.cfg.allowed_schemes)
                if ok and nxt.url not in self._visited:
                    queue.append((nxt, depth + 1))

    def _add_form(self, page: Target, form: Form) -> None:
        action_t = join_in_scope(page, form.action) if form.action else page
        action_url = action_t.url if action_t else page.url
        df = DiscoveredForm(
            page_url=page.url, action_url=action_url, method=form.method,
            enctype=form.enctype, file_fields=[f.name for f in form.file_fields],
            is_upload=form.is_upload,
        )
        self.result.forms.append(df)
        if df.is_upload:
            self.emit("form", f"upload form: {df.method.upper()} {df.action_url}")

    def _wordlist(self, base: Target) -> None:
        words = wordlist_lines(self.cfg.wordlist, FALLBACK_WORDS)
        for word in words:
            try:
                cand = normalize_url(base.origin + "/" + word.lstrip("/"))
            except ValueError:
                continue
            if cand.url in self._visited:
                continue
            self._visited.add(cand.url)
            r = self.client.get(cand, follow=False)
            if r.blocked:
                continue
            ep = self._record(r, discovered_from="wordlist")
            if ep.classification in ("normal", "auth-required", "redirect"):
                self.emit("endpoint", f"{ep.status} {ep.classification:<13} {ep.url}")
