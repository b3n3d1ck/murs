"""Login-page discovery.

Classifies likely login pages from the crawl (forms + endpoints) and, within
the configured scope and request budget, probes a small, configurable login
wordlist. Classification is evidence-based and scored; it never claims that
every login page has been found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from .config import wordlist_lines
from .forms import parse_html
from .httpclient import HttpClient, RequestBudgetExceeded
from .netutil import normalize_url, in_scope

Emit = Callable[[str, str], None]

# common authentication path fragments (no robots.txt dependency).
LOGIN_PATHS = [
    "login", "signin", "sign-in", "log-in", "auth", "authenticate",
    "account/login", "accounts/login", "user/login", "users/login",
    "admin", "admin/login", "administrator", "wp-login.php", "wp-admin",
    "session/new", "sessions/new", "cpanel", "portal", "signin.php",
    "login.php", "login.html", "auth/login",
]
_PATH_RE = re.compile(r"(?i)(login|signin|sign-?in|log-?in|/auth|authenticate|"
                      r"wp-login|wp-admin|session|/admin\b)")
_KEYWORDS = ("password", "sign in", "log in", "login", "username", "user name",
             "email address")

# score weights
W_PASSWORD_FORM = 5
W_PATH = 2
W_KEYWORDS = 1
CLASSIFY_THRESHOLD = 3


@dataclass
class LoginCandidate:
    url: str
    score: int
    evidence: list[str] = field(default_factory=list)
    method: str = "get"
    action_url: str = ""
    param_names: list[str] = field(default_factory=list)
    password_field: str | None = None

    @property
    def is_login(self) -> bool:
        return self.score >= CLASSIFY_THRESHOLD


class LoginDiscovery:
    def __init__(self, config, client: HttpClient, emit: Emit | None = None):
        self.cfg = config
        self.client = client
        self.emit = emit or (lambda k, m: None)

    def find(self, discovery) -> list[LoginCandidate]:
        cands: dict[str, LoginCandidate] = {}

        def bump(url: str, weight: int, note: str, **kw):
            c = cands.get(url)
            if c is None:
                c = LoginCandidate(url=url, score=0)
                cands[url] = c
            c.score += weight
            if note not in c.evidence:
                c.evidence.append(note)
            for k, v in kw.items():
                if v:
                    setattr(c, k, v)
            return c

        # 1. forms with a password field are the strongest signal
        for form in discovery.forms:
            pw = form.password_field
            if pw:
                bump(form.page_url, W_PASSWORD_FORM, "form has a password field",
                     method=form.method, action_url=form.action_url,
                     param_names=form.field_names, password_field=pw)

        # 2. endpoints whose path looks like an auth path
        for ep in discovery.endpoints:
            if ep.classification in ("normal", "auth-required", "redirect") and _PATH_RE.search(ep.url):
                bump(ep.url, W_PATH, "URL path matches a login pattern")

        # 3. probe a small login wordlist for paths not already seen
        self._probe_wordlist(discovery, cands, bump)

        out = [c for c in cands.values() if c.is_login]
        out.sort(key=lambda c: c.score, reverse=True)
        for c in out:
            self.emit("login", f"login page (score {c.score}): {c.url}")
        return out

    def _probe_wordlist(self, discovery, cands, bump):
        import hashlib
        try:
            base = normalize_url(self.cfg.base_url)
        except ValueError:
            return
        # fingerprint the base page: servers that route every unknown path to a
        # catch-all/index (e.g. php -S) would otherwise make every probed path
        # look like a login page. We skip probes whose body matches the base.
        base_hash = None
        try:
            br = self.client.get(base, follow=False)
            if br.ok:
                base_hash = hashlib.sha1(br.body).hexdigest()
        except RequestBudgetExceeded:
            return
        words = wordlist_lines(getattr(self.cfg, "login_wordlist", None), LOGIN_PATHS)
        seen = {c for c in cands}
        for word in words:
            try:
                cand = normalize_url(base.origin + "/" + word.lstrip("/"))
            except ValueError:
                continue
            ok, _ = in_scope(cand, self.cfg.allowed_hosts, self.cfg.allowed_ports,
                             self.cfg.allowed_schemes)
            if not ok or cand.url in seen:
                continue
            seen.add(cand.url)
            try:
                r = self.client.get(cand, follow=False)
            except RequestBudgetExceeded:
                self.emit("warn", "request budget reached; stopping login probe")
                return
            if r.blocked or not r.ok or r.status != 200:
                continue
            if base_hash is not None and hashlib.sha1(r.body).hexdigest() == base_hash:
                continue  # identical to the base page -> not a distinct login path
            page = parse_html(r.text)
            has_pw = any(f.type == "password" for form in page.forms for f in form.fields)
            low = r.text.lower()
            kw_hits = sum(1 for k in _KEYWORDS if k in low)
            if has_pw:
                form = next(f for f in page.forms if any(x.type == "password" for x in f.fields))
                bump(cand.url, W_PASSWORD_FORM, "form has a password field (wordlist)",
                     method=form.method,
                     action_url=normalize_url(base.origin + "/" + word.lstrip("/")).url,
                     param_names=[x.name for x in form.fields if x.name],
                     password_field=next(x.name for x in form.fields if x.type == "password"))
            if _PATH_RE.search(cand.url):
                bump(cand.url, W_PATH, "URL path matches a login pattern")
            if kw_hits >= 2:
                bump(cand.url, W_KEYWORDS, "page text contains login keywords")
