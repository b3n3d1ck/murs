"""SQL-injection assessment (non-destructive, evidence-based).

What it does:
  * Establishes a baseline response for a parameter, then sends a small set of
    structured, non-destructive diagnostic payloads.
  * Error-based indication: a DB-specific error signature appears that was NOT
    in the baseline (a generic 500 or generic "error" text is never enough).
  * Boolean-based indication: a logically-true vs logically-false condition
    produce a consistent, significant response differential.

What it does NOT do: it never extracts or modifies data, never uses stacked
queries or comment-based auth-bypass payloads, and never concludes injection
from an HTTP status code or a generic error alone. Confirmation of exploitable
injection is reserved for the bundled local SQLi lab (`lab_confirm=True`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlencode

from .httpclient import HttpClient
from .netutil import normalize_url, redact_secrets

Emit = Callable[[str, str], None]

# outcomes (explicit, mutually exclusive)
NOT_TESTABLE = "not_testable"
NOT_INJECTABLE = "not_injectable"
ERROR_INDICATION = "error_based_indication"
BOOLEAN_INDICATION = "boolean_based_indication"
INCONCLUSIVE = "inconclusive"
CONFIRMED = "confirmed_in_lab"

OUTCOME_LABEL = {
    NOT_TESTABLE: "not testable",
    NOT_INJECTABLE: "no injection indicated",
    ERROR_INDICATION: "error-based indication",
    BOOLEAN_INDICATION: "boolean-based indication",
    INCONCLUSIVE: "inconclusive",
    CONFIRMED: "confirmed (local lab)",
}

# non-destructive diagnostics only: quote/paren breakers + AND-differential.
# No OR-bypass, no comment (--/#), no stacked (;), no UNION data extraction.
ERROR_PROBES = ["'", "\"", "')", "\\"]
BOOL_TRUE = "' AND '1'='1"
BOOL_FALSE = "' AND '1'='2"

# DB-specific error signatures (NOT generic 500s / generic "error").
_DB_ERROR_RE = re.compile(
    r"(?i)("
    r"you have an error in your sql syntax|warning:\s*mysqli|warning:\s*mysql_|"
    r"unclosed quotation mark|mssql_query|odbc sql|"
    r"pg_query|postgresql.*error|psqlexception|"
    r"sqlite3?::|sqlite_error|unrecognized token|sql logic error|"
    r"near \".*\": syntax error|"
    r"ora-\d{5}|quoted string not properly terminated|"
    r"sqlstate\["
    r")"
)

# input types worth testing (skip submit/button/file/hidden csrf-ish).
_TESTABLE_TYPES = {"text", "search", "email", "url", "tel", "password", "", "number"}


@dataclass
class ParamResult:
    param: str
    outcome: str
    confidence: str
    baseline_status: int = 0
    evidence: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    @property
    def outcome_label(self) -> str:
        return OUTCOME_LABEL.get(self.outcome, self.outcome)

    @property
    def indicated(self) -> bool:
        return self.outcome in (ERROR_INDICATION, BOOLEAN_INDICATION, CONFIRMED)


@dataclass
class SqliTarget:
    url: str
    method: str
    params: list
    results: list = field(default_factory=list)


def _signatures(text: str) -> set[str]:
    return {m.group(0).lower() for m in _DB_ERROR_RE.finditer(text)}


class SqliModule:
    def __init__(self, client: HttpClient, emit: Emit | None = None,
                 lab_confirm: bool = False):
        self.client = client
        self.emit = emit or (lambda k, m: None)
        self.lab_confirm = lab_confirm

    # ------------------------------------------------------------ form target
    def assess_form(self, action_url: str, method: str, field_names: list,
                    testable: list | None = None) -> SqliTarget:
        params = testable if testable is not None else list(field_names)
        tgt = SqliTarget(url=action_url, method=(method or "get").lower(), params=params)
        base_values = {n: "murs_test" for n in field_names}
        for p in params:
            tgt.results.append(self._test_param(action_url, tgt.method, base_values, p))
        return tgt

    def _send(self, action_url: str, method: str, values: dict):
        try:
            t = normalize_url(action_url)
        except ValueError:
            return None
        if method == "post":
            body = urlencode(values).encode()
            return self.client.request("POST", t, body=body, follow=False,
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        # GET: append params to the query
        base = t.url.split("?", 1)[0]
        try:
            gt = normalize_url(base + "?" + urlencode(values))
        except ValueError:
            return None
        return self.client.get(gt, follow=False)

    def _test_param(self, action_url, method, base_values, param) -> ParamResult:
        r = ParamResult(param=param, outcome=NOT_INJECTABLE, confidence="informational")
        base = self._send(action_url, method, base_values)
        if base is None or base.blocked or not base.ok:
            r.outcome, r.notes = NOT_TESTABLE, ["baseline request failed/blocked"]
            return r
        r.baseline_status = base.status
        base_sig = _signatures(base.text)
        base_len = len(base.body)

        # --- error-based: a DB signature that was NOT in the baseline
        new_sig = set()
        for probe in ERROR_PROBES:
            vals = dict(base_values)
            vals[param] = base_values.get(param, "x") + probe
            resp = self._send(action_url, method, vals)
            if resp is None or resp.blocked or resp.error:
                continue
            sigs = _signatures(resp.text) - base_sig
            if sigs:
                new_sig |= sigs
                r.evidence["error_signature"] = redact_secrets(" | ".join(sorted(new_sig)), 200)
                r.evidence["probe"] = probe
                break

        # --- boolean-based differential (AND true vs AND false)
        t_vals = dict(base_values); t_vals[param] = base_values.get(param, "x") + BOOL_TRUE
        f_vals = dict(base_values); f_vals[param] = base_values.get(param, "x") + BOOL_FALSE
        rt = self._send(action_url, method, t_vals)
        rf = self._send(action_url, method, f_vals)
        boolean_hit = False
        if rt and rf and rt.ok and rf.ok and not rt.blocked and not rf.blocked:
            lt, lf = len(rt.body), len(rf.body)
            diff = abs(lt - lf)
            # true should resemble baseline; false should diverge notably
            near_base = abs(lt - base_len) <= max(16, int(base_len * 0.02))
            diverges = diff > max(40, int(base_len * 0.05)) and rt.text != rf.text
            if near_base and diverges:
                boolean_hit = True
                r.evidence["boolean_true_len"] = lt
                r.evidence["boolean_false_len"] = lf

        # --- classify from evidence (never from status alone)
        if new_sig and boolean_hit:
            r.outcome = CONFIRMED if self.lab_confirm else ERROR_INDICATION
            r.confidence = "confirmed" if self.lab_confirm else "potential"
        elif new_sig:
            r.outcome = CONFIRMED if self.lab_confirm else ERROR_INDICATION
            r.confidence = "confirmed" if self.lab_confirm else "potential"
        elif boolean_hit:
            r.outcome = BOOLEAN_INDICATION
            r.confidence = "potential"
        else:
            r.outcome = NOT_INJECTABLE
            r.confidence = "informational"

        self.emit("sqli", f"  param '{param}': {r.outcome_label}")
        return r
