"""Finding model and evidence-bound classification.

Severity and confidence follow the evidence only. In particular, server-side
code execution is asserted (Critical / Confirmed) solely when the upload module
observed the *evaluated* canary marker returned from the stored file. A
successful upload, a 200 response, or a ".php" filename never raise severity on
their own.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

# severity
CRITICAL, HIGH, MEDIUM, LOW, INFO = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

# confidence
CONFIRMED, POTENTIAL, INFORMATIONAL = ("confirmed", "potential", "informational")

# verification status
V_CONFIRMED = "Confirmed"
V_POTENTIAL = "Potential"
V_INCONCLUSIVE = "Inconclusive"
V_NOT_REPRO = "Not Reproducible"
V_FIXED = "Fixed"
V_STILL_PRESENT = "Still Present"

# retest status
R_NOT_RETESTED = "not-retested"


SENSITIVE_PATHS = (".env", ".git/config", ".git", "wp-config.php", "config.php",
                   "backup", ".htpasswd", "id_rsa")


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    confidence: str
    endpoint: str
    detection_method: str
    observed_condition: str
    impact: str
    prerequisites: str
    reproduction: str
    recommendation: str
    tested_at: str
    verification_status: str = V_POTENTIAL
    retest_status: str = R_NOT_RETESTED
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _id_endpoint(endpoint: str) -> str:
    """Normalize an endpoint for stable IDs: host + path, without scheme or port.

    This keeps a finding's ID stable across retests of the same deployment even
    when the port changes (e.g. the ephemeral local lab), so before/after
    comparison matches the same endpoint rather than treating it as new.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(endpoint if "://" in endpoint else "http://" + endpoint)
        host = (parts.hostname or "").lower()
        return f"{host}{parts.path or '/'}"
    except ValueError:
        return endpoint


def _fid(category: str, endpoint: str, key: str = "") -> str:
    norm = _id_endpoint(endpoint)
    h = hashlib.sha1(f"{category}|{norm}|{key}".encode()).hexdigest()[:8]
    return f"MURS-{h.upper()}"


def _severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


class FindingEngine:
    def __init__(self, tested_at: str):
        self.tested_at = tested_at

    def build(self, discovery, upload_attempts: list,
              login_candidates: list | None = None,
              sqli_targets: list | None = None) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._from_discovery(discovery))
        out.extend(self._from_uploads(upload_attempts))
        out.extend(self._from_login(login_candidates or []))
        out.extend(self._from_sqli(sqli_targets or []))
        out.sort(key=lambda f: (_severity_rank(f.severity), f.title))
        return out

    # --------------------------------------------------------------- login
    def _from_login(self, candidates: list) -> list[Finding]:
        if not candidates:
            return []
        urls = ", ".join(c.url for c in candidates[:8])
        return [Finding(
            id=_fid("login", candidates[0].url, "set"),
            title="Login page(s) discovered",
            category="Authentication surface",
            severity=INFO, confidence=INFORMATIONAL, endpoint=candidates[0].url,
            detection_method="Form/password-field + URL-pattern + wordlist probing",
            observed_condition=f"{len(candidates)} login candidate(s): {urls}",
            impact="Authentication surface for review; not a vulnerability by itself.",
            prerequisites="None.",
            reproduction="Open each candidate URL and confirm the login form.",
            recommendation="Ensure login is rate-limited, over HTTPS, and protected "
                           "against credential stuffing and injection.",
            tested_at=self.tested_at, verification_status=V_CONFIRMED,
            evidence={"candidates": [{"url": c.url, "score": c.score,
                                      "evidence": c.evidence} for c in candidates[:8]]},
        )]

    # ---------------------------------------------------------------- sqli
    def _from_sqli(self, targets: list) -> list[Finding]:
        from .sqli import (ERROR_INDICATION, BOOLEAN_INDICATION,
                           CONFIRMED as SQLI_CONFIRMED)
        findings: list[Finding] = []
        for tgt in targets:
            for r in tgt.results:
                if r.outcome == SQLI_CONFIRMED:
                    sev, conf, status, title = (
                        CRITICAL, CONFIRMED, V_CONFIRMED,
                        "SQL injection confirmed (local lab)")
                elif r.outcome == ERROR_INDICATION:
                    sev, conf, status, title = (
                        HIGH, POTENTIAL, V_POTENTIAL,
                        "Possible SQL injection — error-based indication")
                elif r.outcome == BOOLEAN_INDICATION:
                    sev, conf, status, title = (
                        HIGH, POTENTIAL, V_POTENTIAL,
                        "Possible SQL injection — boolean-based indication")
                else:
                    continue
                findings.append(Finding(
                    id=_fid("sqli", tgt.url, r.param),
                    title=title, category="SQL injection",
                    severity=sev, confidence=conf, endpoint=tgt.url,
                    detection_method=("DB error signature appeared after a quote probe "
                                      "(absent in baseline)" if r.outcome == ERROR_INDICATION
                                      else "Boolean true/false differential vs baseline"
                                      if r.outcome == BOOLEAN_INDICATION
                                      else "Local-lab confirmation"),
                    observed_condition=f"Parameter '{r.param}': {r.outcome_label} "
                                       f"(baseline HTTP {r.baseline_status}).",
                    impact="If exploitable, an attacker could read or alter database "
                           "content. Not confirmed on this target unless stated.",
                    prerequisites="Reachable parameter in scope.",
                    reproduction=f"Submit the '{r.param}' parameter with a single quote "
                                 "and a true/false AND condition; compare to baseline. "
                                 "Confirm safely in the local SQLi lab.",
                    recommendation="Use parameterised queries / prepared statements, "
                                   "validate input, and avoid surfacing DB errors.",
                    tested_at=self.tested_at, verification_status=status,
                    evidence=dict(r.evidence, param=r.param, outcome=r.outcome),
                ))
        return findings

    # ------------------------------------------------------------- discovery
    def _from_discovery(self, d) -> list[Finding]:
        findings: list[Finding] = []
        if d is None:
            return findings

        if d.missing_security_headers:
            findings.append(Finding(
                id=_fid("headers", d.base_url),
                title="Missing HTTP security headers",
                category="Security headers",
                severity=LOW, confidence=CONFIRMED, endpoint=d.base_url,
                detection_method="Header inspection of the base response",
                observed_condition=f"Absent: {', '.join(d.missing_security_headers)}",
                impact="Weaker defence-in-depth (clickjacking, MIME sniffing, "
                       "transport downgrade, injection impact).",
                prerequisites="None.",
                reproduction="Send a GET to the base URL and inspect response headers.",
                recommendation="Add CSP, HSTS, X-Content-Type-Options, X-Frame-Options "
                               "and Referrer-Policy at the server or framework layer.",
                tested_at=self.tested_at, verification_status=V_CONFIRMED,
                evidence={"missing": d.missing_security_headers, "server": d.server},
            ))

        for ep in d.endpoints:
            low = ep.url.lower()
            if ep.classification == "normal" and any(s in low for s in SENSITIVE_PATHS):
                findings.append(Finding(
                    id=_fid("exposure", ep.url),
                    title="Sensitive file or path is publicly reachable",
                    category="Information exposure",
                    severity=HIGH, confidence=CONFIRMED, endpoint=ep.url,
                    detection_method=f"Discovery ({ep.discovered_from}) returned HTTP {ep.status}",
                    observed_condition=f"{ep.url} returned {ep.status} "
                                       f"({ep.length} bytes, {ep.content_type}).",
                    impact="May disclose credentials, source, or configuration.",
                    prerequisites="None — reachable without authentication.",
                    reproduction=f"GET {ep.url} and review the body.",
                    recommendation="Remove the file from the web root or block access; "
                                   "rotate any secrets that were exposed.",
                    tested_at=self.tested_at, verification_status=V_CONFIRMED,
                    evidence={"status": ep.status, "content_type": ep.content_type,
                              "length": ep.length},
                ))

        if d.server and any(ch.isdigit() for ch in d.server):
            findings.append(Finding(
                id=_fid("disclosure", d.base_url, "server"),
                title="Server version disclosed in banner",
                category="Information exposure",
                severity=INFO, confidence=CONFIRMED, endpoint=d.base_url,
                detection_method="Server response header",
                observed_condition=f"Server: {d.server}",
                impact="Aids an attacker in matching known CVEs to the stack.",
                prerequisites="None.",
                reproduction="GET the base URL; read the Server header.",
                recommendation="Suppress or genericise the Server banner.",
                tested_at=self.tested_at, verification_status=V_CONFIRMED,
                evidence={"server": d.server},
            ))
        return findings

    # --------------------------------------------------------------- uploads
    def _from_uploads(self, attempts: list) -> list[Finding]:
        from .upload import (
            OUT_EXECUTION_CONFIRMED, OUT_INTERPRETED_UNCONFIRMED,
            OUT_EXECUTION_UNCONFIRMED, OUT_PUBLIC_NOT_INTERPRETED,
            OUT_ACCESS_CONTROLLED, OUT_ACCEPTED_LOCATION_UNKNOWN,
        )
        hardening = ("Validate uploads by content (allowlist), store them outside the "
                     "web root, serve with a fixed non-executable Content-Type, and "
                     "disable script execution in the upload directory.")
        findings: list[Finding] = []
        for at in attempts or []:
            if not at.sent:
                continue
            is_code = at.probe_kind in ("php_extension", "double_extension")
            base_repro = (
                f"Upload the inert probe '{at.filename}' to {at.endpoint} via the "
                f"'{at.field_name}' field, then GET the stored URL "
                f"({at.stored_location or 'location not determined'})."
            )

            if at.outcome == OUT_EXECUTION_CONFIRMED:
                # requirement 9: the execution URL is reported only because it was
                # actually observed returning the evaluated marker.
                findings.append(Finding(
                    id=_fid("upload-rce", at.endpoint, at.probe_kind),
                    title="Unrestricted file upload leads to server-side code execution",
                    category="File upload",
                    severity=CRITICAL, confidence=CONFIRMED, endpoint=at.endpoint,
                    detection_method="Inert echo-canary: the evaluated marker was "
                                     "returned from the stored file (raw source absent)",
                    observed_condition=f"Probe '{at.probe_kind}' stored at "
                                       f"{at.execution_url} executed on retrieval.",
                    impact="An attacker who can upload a script may run code on the "
                           "server. Demonstrated here only with an inert marker.",
                    prerequisites="Ability to reach the upload endpoint.",
                    reproduction=base_repro + " The response contains the evaluated "
                                 "marker, proving interpreter execution.",
                    recommendation=hardening,
                    tested_at=self.tested_at, verification_status=V_CONFIRMED,
                    evidence=dict(at.evidence, probe=at.probe_kind,
                                  execution_url=at.execution_url),
                ))
            elif at.outcome == OUT_INTERPRETED_UNCONFIRMED:
                findings.append(Finding(
                    id=_fid("upload-interp", at.endpoint, at.probe_kind),
                    title="Uploaded script appears to be processed server-side "
                          "(execution unconfirmed)",
                    category="File upload",
                    severity=HIGH, confidence=POTENTIAL, endpoint=at.endpoint,
                    detection_method="The stored file no longer returns its raw source, "
                                     "but the evaluated marker was not observed",
                    observed_condition=f"Probe '{at.probe_kind}' at {at.stored_location} "
                                       "was altered on retrieval (source tags absent), "
                                       "yet execution could not be confirmed.",
                    impact="The server may interpret uploaded files. Code execution is "
                           "plausible but was NOT verified on this target.",
                    prerequisites="Ability to reach the upload endpoint.",
                    reproduction=base_repro + " Compare the retrieved body with the "
                                 "uploaded source; confirm safely in the local lab.",
                    recommendation=hardening,
                    tested_at=self.tested_at, verification_status=V_INCONCLUSIVE,
                    evidence=dict(at.evidence, probe=at.probe_kind,
                                  note="execution not confirmed; no execution URL reported"),
                ))
            elif at.outcome == OUT_EXECUTION_UNCONFIRMED and is_code:
                findings.append(Finding(
                    id=_fid("upload-unverified", at.endpoint, at.probe_kind),
                    title="Script-typed upload accepted; execution could not be verified",
                    category="File upload",
                    severity=LOW, confidence=POTENTIAL, endpoint=at.endpoint,
                    detection_method="Upload accepted, but the stored file could not be "
                                     "located/retrieved to test execution",
                    observed_condition=f"Probe '{at.probe_kind}' accepted "
                                       f"(HTTP {at.http_status}); storage location not found.",
                    impact="Risk is undetermined. Execution was not inferred from the "
                           "status code or extension.",
                    prerequisites="Ability to reach the upload endpoint.",
                    reproduction=base_repro,
                    recommendation=hardening,
                    tested_at=self.tested_at, verification_status=V_INCONCLUSIVE,
                    evidence=dict(at.evidence, probe=at.probe_kind),
                ))
            elif is_code and at.outcome == OUT_PUBLIC_NOT_INTERPRETED:
                findings.append(Finding(
                    id=_fid("upload-type", at.endpoint, at.probe_kind),
                    title="Server-side script type accepted and stored (no execution)",
                    category="File upload",
                    severity=MEDIUM, confidence=CONFIRMED, endpoint=at.endpoint,
                    detection_method="Policy probe with an inert script-typed file",
                    observed_condition=f"Probe '{at.probe_kind}' accepted and retrievable "
                                       f"at {at.stored_location}, served as inert source "
                                       "(no execution observed).",
                    impact="A permissive upload policy raises execution risk if the "
                           "storage directory ever allows it. No execution here.",
                    prerequisites="Ability to reach the upload endpoint.",
                    reproduction=base_repro,
                    recommendation=hardening,
                    tested_at=self.tested_at, verification_status=V_CONFIRMED,
                    evidence=dict(at.evidence, probe=at.probe_kind),
                ))
            elif is_code and at.outcome in (OUT_ACCESS_CONTROLLED,
                                            OUT_ACCEPTED_LOCATION_UNKNOWN):
                findings.append(Finding(
                    id=_fid("upload-type", at.endpoint, at.probe_kind),
                    title="Server-side script type accepted by the upload endpoint",
                    category="File upload",
                    severity=LOW, confidence=POTENTIAL, endpoint=at.endpoint,
                    detection_method="Policy probe with an inert script-typed file",
                    observed_condition=f"Probe '{at.probe_kind}' accepted "
                                       f"(HTTP {at.http_status}); "
                                       f"{at.outcome.replace('_', ' ')}.",
                    impact="A permissive upload policy raises execution risk. Storage "
                           "or execution was not confirmed on this target.",
                    prerequisites="Ability to reach the upload endpoint.",
                    reproduction=base_repro,
                    recommendation=hardening,
                    tested_at=self.tested_at, verification_status=V_INCONCLUSIVE,
                    evidence=dict(at.evidence, probe=at.probe_kind),
                ))
            elif (not is_code) and at.outcome == OUT_PUBLIC_NOT_INTERPRETED:
                findings.append(Finding(
                    id=_fid("upload-access", at.endpoint, at.probe_kind),
                    title="Uploaded files are publicly accessible without access control",
                    category="File upload",
                    severity=LOW, confidence=CONFIRMED, endpoint=at.endpoint,
                    detection_method="Fetched the stored probe without authentication",
                    observed_condition=f"'{at.filename}' retrievable at {at.stored_location}.",
                    impact="Uploaded content is exposed to anyone with the URL.",
                    prerequisites="Knowledge of the stored URL (often predictable).",
                    reproduction=base_repro,
                    recommendation="Require authorization to read uploads or randomise "
                                   "and expire storage URLs.",
                    tested_at=self.tested_at, verification_status=V_CONFIRMED,
                    evidence=dict(at.evidence, probe=at.probe_kind),
                ))
        # positive signal: nothing dangerous accepted
        if attempts and not findings and any(a.sent for a in attempts):
            at = next(a for a in attempts if a.sent)
            findings.append(Finding(
                id=_fid("upload-ok", at.endpoint),
                title="Upload endpoint rejected the script-typed probes",
                category="File upload",
                severity=INFO, confidence=INFORMATIONAL, endpoint=at.endpoint,
                detection_method="Inert policy probes",
                observed_condition="Script-typed inert probes were not stored/retrievable.",
                impact="No upload weakness demonstrated by these probes.",
                prerequisites="None.",
                reproduction="Re-run the upload module against the endpoint.",
                recommendation="Keep validating by content and storing uploads safely.",
                tested_at=self.tested_at, verification_status=V_NOT_REPRO,
                evidence={},
            ))
        return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
