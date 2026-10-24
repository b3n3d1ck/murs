"""Upload-security assessment with inert, uniquely-marked probe files.

Safety rules enforced here:
  * Every probe is inert. The only "code" probe is a static marker that, if a
    server ever evaluated it, would print a token and nothing else. It contains
    no command execution, no input handling, no includes — it cannot be used as
    a webshell or backdoor.
  * Execution is claimed ONLY when the fetched, stored file returns the
    *evaluated* marker (and not its raw source). A 200, a ".php" name, or a
    successful upload is never treated as proof of execution.
  * Access control is tested by fetching the stored URL and reading the status;
    nothing attempts to bypass authentication.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from .httpclient import HttpClient
from .netutil import normalize_url, Target

PNG_HEADER = bytes.fromhex("89504E470D0A1A0A")

# Explicit, mutually-exclusive outcomes of an upload probe. These separate the
# four concerns the workflow requires: acceptance, public accessibility,
# server-side interpretation, and *confirmed* code execution. Execution is only
# ever CONFIRMED when the evaluated marker was observed; everything short of
# that is reported as unconfirmed rather than inferred.
OUT_NOT_SENT = "not_sent"
OUT_REJECTED = "rejected"
OUT_ACCEPTED_LOCATION_UNKNOWN = "accepted_location_unknown"
OUT_ACCESS_CONTROLLED = "accepted_access_controlled"
OUT_PUBLIC_NOT_INTERPRETED = "accepted_public_not_interpreted"
OUT_INTERPRETED_UNCONFIRMED = "server_side_interpreted_unconfirmed"
OUT_EXECUTION_UNCONFIRMED = "execution_unconfirmed"
OUT_EXECUTION_CONFIRMED = "execution_confirmed"

OUTCOME_LABEL = {
    OUT_NOT_SENT: "not sent",
    OUT_REJECTED: "rejected by validation",
    OUT_ACCEPTED_LOCATION_UNKNOWN: "accepted; storage location undetermined",
    OUT_ACCESS_CONTROLLED: "accepted; stored file access-controlled",
    OUT_PUBLIC_NOT_INTERPRETED: "accepted; publicly served as inert content",
    OUT_INTERPRETED_UNCONFIRMED: "server-side interpretation observed; execution unconfirmed",
    OUT_EXECUTION_UNCONFIRMED: "accepted; execution could not be verified",
    OUT_EXECUTION_CONFIRMED: "code execution confirmed",
}


@dataclass
class UploadProbe:
    kind: str
    filename: str
    content: bytes
    content_type: str
    token: str
    # for the code canary: the string that only appears if the file was executed
    executed_signature: str | None = None


@dataclass
class UploadAttempt:
    probe_kind: str
    filename: str
    endpoint: str
    field_name: str
    sent: bool = False
    http_status: int = 0
    accepted: bool | None = None          # server kept the file?
    stored_location: str | None = None    # URL where the file can be fetched
    accessible: bool | None = None        # could we GET it?
    access_controlled: bool | None = None  # fetch denied (401/403)?
    interpreted: bool | None = None       # server processed it as code?
    executed: bool | None = None          # evaluated marker returned? (proof)
    outcome: str = OUT_NOT_SENT           # single, explicit ladder state
    execution_url: str | None = None      # set ONLY when execution is confirmed
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def outcome_label(self) -> str:
        return OUTCOME_LABEL.get(self.outcome, self.outcome)


def build_probes(max_bytes: int) -> list[UploadProbe]:
    """A small set of inert probes. Content is tiny and marker-tagged."""
    token = secrets.token_hex(8)
    exec_sig = f"MURSX{token}EXEC"
    # static echo: concatenation means the *source* never contains exec_sig,
    # but an interpreter that ran it would print exactly exec_sig.
    php_canary = (
        f"<?php echo 'MURSX' . '{token}' . 'EXEC'; ?>\n"
        f"inert-marker:{token}"
    ).encode()
    probes = [
        UploadProbe("image_baseline", f"murs_{token}.png",
                    PNG_HEADER + f"inert-marker:{token}".encode(), "image/png", token),
        UploadProbe("text_baseline", f"murs_{token}.txt",
                    f"inert-marker:{token}".encode(), "text/plain", token),
        UploadProbe("php_extension", f"murs_{token}.php",
                    php_canary, "application/x-php", token, exec_sig),
        UploadProbe("double_extension", f"murs_{token}.php.png",
                    php_canary, "image/png", token, exec_sig),
    ]
    return [p for p in probes if len(p.content) <= max_bytes]


def _multipart(field_name: str, probe: UploadProbe) -> tuple[bytes, str]:
    boundary = "----MURS" + secrets.token_hex(12)
    lines = [
        f"--{boundary}".encode(),
        (f'Content-Disposition: form-data; name="{field_name}"; '
         f'filename="{probe.filename}"').encode(),
        f"Content-Type: {probe.content_type}".encode(),
        b"",
        probe.content,
        f"--{boundary}--".encode(),
        b"",
    ]
    body = b"\r\n".join(lines)
    return body, f"multipart/form-data; boundary={boundary}"


_URL_RE = re.compile(r"""(?:href=|src=|["'(]|\s)(/[^\s"'<>)]+)""")


def _candidate_locations(base: Target, resp_text: str, filename: str) -> list[str]:
    cands: list[str] = []
    # 1. any path in the response that mentions the stored filename
    for m in _URL_RE.finditer(resp_text):
        path = m.group(1)
        if filename in path or "/uploads/" in path or "/upload/" in path:
            cands.append(path)
    # 2. common guesses
    for guess in (f"/uploads/{filename}", f"/upload/{filename}", f"/files/{filename}",
                  f"/media/{filename}"):
        cands.append(guess)
    # de-dup, resolve to absolute
    seen, out = set(), []
    for p in cands:
        try:
            t = normalize_url(base.origin + p if p.startswith("/") else p)
        except ValueError:
            continue
        if t.url not in seen:
            seen.add(t.url)
            out.append(t.url)
    return out


class UploadModule:
    def __init__(self, client: HttpClient, base: Target, emit=None, max_bytes: int = 65536):
        self.client = client
        self.base = base
        self.emit = emit or (lambda k, m: None)
        self.max_bytes = max_bytes

    def assess(self, action_url: str, field_name: str = "file") -> list[UploadAttempt]:
        try:
            action = normalize_url(action_url)
        except ValueError:
            return []
        results: list[UploadAttempt] = []
        for probe in build_probes(self.max_bytes):
            results.append(self._one(action, field_name, probe))
        return results

    def _one(self, action: Target, field_name: str, probe: UploadProbe) -> UploadAttempt:
        at = UploadAttempt(probe_kind=probe.kind, filename=probe.filename,
                           endpoint=action.url, field_name=field_name)
        body, ctype = _multipart(field_name, probe)
        self.emit("upload", f"probe {probe.kind}: POST {probe.filename}")
        resp = self.client.request("POST", action, headers={"Content-Type": ctype},
                                   body=body, follow=False)
        if resp.blocked:
            at.notes.append(f"blocked: {resp.reason}")
            return at
        at.sent = True
        at.http_status = resp.status
        at.evidence["upload_status"] = resp.status
        at.evidence["upload_snippet"] = resp.text[:300]
        # "accepted" is a *tentative* read of the response, never proof on its own
        at.accepted = resp.status in (200, 201, 204) and "error" not in resp.text.lower() \
            and "reject" not in resp.text.lower()

        if not at.accepted:
            at.outcome = OUT_REJECTED
            self._emit_summary(at)
            return at

        self._locate_and_classify(resp, probe, at)
        self._emit_summary(at)
        return at

    def _locate_and_classify(self, resp, probe: UploadProbe, at: UploadAttempt) -> None:
        """Fetch the stored file (same-scope) and set the explicit outcome."""
        is_code = probe.executed_signature is not None
        for url in _candidate_locations(self.base, resp.text, probe.filename):
            try:
                t = normalize_url(url)
            except ValueError:
                continue
            got = self.client.get(t, follow=False)
            if got.blocked:
                continue
            if got.status in (401, 403):
                at.stored_location = url
                at.accessible = False
                at.access_controlled = True
                at.evidence["fetch_status"] = got.status
                at.outcome = OUT_ACCESS_CONTROLLED
                return
            body = got.text
            has_raw = f"inert-marker:{probe.token}" in body
            has_exec = bool(probe.executed_signature and probe.executed_signature in body)
            if got.status == 200 and (has_raw or has_exec):
                at.stored_location = url
                at.accessible = True
                at.access_controlled = False
                at.evidence["fetch_status"] = got.status
                at.evidence["fetch_ctype"] = got.header("content-type")
                if not is_code:
                    at.outcome = OUT_PUBLIC_NOT_INTERPRETED
                    return
                has_php_source = "<?php" in body
                if has_exec and not has_php_source:
                    # deterministic proof: the evaluated marker came back, the
                    # raw source did not. This is the ONLY path to "confirmed".
                    at.executed = True
                    at.interpreted = True
                    at.execution_url = url
                    at.evidence["execution_proof"] = probe.executed_signature
                    at.outcome = OUT_EXECUTION_CONFIRMED
                elif has_php_source:
                    # stored verbatim and served as source → not interpreted
                    at.executed = False
                    at.interpreted = False
                    at.outcome = OUT_PUBLIC_NOT_INTERPRETED
                else:
                    # the script tag is gone but our marker was not emitted: the
                    # file was processed somehow, yet execution is NOT proven.
                    at.executed = None
                    at.interpreted = True
                    at.outcome = OUT_INTERPRETED_UNCONFIRMED
                    at.notes.append("server processed the file but execution was not confirmed")
                return
        # nothing retrievable
        at.accessible = None
        if is_code:
            at.outcome = OUT_EXECUTION_UNCONFIRMED
            at.notes.append("stored location not found; execution could not be verified")
        else:
            at.outcome = OUT_ACCEPTED_LOCATION_UNKNOWN
            at.notes.append("stored location not found from the response")

    def _emit_summary(self, at: UploadAttempt) -> None:
        self.emit("upload", f"  {at.probe_kind}: {at.outcome_label} "
                            f"(status={at.http_status})")
