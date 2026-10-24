"""Assessment orchestration: discovery → upload assessment → findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import ScanConfig
from .discovery import DiscoveryEngine, DiscoveryResult
from .findings import Finding, FindingEngine
from .httpclient import HttpClient, RequestBudgetExceeded
from .netutil import normalize_url, Target
from .upload import UploadModule, UploadAttempt

Emit = None  # typing hint only


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class RunResult:
    config: ScanConfig
    base: Target
    discovery: DiscoveryResult
    upload_attempts: list[UploadAttempt]
    findings: list[Finding]
    started_at: str
    finished_at: str
    requests_made: int
    notes: list[str] = field(default_factory=list)


def prepare(cfg: ScanConfig) -> Target:
    """Normalize the target and fill derived scope defaults in place."""
    t = normalize_url(cfg.target)
    cfg.base_scheme, cfg.base_host, cfg.base_port = t.scheme, t.host, t.port
    cfg.base_url = t.url
    if not cfg.allowed_hosts:
        cfg.add_allowed_host(t.host)
    else:
        cfg.add_allowed_host(t.host)
    cfg.allowed_ports.add(t.port)
    cfg.allowed_schemes.add(t.scheme)
    return t


def run_assessment(cfg: ScanConfig, emit=None, allow_private: bool = False) -> RunResult:
    emit = emit or (lambda k, m: None)
    base = prepare(cfg)
    started = _now()
    client = HttpClient(
        allowed_hosts=cfg.allowed_hosts,
        allowed_ports=cfg.allowed_ports,
        allowed_schemes=cfg.allowed_schemes,
        timeout=cfg.timeout,
        retries=cfg.retries,
        max_response_bytes=cfg.max_response_bytes,
        rate_limit_per_sec=cfg.rate_limit_per_sec,
        max_requests=cfg.max_requests,
        allow_private=allow_private,
    )
    notes: list[str] = []

    emit("info", f"discovery starting on {base.url}")
    discovery = DiscoveryEngine(cfg, client, emit).run()
    emit("ok", f"discovery: {len(discovery.endpoints)} endpoint(s), "
               f"{len(discovery.upload_forms)} upload form(s)")

    upload_attempts: list[UploadAttempt] = []
    if cfg.mode == "assessment":
        seen: set[str] = set()
        mod = UploadModule(client, base, emit, cfg.max_test_file_bytes)
        for form in discovery.upload_forms:
            if form.action_url in seen:
                continue
            seen.add(form.action_url)
            field_name = form.file_fields[0] if form.file_fields else "file"
            emit("upload", f"assessing upload endpoint {form.action_url}")
            try:
                upload_attempts += mod.assess(form.action_url, field_name)
            except RequestBudgetExceeded:
                notes.append("request budget reached during upload assessment")
                emit("warn", "request budget reached; stopping upload assessment")
                break
        if not discovery.upload_forms:
            emit("info", "no upload forms discovered; skipping upload assessment")

    findings = FindingEngine(tested_at=_now()).build(discovery, upload_attempts)
    emit("ok", f"{len(findings)} finding(s) classified")

    notes.extend(discovery.notes)
    return RunResult(
        config=cfg, base=base, discovery=discovery, upload_attempts=upload_attempts,
        findings=findings, started_at=started, finished_at=_now(),
        requests_made=client.count, notes=notes,
    )
