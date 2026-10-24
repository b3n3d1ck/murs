"""Scan configuration and scope model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable


# Test modes decide how aggressive discovery/upload assessment is allowed to be.
MODES = ("passive", "discovery", "assessment")


@dataclass
class ScanConfig:
    """Everything an assessment run needs. Values are validated in __post_init__."""

    target: str
    project: str = "MURS research assessment"
    researcher: str = "unspecified"

    # scope
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=lambda: {80, 443})
    allowed_schemes: set[str] = field(default_factory=lambda: {"http", "https"})

    # crawling / discovery
    max_depth: int = 2
    max_requests: int = 300
    concurrency: int = 6
    rate_limit_per_sec: float = 8.0
    wordlist: str | None = None

    # transport
    timeout: float = 10.0
    retries: int = 2
    max_response_bytes: int = 512 * 1024

    # upload
    max_test_file_bytes: int = 64 * 1024

    # output
    report_dir: str = "reports"
    mode: str = "assessment"

    # set by normalize(), not by the caller
    base_scheme: str = ""
    base_host: str = ""
    base_port: int = 0
    base_url: str = ""

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {self.mode!r}")
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        if self.max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.rate_limit_per_sec <= 0:
            raise ValueError("rate_limit_per_sec must be > 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.max_response_bytes < 1024:
            raise ValueError("max_response_bytes must be >= 1024")
        self.allowed_hosts = {h.strip().lower() for h in self.allowed_hosts if h.strip()}

    def add_allowed_host(self, host: str) -> None:
        if host:
            self.allowed_hosts.add(host.strip().lower())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["allowed_hosts"] = sorted(self.allowed_hosts)
        d["allowed_ports"] = sorted(self.allowed_ports)
        d["allowed_schemes"] = sorted(self.allowed_schemes)
        return d

    @classmethod
    def from_file(cls, path: str | Path) -> "ScanConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        data = dict(data)
        for key in ("allowed_hosts", "allowed_schemes"):
            if key in data and data[key] is not None:
                data[key] = set(data[key])
        if "allowed_ports" in data and data["allowed_ports"] is not None:
            data["allowed_ports"] = {int(p) for p in data["allowed_ports"]}
        # drop derived fields if present in a saved file
        for derived in ("base_scheme", "base_host", "base_port", "base_url"):
            data.pop(derived, None)
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


def wordlist_lines(path: str | None, fallback: Iterable[str]) -> list[str]:
    """Load a discovery wordlist, falling back to a built-in list."""
    if path:
        p = Path(path)
        if p.exists():
            return [
                ln.strip()
                for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
    return list(fallback)
