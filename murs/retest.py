"""Before/after retest comparison."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding, V_FIXED, V_STILL_PRESENT

NEW = "New"


@dataclass
class RetestEntry:
    id: str
    title: str
    severity: str
    result: str  # "Fixed" | "Still Present" | "New"


def compare(before: list[Finding], after: list[Finding]) -> list[RetestEntry]:
    bmap = {f.id: f for f in before}
    amap = {f.id: f for f in after}
    entries: list[RetestEntry] = []
    for fid, bf in bmap.items():
        result = V_STILL_PRESENT if fid in amap else V_FIXED
        entries.append(RetestEntry(fid, bf.title, bf.severity, result))
    for fid, af in amap.items():
        if fid not in bmap:
            entries.append(RetestEntry(fid, af.title, af.severity, NEW))
    return entries


def apply_retest(after: list[Finding], entries: list[RetestEntry]) -> None:
    """Stamp the retest result onto the current findings."""
    by_id = {e.id: e for e in entries}
    for f in after:
        e = by_id.get(f.id)
        if e:
            f.retest_status = e.result
            if e.result == V_STILL_PRESENT:
                f.verification_status = V_STILL_PRESENT


def save_findings(findings: list[Finding], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8"
    )


def load_findings(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    allowed = set(Finding.__dataclass_fields__)
    for d in data:
        out.append(Finding(**{k: v for k, v in d.items() if k in allowed}))
    return out
