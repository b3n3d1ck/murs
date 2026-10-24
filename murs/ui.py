"""Matrix-styled terminal output. Every line reflects real engine activity."""

from __future__ import annotations

import os
import sys
import time

_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

G = "\033[32m" if _ENABLED else ""
GB = "\033[92m" if _ENABLED else ""
DIM = "\033[2;32m" if _ENABLED else ""
RED = "\033[91m" if _ENABLED else ""
YEL = "\033[93m" if _ENABLED else ""
CY = "\033[96m" if _ENABLED else ""
R = "\033[0m" if _ENABLED else ""

BANNER = r"""
 __  __ _   _ ____  ____
|  \/  | | | |  _ \/ ___|    MATRIX UPLOAD RESEARCH SUITE
| |\/| | | | | |_) \___ \    authorized web upload security research
| |  | | |_| |  _ < ___) |   passive-by-default · inert probes · scope-bound
|_|  |_|\___/|_| \_\____/
"""

_KIND_COLOR = {
    "info": G, "ok": GB, "warn": YEL, "error": RED, "endpoint": CY,
    "form": GB, "upload": G, "finding": GB, "sys": DIM,
}


class MatrixUI:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def banner(self) -> None:
        if self.enabled:
            print(f"{GB}{BANNER}{R}")

    def line(self, kind: str, msg: str) -> None:
        if not self.enabled:
            return
        color = _KIND_COLOR.get(kind, G)
        ts = time.strftime("%H:%M:%S")
        print(f"{DIM}[{ts}]{R} {color}{kind:<8}{R} {msg}")

    def head(self, text: str) -> None:
        if self.enabled:
            print(f"\n{GB}== {text} =={R}")

    def kv(self, key: str, value: str) -> None:
        if self.enabled:
            print(f"  {DIM}{key:<16}{R}{G}{value}{R}")

    def emit(self, kind: str, msg: str) -> None:
        self.line(kind, msg)
