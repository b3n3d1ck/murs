"""Run the MURS lab apps with PHP's built-in server, bound to 127.0.0.1 only.

The lab is deliberately isolated: it never binds to a public interface, and the
'vulnerable' variant is clearly marked and intended only for local research.
Requires the `php` CLI; if it is absent, LabUnavailable is raised so callers can
report the exact blocker instead of faking a result.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
VARIANTS = ("vuln", "patched", "sqli_vuln", "sqli_patched")


class LabUnavailable(RuntimeError):
    pass


def php_available() -> bool:
    return shutil.which("php") is not None


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LabServer:
    """Context manager starting one lab variant on localhost."""

    def __init__(self, variant: str):
        if variant not in VARIANTS:
            raise ValueError(f"variant must be one of {VARIANTS}")
        if not php_available():
            raise LabUnavailable("the `php` CLI was not found on PATH")
        self.variant = variant
        self.docroot = LAB_DIR / variant
        self.host = "127.0.0.1"
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.port}"

    def _clean(self) -> None:
        # reset any uploaded artefacts from a previous run
        for sub in (self.docroot / "uploads", LAB_DIR / self.variant / "../storage_patched"):
            p = sub.resolve()
            if p.exists() and p.is_dir() and str(p).startswith(str(LAB_DIR)):
                for f in p.iterdir():
                    if f.is_file():
                        f.unlink()
        # reset the SQLi lab's throwaway SQLite database
        import tempfile
        for name in ("murs_sqli_vuln.db", "murs_sqli_patched.db"):
            dbf = Path(tempfile.gettempdir()) / name
            try:
                if dbf.exists():
                    dbf.unlink()
            except OSError:
                pass

    def __enter__(self) -> "LabServer":
        self._clean()
        self.proc = subprocess.Popen(
            ["php", "-S", f"{self.host}:{self.port}", "-t", str(self.docroot)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(self.docroot),
        )
        self._wait_ready()
        return self

    def _wait_ready(self, timeout: float = 8.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise LabUnavailable("php server exited during startup")
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise LabUnavailable("php server did not become ready in time")

    def __exit__(self, *exc):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._clean()
