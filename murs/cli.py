"""MURS command-line entry point with the Matrix terminal UI."""

from __future__ import annotations

import argparse
import sys
from contextlib import nullcontext

from . import __version__
from .config import ScanConfig
from .findings import severity_counts, SEVERITY_ORDER
from .netutil import check_host_safe
from .retest import compare, apply_retest, save_findings, load_findings
from .runner import run_assessment, prepare
from .ui import MatrixUI, G, GB, RED, YEL, R, DIM


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="murs",
        description="MURS — authorized web upload security research suite.",
    )
    p.add_argument("target", nargs="?", help="target URL (with or without scheme)")
    p.add_argument("--config", help="load a JSON config file")
    p.add_argument("--project", default="MURS research assessment")
    p.add_argument("--researcher", default="unspecified")
    p.add_argument("--scope-host", action="append", default=[],
                   help="additional in-scope host (repeatable)")
    p.add_argument("--port", action="append", type=int, default=[],
                   help="additional allowed port (repeatable)")
    p.add_argument("--depth", type=int, default=2, help="max crawl depth")
    p.add_argument("--max-requests", type=int, default=300)
    p.add_argument("--rate", type=float, default=8.0, help="requests per second")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--max-response-bytes", type=int, default=512 * 1024)
    p.add_argument("--max-file-bytes", type=int, default=64 * 1024)
    p.add_argument("--wordlist", help="path to a discovery wordlist")
    p.add_argument("--mode", choices=("passive", "discovery", "assessment"),
                   default="assessment")
    p.add_argument("--report-dir", default="reports")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    p.add_argument("--save-findings", help="write findings JSON (for later retest)")
    p.add_argument("--retest-baseline", help="compare against a saved findings JSON")
    p.add_argument("--auth-cookie", action="append", default=[], metavar="NAME=VALUE",
                   help="send a test session cookie (repeatable); kept in scope, "
                        "never written to the report")
    p.add_argument("--auth-header", action="append", default=[], metavar="NAME:VALUE",
                   help="send an auth header, e.g. 'Authorization: Bearer ...' "
                        "(repeatable); never written to the report")
    p.add_argument("--lab", choices=("vuln", "patched"),
                   help="run against the bundled localhost lab instead of a URL")
    p.add_argument("--allow-private", action="store_true",
                   help="permit private/loopback targets (self-hosted labs only)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"MURS {__version__}")
    return p


def _make_config(args) -> ScanConfig:
    if args.config:
        cfg = ScanConfig.from_file(args.config)
        if args.target:
            cfg.target = args.target
        return cfg
    if not args.target and not args.lab:
        raise SystemExit("error: a target URL (or --lab) is required")
    cfg = ScanConfig(
        target=args.target or "",
        project=args.project,
        researcher=args.researcher,
        allowed_hosts=set(args.scope_host),
        allowed_ports=set(args.port) | {80, 443},
        max_depth=args.depth,
        max_requests=args.max_requests,
        rate_limit_per_sec=args.rate,
        timeout=args.timeout,
        retries=args.retries,
        max_response_bytes=args.max_response_bytes,
        max_test_file_bytes=args.max_file_bytes,
        wordlist=args.wordlist,
        mode=args.mode,
        report_dir=args.report_dir,
    )
    return cfg


def _build_auth_headers(args) -> dict:
    """Build auth headers from --auth-cookie / --auth-header. Values are never
    echoed; only header names are ever shown to the user."""
    headers: dict[str, str] = {}
    cookies = []
    for c in args.auth_cookie:
        if "=" in c:
            cookies.append(c.strip())
    if cookies:
        headers["Cookie"] = "; ".join(cookies)
    for h in args.auth_header:
        if ":" in h:
            name, _, value = h.partition(":")
            if name.strip():
                headers[name.strip()] = value.strip()
    return headers


def _print_scope(ui: MatrixUI, cfg: ScanConfig, allow_private: bool) -> None:
    ui.head("Target and scope (review before active assessment)")
    ui.kv("Final URL", cfg.base_url)
    ui.kv("Project", cfg.project)
    ui.kv("Researcher", cfg.researcher)
    ui.kv("Allowed hosts", ", ".join(sorted(cfg.allowed_hosts)))
    ui.kv("Allowed ports", ", ".join(map(str, sorted(cfg.allowed_ports))))
    ui.kv("Mode", cfg.mode)
    ui.kv("Max requests", str(cfg.max_requests))
    ui.kv("Rate limit", f"{cfg.rate_limit_per_sec}/s")
    ui.kv("SSRF guard", "ON (private bypass scoped to approved hosts)"
          if allow_private else "ON")


def _print_findings(ui: MatrixUI, findings) -> None:
    ui.head(f"Findings ({len(findings)})")
    if not findings:
        ui.line("info", "no findings produced by the checks that ran")
        return
    counts = severity_counts(findings)
    ui.line("info", "severity: " + "  ".join(f"{k}={counts[k]}" for k in SEVERITY_ORDER))
    for f in findings:
        color = {"Critical": RED, "High": YEL, "Medium": G, "Low": DIM}.get(f.severity, G)
        print(f"  {color}{f.severity:<13}{R} {GB}{f.id}{R} {f.title} "
              f"{DIM}[{f.verification_status}]{R}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    import os
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    ui = MatrixUI(enabled=True)
    ui.banner()

    try:
        cfg = _make_config(args)
    except SystemExit as e:
        print(f"{RED}{e}{R}")
        return 2

    # pick the execution context: bundled lab, or a real target
    lab_ctx = nullcontext()
    allow_private = args.allow_private
    if args.lab:
        try:
            from .lab import LabServer, LabUnavailable
        except Exception as e:  # pragma: no cover
            print(f"{RED}lab unavailable: {e}{R}")
            return 3
        try:
            lab_ctx = LabServer(args.lab)
        except LabUnavailable as e:
            print(f"{RED}blocker: {e}. Install the PHP CLI to run the lab.{R}")
            return 3

    with lab_ctx as lab:
        if args.lab:
            cfg.target = f"{lab.base}/index.php"
            cfg.allowed_hosts = {lab.host}
            cfg.allowed_ports = {lab.port}
            allow_private = True
            ui.line("sys", f"lab '{args.lab}' running at {lab.base} (localhost only)")

        prepare(cfg)

        if not allow_private:
            chk = check_host_safe(cfg.base_host)
            if not chk.allowed:
                print(f"{RED}blocker: target refused by SSRF guard: {chk.reason}{R}")
                print(f"{DIM}Use --allow-private only for self-hosted/local labs.{R}")
                return 4
            ui.line("ok", f"host check: {cfg.base_host} -> {', '.join(chk.ips)}")

        _print_scope(ui, cfg, allow_private)

        # assemble an optional, user-supplied auth profile (never logged verbatim)
        auth_headers = _build_auth_headers(args)
        if auth_headers:
            ui.line("info", f"auth profile supplied ({', '.join(sorted(auth_headers))}) "
                            "— values hidden, kept in scope, excluded from the report")

        ui.head("Active assessment")
        try:
            result = run_assessment(cfg, emit=ui.emit, allow_private=allow_private,
                                    auth_headers=auth_headers)
        except Exception as e:  # pragma: no cover
            print(f"{RED}assessment error: {type(e).__name__}: {e}{R}")
            return 5

        # retest comparison
        retest_entries = []
        if args.retest_baseline:
            try:
                baseline = load_findings(args.retest_baseline)
                retest_entries = compare(baseline, result.findings)
                apply_retest(result.findings, retest_entries)
                ui.line("ok", f"retest vs baseline: "
                              f"{sum(1 for e in retest_entries if e.result=='Fixed')} fixed, "
                              f"{sum(1 for e in retest_entries if e.result=='Still Present')} still present, "
                              f"{sum(1 for e in retest_entries if e.result=='New')} new")
            except (OSError, ValueError) as e:
                ui.line("warn", f"could not load baseline: {e}")

        _print_findings(ui, result.findings)

        if args.save_findings:
            save_findings(result.findings, args.save_findings)
            ui.line("ok", f"findings saved to {args.save_findings}")

        if not args.no_pdf:
            try:
                from .report import ReportData, generate_pdf
            except ImportError:
                ui.line("warn", "reportlab not installed; skipping PDF "
                                "(pip install reportlab). Use --no-pdf to silence.")
                return 0
            data = ReportData(
                project=cfg.project, researcher=cfg.researcher, target=cfg.base_url,
                scope=cfg.to_dict(), findings=result.findings,
                endpoints=result.discovery.endpoints,
                technologies=result.discovery.technologies,
                started_at=result.started_at, finished_at=result.finished_at,
                requests_made=result.requests_made, retest=retest_entries,
                upload_attempts=result.upload_attempts,
                notes=result.notes,
            )
            path = generate_pdf(data, out_dir=cfg.report_dir)
            ui.head("Report")
            ui.kv("PDF", path)
        return 0


if __name__ == "__main__":
    sys.exit(main())
