# MURS — Matrix Upload Research Suite

An authorized web-security research tool focused on **file-upload safety**. MURS
runs scope-bound active discovery, assesses upload endpoints with **inert,
uniquely-marked probe files**, classifies findings by evidence, generates a
professional PDF report, and supports before/after **retesting**. It ships an
isolated **localhost lab** (a deliberately-vulnerable PHP app and a patched
one) so upload-to-RCE risk can be demonstrated — and fixed — reproducibly.

> MURS is for systems you own or are explicitly authorized to test. It does not
> grant authorization. It never uploads functional webshells, backdoors, reverse
> shells, or command-execution payloads, and never attempts to bypass
> authentication or access control. Server-side code execution is demonstrated
> only inside the bundled lab, using an inert echo-marker.

## Why upload testing is handled carefully here

A `200 OK`, a `.php` filename, or a "file uploaded" message proves nothing about
whether a server will *run* an uploaded file. MURS only asserts execution when
the stored file, once fetched, returns the **evaluated** marker (and not its raw
source). The marker is a static `echo` of a random token: no command execution,
no input handling, no includes — it cannot be weaponized.

## Architecture

```
murs/
  netutil.py     URL normalization, DNS/IP validation (SSRF), scope checks
  httpclient.py  scope-bound HTTP: timeouts, retries, rate limit, body cap,
                 per-hop redirect re-validation, request budget
  forms.py       HTML link/form/file-input parsing (stdlib)
  discovery.py   crawl + directory wordlist + fingerprinting + soft-404
  upload.py      inert upload probes, staged evidence, access-control checks
  findings.py    evidence-bound classification (severity/confidence/status)
  report.py      ReportLab PDF (cover, sections, tables, page numbers)
  retest.py      before/after comparison (Fixed / Still Present / New)
  runner.py      orchestration: discovery -> upload -> findings
  cli.py, ui.py  argparse + Matrix terminal UI (events reflect real work)
  lab/           localhost PHP lab: vuln/ and patched/ + server runner
  wordlists/     default discovery wordlist
tests/           unittest suite + a local HTTP fixture app
```

Runtime dependencies: **Python 3.10+** and **reportlab** (for PDF). The local
lab needs the **php** CLI. Everything else is the standard library.

## Installation

```bash
git clone <this-repo> murs && cd murs
python3 -m pip install -r requirements.txt     # installs reportlab
# optional, for the lab: install php (e.g. apt install php-cli)
```

No install step is required to run it from the source tree.

## Running

All of these are equivalent entry points:

```bash
./run.sh            <args>     # Linux / macOS / WSL / Kali / Ubuntu
run.cmd             <args>     # Windows CMD
powershell -File run.ps1 <args>  # Windows PowerShell
python -m murs      <args>     # any platform
```

The launchers check for Python, reportlab and php, and print clear notes if any
are missing (MURS still runs; only the dependent feature is skipped).

### Scanning an authorized target

```bash
python -m murs https://your-site.example \
  --project "Q1 upload review" --researcher "you" \
  --scope-host your-site.example --depth 2 --max-requests 300 --rate 6
```

MURS normalizes the URL (scheme optional, `www` accepted), prints the **final
URL and scope** before the active phase, then runs discovery and (in
`assessment` mode) upload probing. A PDF lands in `reports/`.

Private/loopback targets are refused by the SSRF guard. For a self-hosted local
test target you control, add `--allow-private`.

### Setting scope

- `--scope-host HOST` (repeatable) — hosts allowed in scope. The target host is
  always added. Only these hosts are ever requested; redirects leaving them are
  reported, not followed.
- `--port N` (repeatable), `--depth`, `--max-requests`, `--rate`, `--timeout`,
  `--retries`, `--max-response-bytes`, `--max-file-bytes`, `--wordlist`,
  `--mode {passive,discovery,assessment}`, `--report-dir`.
- Or load everything from JSON: `--config config.json` (see `ScanConfig`).

### Active discovery

Discovery crawls in-scope links, parses forms (flagging multipart/file-input
upload forms), probes a configurable directory wordlist, fingerprints the server
/ tech (incl. WordPress when evidenced), and lists missing security headers.
Responses are classified as `normal`, `auth-required`, `not-found`, `redirect`,
`rate-limited`, `error`, or `ambiguous`, with **soft-404 calibration** (two
probes) so fallback pages don't become false positives.

### Reading the upload assessment

For each discovered upload endpoint, MURS sends inert probes (image, text,
script-extension canary, double-extension) and records, per probe: whether it
was **sent**, the server's response, whether it was tentatively **accepted**,
the **stored location** (if derivable), whether it was **accessible**, whether
it was **access-controlled**, and whether it **executed**. Only an observed
evaluated marker raises a finding to *Unrestricted upload → code execution*
(Critical / Confirmed).

Each probe resolves to exactly one explicit **outcome** (kept separate on
purpose), reported in the terminal and in the PDF's outcome matrix:

| Outcome | Meaning | Execution URL reported? |
|---|---|---|
| `rejected` | validation refused the file | no |
| `accepted_location_unknown` | stored, location not derivable | no |
| `accepted_access_controlled` | stored, but the file is not retrievable (401/403) | no |
| `accepted_public_not_interpreted` | retrievable, served as inert source | no |
| `server_side_interpreted_unconfirmed` | processed server-side, but execution **not** proven | no |
| `execution_unconfirmed` | accepted, but execution could not be verified | no |
| `execution_confirmed` | evaluated marker returned — execution proven | **yes** |

An execution URL is emitted **only** for `execution_confirmed`. Interpretation
that cannot be proven is reported as unconfirmed, never inferred from an HTTP
status or a file extension.

### Running the local lab

```bash
python -m murs --lab vuln       # intentionally-vulnerable app (localhost only)
python -m murs --lab patched    # the fixed app, for comparison
```

The lab binds to `127.0.0.1` on an ephemeral port, resets its upload dirs each
run, and is for local research only. Against `vuln`, MURS confirms execution of
the inert canary (Critical); against `patched`, the script probe is rejected and
no execution occurs.

### Generating the PDF

The PDF is produced automatically unless `--no-pdf` is passed. It includes a
cover, project identity, executive summary, scope and limits, methodology,
severity summary, endpoints examined, verified vs potential findings, full
per-finding detail (evidence, impact, safe reproduction, remediation),
remediation priority, retest results, conclusion, and a technical appendix —
with page numbers, header/footer, and document metadata. The output path is
printed only after the file is written.

### Retesting after a fix

```bash
# 1. baseline the current state
python -m murs https://your-site.example --save-findings baseline.json
# 2. after remediation, compare
python -m murs https://your-site.example --retest-baseline baseline.json
```

Findings are matched by a stable ID derived from category + host + path, so a
retest of the same deployment reports each prior finding as **Fixed** or **Still
Present**, and surfaces **New** ones. (Demo: baseline `--lab vuln`, then retest
`--lab patched` — the execution finding reads as Fixed.)

## Testing

```bash
python -m unittest discover -s tests -v
```

The suite uses a local HTTP fixture and the PHP lab — no third-party sites.
Tests that need `php` are skipped (not failed) when it is absent, and report as
skipped.

## Troubleshooting

- **"reportlab not installed"** — `python -m pip install -r requirements.txt`.
  MURS still runs discovery/upload; only the PDF is skipped.
- **"blocker: target refused by SSRF guard"** — the target resolves to a
  private/reserved address. That is intended. Use `--allow-private` only for
  local labs you control.
- **"blocker: the php CLI was not found"** — install php to use `--lab`.
- **"request budget reached"** — raise `--max-requests`.

## Limitations (honest)

- Discovery issues requests **serially** under the rate limit; the `concurrency`
  config value is reserved and not yet parallelised.
- **DNS rebinding** is only partially mitigated: the host is validated at check
  time, but the standard-library client cannot pin the socket to the validated
  IP for the subsequent request.
- Discovery is link/wordlist based; it does not execute JavaScript, so SPA-only
  routes may be missed.
- The upload module derives the stored location from the response and a few
  common paths; if the app hides it, the result is reported as *location not
  determined* rather than guessed.
- The lab proves execution risk for the **PHP** case; other interpreters are not
  modelled.

## Scope and intent

MURS is a tool for people with authorization to test a system. Running it
against systems you neither own nor are permitted to test may be illegal. The
authors provide it for authorized research, teaching, and remediation validation.
