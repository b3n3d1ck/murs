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
test target you control, add `--allow-private` — this approves **only the hosts
in scope**, not a blanket private-network bypass (a redirect to any other
private address is still refused).

The client resolves the host, validates every resolved IPv4/IPv6 address, and
**pins the socket to a validated IP** so the hostname cannot be re-resolved to a
private address mid-connection (DNS-rebinding resistance; covered by a test that
asserts the socket connects to the validated IP and the host is resolved only
once). HTTPS still verifies the certificate and uses SNI for the original
hostname. Redirects are followed with correct per-code semantics (301/302/303 →
GET, 307/308 preserve method+body) and credentials are dropped on any origin
change. Query strings are preserved on the wire (the fragment is never sent),
and IPv6 literals are bracketed correctly in the authority and `Host` header.

The `--allow-private` lab exception is **loopback-only and fail-closed**: an
approved host may resolve to `127.0.0.1`/`::1`, but if it resolves to a LAN
address, link-local, or the cloud metadata service — or to a mix — the request
is refused. Approving a hostname never means trusting whatever DNS returns.

### Authenticated assessment (optional)

For targets you're authorized to test that need a session, supply your own:

```bash
# safer: environment variables (not saved in shell history, not in the process
# argument list the way flags are)
export MURS_AUTH_COOKIE="session=<your-test-session>"
export MURS_AUTH_HEADER="Authorization: Bearer <token>"
python -m murs https://your-site.example

# or as flags (convenient, but see the caveat below)
python -m murs https://your-site.example \
  --auth-cookie "session=<your-test-session>" \
  --auth-header "Authorization: Bearer <token>"
```

MURS never acquires credentials itself and never bypasses authentication. The
values you supply are sent only to in-scope hosts, are **excluded from the PDF,
the findings JSON, and logs** (only header *names* are ever shown), and are
dropped whenever a redirect changes the **origin** (scheme, host, or port —
including any HTTPS→HTTP downgrade). Endpoints that still require authentication
are listed as not-assessed rather than treated as findings.

> **Caveat (honest):** credentials passed as `--auth-*` **flags** are visible to
> other local users through the process list and may be written to your shell
> history. The env-var form avoids both. MURS does not, and cannot, secure the
> input path before it reaches the process — only what it does with the value
> afterward. This is not claimed to be audited end-to-end.

**Redirect header policy.** A caller-supplied `Host` header never overrides the
`Host` derived from the validated target (that would defeat scope/SSRF pinning).
On any origin change (scheme, host, or port), MURS applies an **allowlist**, not
a denylist: it forwards only a few generic headers (`Accept`, `Accept-Language`,
`Accept-Encoding`, `User-Agent`), and drops **every** other caller header —
credentials and arbitrary custom headers alike. This means correctness does not
depend on a regex recognising every secret header name; an unknown custom auth
header (`X-Access-Token`, `X-Amz-Security-Token`, anything) is dropped because it
is simply not on the allowlist. Body-framing headers (`Content-Type`,
`Content-Length`) ride along only when the body itself is preserved (307/308);
when a 301/302/303 turns the request into a bodyless GET, they are removed with
the body. Same-origin hops keep the caller's headers unchanged.

**Secret redaction (evidence snippets).** `redact_secrets()` masks: credential
headers by name — Authorization (the full `Bearer`/`Basic` value, not just the
scheme word), Proxy-Authorization, Cookie, Set-Cookie, X-API-Key / API-Key,
X-Auth-Token, Authentication, X-CSRF-Token; `Bearer`/`Basic` values anywhere;
`key=value` secrets in query strings / form bodies; `"key":"value"` secrets in
JSON; and any long opaque token. It is **best-effort and pattern-based, not
universal** — it won't catch every encoding, custom key name, or
split/obfuscated value, and it scans only the first ~600 chars. The reliable
control is that MURS never stores request auth headers on responses or in
findings in the first place (verified by tests that a Bearer-token canary is
absent from stdout, the PDF, and the findings JSON).

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
no execution occurs. There is also an SQL-injection lab:

```bash
python -m murs --lab sqli_vuln     # string-interpolated SQLite login (injectable)
python -m murs --lab sqli_patched  # prepared-statement login (not injectable)
```

### Login discovery & SQL-injection assessment (opt-in)

```bash
# discover login pages in scope
python -m murs https://your-site.example --login-discovery

# + non-destructive SQL-injection diagnostics on discovered forms
python -m murs https://your-site.example --sqli \
  --sqli-delay 2 --per-host-max 200
```

Config JSON accepts the same keys: `enable_login`, `enable_sqli`, `login_wordlist`,
`sqli_delay`, `per_host_max`.

**Login discovery** classifies login pages from the crawl (forms with a password
field), URL patterns, and a configurable wordlist, scored with recorded evidence.
It is bounded by depth/request/timeout/rate limits, collapses catch-all/index
pages, and **does not claim every login page is found**.

**SQL-injection assessment** is non-destructive and evidence-based. It takes a
baseline, then sends structured diagnostics — quote/paren syntax breakers and an
`AND '1'='1'`/`'1'='2'` boolean differential (no `OR`-bypass, no `--`/`#`
comments, no stacked `;` queries, no `UNION` data extraction, no auth bypass).
It reports:

- **error-based indication** — a *DB-specific* error signature appears that was
  absent in the baseline (a generic 500 or the word "error" is never enough);
- **boolean-based indication** — true vs false conditions produce a consistent,
  significant response differential;
- **not injectable / inconclusive / not testable** otherwise.

It never concludes injection from an HTTP status or a generic error, and an
outcome is only **confirmed** inside the bundled `sqli_vuln` lab. On an external
target, results are indications (High / Potential) for manual confirmation —
confirm safely in the local lab or an explicitly-provided staging environment,
and never extract/alter data or bypass authentication on production.

**Request scheduling.** SQLi probes run through a scheduler with a configurable
inter-request delay (default **2s**), a global and optional **per-host** request
budget, and polite back-off: on HTTP 429 it pauses and honours `Retry-After`
(bounded), and it never rotates identity to evade throttling.

### Generating the PDF

The PDF is produced automatically unless `--no-pdf` is passed. It includes a
cover, project identity, executive summary, scope and limits, methodology,
severity summary, endpoints examined, the upload outcome matrix, discovered
login pages and the SQL-injection outcome table (when those run), verified vs
potential findings, full per-finding detail (evidence, impact, safe
reproduction, remediation), remediation priority, retest results, conclusion,
and a technical appendix —
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
- **DNS rebinding** is mitigated by pinning the socket to a validated IP (and
  refusing mixed public/private answers), covered by tests. The residual risk is
  a resolver/OS-level cache poisoning between validation and connect, which is
  outside the client's control.
- Discovery is link/wordlist based; it does not execute JavaScript, so SPA-only
  routes may be missed — this is reported, not hidden.
- The upload module confirms a stored location only by **retrieving the unique
  marker**. Paths it tries but cannot confirm are kept as *candidates* and never
  reported as the stored file; if the app hides the location, the result is
  *location not determined*.
- The lab proves execution risk for the **PHP** case; other interpreters are not
  modelled.

## Scope and intent

MURS is a tool for people with authorization to test a system. Running it
against systems you neither own nor are permitted to test may be illegal. The
authors provide it for authorized research, teaching, and remediation validation.
