# Security Review — Production Readiness Assessment

**Date:** 2026-03-05
**Reviewers:** 3 parallel agents (CISO security reviewer, security auditor, infrastructure security reviewer)
**Scope:** Full codebase (`bgp_route_analyzer.py`, config, tests, dependencies)
**Verdict:** **NO-GO** for production until critical and high findings are resolved.

---

## CRITICAL (4)

### C1. SSH Host Key Verification Disabled by Default

- **Location:** `bgp_route_analyzer.py`, `poll_router()` (~line 166)
- **Issue:** `ssh_strict` defaults to `False`, disabling Paramiko host key verification. This allows man-in-the-middle attacks on SSH connections to routers.
- **Impact:** An attacker on the network path can intercept SSH sessions, capture router credentials, and inject commands.
- **Fix:** Default `ssh_strict` to `True`. Require operators to explicitly opt out per-router with `"ssh_strict": false` in `routers.json`.

### C2. Timing-Unsafe API Key Comparison

- **Location:** `bgp_route_analyzer.py`, `verify_api_key()` (~line 410)
- **Issue:** API key is compared with `!=` operator, which short-circuits on first byte mismatch. This leaks key length and content via response timing.
- **Impact:** An attacker can recover the API key byte-by-byte with ~256 requests per byte position.
- **Fix:** Replace `key != API_KEY` with `hmac.compare_digest(key, API_KEY)`. Import `hmac` at top of file.

### C3. No Schema Validation on Router Config

- **Location:** `bgp_route_analyzer.py`, `_load_routers()` (~line 69)
- **Issue:** `routers.json` is loaded with no validation. Arbitrary keys are passed directly to Netmiko's `ConnectHandler`. A malicious or malformed config could inject unexpected SSH parameters.
- **Impact:** SSRF-adjacent risk — could connect to arbitrary hosts/ports. Unexpected Netmiko parameters could alter connection behavior.
- **Fix:** Define a Pydantic model for router config with an explicit allowlist of fields (`host`, `device_type`, `username`, `password`, `port`, `ssh_strict`). Validate on load. Reject unknown fields.

### C4. Plaintext Credentials in Router Config

- **Location:** `routers.json` (runtime config)
- **Issue:** Router passwords are stored as plaintext in a JSON file on disk. No integration with secrets managers or environment variable expansion.
- **Impact:** Credential exposure if file is readable by other users or included in backups/logs. Violates CIS and NIST credential storage guidelines.
- **Fix (recommended for production):** Support `BGP_ROUTER_PASSWORD` env var override, or integrate with AWS Secrets Manager / HashiCorp Vault. At minimum, validate file permissions (0600) and warn if too permissive.

---

## HIGH (6)

### H1. Rate Limiting Bypassable via Header Spoofing

- **Location:** `bgp_route_analyzer.py`, slowapi `Limiter` setup (~line 400)
- **Issue:** `get_remote_address` (from slowapi) trusts `X-Forwarded-For` headers by default. Without a trusted reverse proxy, any client can spoof their IP to bypass rate limits.
- **Impact:** Rate limiting is ineffective. Attackers can flood the API with snapshot requests, exhausting SSH connections and router resources.
- **Fix:** Implement a custom `key_func` that ignores proxy headers and uses `request.client.host` directly. Only trust `X-Forwarded-For` when behind a known proxy (configurable).

### H2. Unbounded Concurrent SSH Connections

- **Location:** `bgp_route_analyzer.py`, `POST /snapshots` endpoint (~line 466)
- **Issue:** Each POST request triggers `take_snapshots()`, which connects to all configured routers. Multiple concurrent requests spawn parallel SSH sessions with no mutex or semaphore.
- **Impact:** Resource exhaustion on both the analyzer host and target routers. Could trigger router security lockouts. Potential denial-of-service vector.
- **Fix:** Add an `asyncio.Lock` or `threading.Lock` around `take_snapshots()`. Return 429 if a snapshot is already in progress. Consider a background task queue.

### H3. No Security Response Headers

- **Location:** `bgp_route_analyzer.py`, FastAPI app creation (~line 433)
- **Issue:** No security headers are set on API responses. Missing: `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`, `Strict-Transport-Security`, `Content-Security-Policy`.
- **Impact:** Responses may be cached by intermediaries (leaking snapshot data), framed by malicious pages, or MIME-sniffed.
- **Fix:** Add a Starlette middleware that sets security headers on all responses.

### H4. No Database File Permission Controls

- **Location:** `bgp_route_analyzer.py`, `init_db()` / `get_db()` (~line 139)
- **Issue:** SQLite database is created with default umask permissions. On many systems this means world-readable (0644). The database contains raw router BGP output and network topology data.
- **Impact:** Any local user can read the database, exposing network topology, BGP attributes, and router names.
- **Fix:** After creating the database file, set permissions to `0o600` (`os.chmod()`). Verify on each open.

### H5. No TLS Enforcement When API Key Is Set

- **Location:** `bgp_route_analyzer.py`, `_cli()` serve mode (~line 573)
- **Issue:** When `BGP_ANALYZER_API_KEY` is set, the API key is transmitted in the `X-API-Key` header. If TLS is not configured (`--ssl-cert`/`--ssl-key` not provided), the key is sent in plaintext.
- **Impact:** API key can be captured by network sniffers or MITM attacks.
- **Fix:** Log a prominent warning when API key auth is enabled but TLS is not configured. Consider refusing to start without TLS when an API key is set (with a `--allow-insecure` override).

### H6. Exception Handler Leaks Internal Details

- **Location:** `bgp_route_analyzer.py`, global exception handler (~line 455)
- **Issue:** The exception handler logs `str(exc)` which may contain internal paths, database errors, or stack details. While the HTTP response is generic ("Internal server error"), the log output could leak to monitoring systems with broader access.
- **Impact:** Internal details (file paths, SQL errors, SSH errors) exposed in logs. Could aid attacker reconnaissance if logs are accessible.
- **Fix:** Log exception type and a sanitized message. Use `log.exception()` only at DEBUG level. At INFO/WARNING, log only the exception class name and a generic message.

---

## MEDIUM (9)

### M1. No Validation When Binding to 0.0.0.0 Without API Key

- **Location:** `_cli()` serve mode
- **Issue:** The server can bind to all interfaces (`--host 0.0.0.0`) without API key authentication enabled. No warning is emitted.
- **Fix:** Warn or refuse to bind to non-loopback addresses when `BGP_ANALYZER_API_KEY` is not set.

### M2. SQLite Without WAL Mode or Busy Timeout

- **Location:** `get_db()` context manager
- **Issue:** SQLite uses the default rollback journal mode. Under concurrent FastAPI requests, this causes `database is locked` errors.
- **Fix:** Enable WAL mode (`PRAGMA journal_mode=WAL`) and set `busy_timeout` (e.g., 5000ms) in `get_db()`.

### M3. Sensitive Data in Logs

- **Location:** Various log statements
- **Issue:** Router hostnames/IPs are logged at INFO level during polling. In shared logging systems, this exposes network topology.
- **Fix:** Log router names (not IPs) at INFO. Log IPs only at DEBUG level.

### M4. No Path Canonicalization on CLI Arguments

- **Location:** `--db` and `--router-config` CLI args
- **Issue:** User-supplied paths are used without canonicalization. Path traversal (e.g., `--db ../../../etc/shadow`) could write to unexpected locations.
- **Fix:** Resolve and canonicalize paths with `Path.resolve()`. Validate the target directory exists and is writable.

### M5. No device_type Validation

- **Location:** `_load_routers()`, passed to Netmiko
- **Issue:** `device_type` from `routers.json` is passed directly to Netmiko without validation. An invalid or unexpected value could cause crashes or unexpected behavior.
- **Fix:** Validate against a known allowlist of supported Netmiko device types.

### M6. Rate Limiting Only on POST /snapshots

- **Location:** FastAPI rate limiting decorator
- **Issue:** Only POST `/snapshots` is rate-limited. GET endpoints (`/snapshots`, `/snapshots/{id}`, `/diff`) have no rate limits, allowing enumeration and resource exhaustion.
- **Fix:** Apply rate limits to all endpoints with appropriate thresholds (higher for GETs, lower for POSTs).

### M7. CORS Accepts Arbitrary Origins

- **Location:** CORS middleware configuration
- **Issue:** `BGP_CORS_ORIGINS` accepts a comma-separated list with no validation. A wildcard (`*`) would allow any origin. No origin format validation is performed.
- **Fix:** Validate that origins are well-formed URLs. Reject wildcard (`*`) when API key auth is enabled. Log configured origins at startup.

### M8. No Data Retention Policy for raw_output

- **Location:** `snapshots` table schema
- **Issue:** Raw BGP output is stored indefinitely. Over time, the database grows unbounded. Raw output contains full router CLI output that may include sensitive information.
- **Fix:** Add a configurable retention period. Implement a cleanup function (or CLI command) that purges snapshots older than N days.

### M9. Uvicorn Not Hardened

- **Location:** `uvicorn.run()` call in `_cli()`
- **Issue:** Uvicorn runs with default settings: server header enabled (leaks version), no request size limits, no connection limits.
- **Fix:** Set `server_header=False`, `limit_concurrency`, and `limit_max_requests` in the `uvicorn.run()` call.

---

## LOW (6)

### L1. Dependencies Use Minimum Version Pins Only

- **Location:** `requirements.txt`
- **Issue:** All dependencies use `>=` pins (e.g., `netmiko>=4.1.0`). No upper bounds means untested major versions could be pulled in.
- **Risk:** A breaking change in a dependency could cause production failures.
- **Recommendation:** Pin to compatible releases (e.g., `netmiko~=4.1`) or use a lockfile.

### L2. OpenAPI/Swagger Docs Enabled by Default

- **Location:** FastAPI app initialization
- **Issue:** `/docs` and `/redoc` are accessible by default, exposing the full API schema including all endpoints and parameter descriptions.
- **Recommendation:** Disable in production with `docs_url=None, redoc_url=None` or gate behind auth.

### L3. No Audit Logging of Authentication Failures

- **Location:** `verify_api_key()` dependency
- **Issue:** Failed authentication attempts are not logged. No way to detect brute-force attacks against the API key.
- **Recommendation:** Log failed auth attempts with source IP at WARNING level.

### L4. API Key Loaded Once at Import

- **Location:** Module-level `API_KEY = os.environ.get(...)`
- **Issue:** The API key is read once at import time. Rotating the key requires restarting the server.
- **Recommendation:** For most deployments this is acceptable. For high-security environments, consider re-reading per-request or supporting key rotation signals.

### L5. No Input Length Limits on Snapshot Data

- **Location:** `save_snapshot()` — `raw_output` column
- **Issue:** Raw BGP output from routers is stored without size limits. A malfunctioning or compromised router could return extremely large output.
- **Recommendation:** Add a configurable max size for `raw_output` (e.g., 10MB). Truncate and warn if exceeded.

### L6. No Signal Handling for Graceful Shutdown

- **Location:** CLI mode, `_cli()`
- **Issue:** No SIGTERM/SIGINT handler for graceful shutdown during long-running snapshot operations. Interrupted snapshots leave partial data.
- **Recommendation:** Add signal handlers that set a cancellation flag checked between router polls.

---

## Positive Findings

All three reviewers noted these strengths:

- **SQL injection: zero risk.** All queries use parameterized statements throughout.
- **Input validation** on the `router` query parameter with regex pattern.
- **Default bind to 127.0.0.1** — not exposed to network by default.
- **`.gitignore`** correctly excludes `routers.json`, `.env`, `*.db`.
- **CORS disabled by default** — only enabled when `BGP_CORS_ORIGINS` is set.
- **Fixed SSH command string** — `show ip bgp` is hardcoded, not user-controllable.
- **Good test isolation** — all DB tests use `tmp_path` fixture for independent SQLite files.
- **Generic error responses** — API returns "Internal server error" without stack traces.

---

## Recommended Fix Priority

1. C1 + C2 — One-line fixes, highest security impact
2. H1 + H2 — Rate limit bypass and resource exhaustion
3. C3 — Router config validation (prevents SSRF-adjacent attacks)
4. H3 + H4 — Security headers and DB permissions
5. H5 + H6 — TLS warning and log sanitization
6. M1 + M2 — Network bind validation and SQLite hardening
7. Remaining medium and low findings
