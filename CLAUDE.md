# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGP Route Analyzer — a Python tool that SSH-polls edge routers (via Netmiko), parses BGP tables (via TextFSM), stores time-series snapshots in SQLite, and diffs pre/post change windows. Exposes a CLI, a security-hardened FastAPI REST API, and a React admin UI served from the same origin at `/ui`.

Components:
- `bgp_route_analyzer.py` — the entire backend (CLI + API), ~1900 lines
- `ui/` — Vite + React + TypeScript admin SPA, built to `ui/dist` and served by FastAPI
- `Dockerfile` / `docker-compose.yml` — multi-stage container build
- `docker-healthcheck.py` — auth-aware container healthcheck

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # requirements.txt is runtime-only

# Admin UI (optional — the server runs API-only without it)
cd ui && npm ci && npm run build
```

**Two requirements files.** `requirements.txt` holds runtime deps only, so the Docker image doesn't ship pytest. `requirements-dev.txt` starts with `-r requirements.txt` and adds `httpx` + `pytest`, so the two cannot drift. CI and local development install the dev file; the Dockerfile installs the runtime one.

Copy `routers.json.example` to `routers.json` and fill in router credentials (or set `BGP_ROUTER_PASSWORD` to inject a password without storing it in the file).

`ui/dist` is gitignored. If it is absent, `mount_ui()` logs a notice and the server starts in API-only mode — the UI is never a hard dependency of the backend.

## Common Commands

```bash
# CLI operations
python bgp_route_analyzer.py --snapshot              # Poll all routers (in parallel), save snapshots
python bgp_route_analyzer.py --list                  # List stored snapshots
python bgp_route_analyzer.py --list --router NAME    # Filter by router
python bgp_route_analyzer.py --routers               # Router inventory + health
python bgp_route_analyzer.py --audit                 # Recent audit log entries
python bgp_route_analyzer.py --diff --before ID --after ID  # Diff two snapshots
python bgp_route_analyzer.py --purge DAYS            # Delete snapshots older than N days (>=1)
python bgp_route_analyzer.py --purge-audit DAYS      # Delete audit entries older than N days

# API server + admin UI (binds to 127.0.0.1:8000; docs disabled unless BGP_ENABLE_DOCS=1)
python bgp_route_analyzer.py --serve                 # UI at http://127.0.0.1:8000/ui
python bgp_route_analyzer.py --serve --host HOST --port PORT
python bgp_route_analyzer.py --serve --ssl-cert cert.pem --ssl-key key.pem

# Override database path or router config
python bgp_route_analyzer.py --snapshot --db /path/to/db
python bgp_route_analyzer.py --serve --router-config /path/to/routers.json

# Backend linting and testing
.venv/bin/ruff check .
.venv/bin/flake8 bgp_route_analyzer.py --max-line-length 120
.venv/bin/mypy bgp_route_analyzer.py --ignore-missing-imports
.venv/bin/python -m pytest tests/ -v
.venv/bin/python -m pytest tests/test_parsing.py::test_parse_returns_correct_count  # single test

# UI
cd ui && npm run dev      # Vite dev server on :5173, proxies API to :8000
cd ui && npm run lint     # tsc --noEmit
cd ui && npm run build    # emits ui/dist for FastAPI to serve
```

```bash
# Docker
docker compose up -d                             # API + UI on 127.0.0.1:8000
docker compose run --rm analyzer --snapshot      # CLI against the same volume
docker build -t bgp-route-analyzer .
```

CI (`.github/workflows/ci.yml`) has four jobs: `lint` (ruff/flake8/mypy on 3.13), `test` (pytest on the 3.12/3.13 matrix), `ui` (npm ci, typecheck, build), and `docker` (build the image, then smoke-test that it becomes healthy, refuses unauthenticated requests, serves the UI, runs as UID 10001, and writes the DB to `/data`). All run on every push/PR against `main`.

**Dev-server note:** run `npm run dev` alongside a real `--serve` backend. The Vite proxy forwards API paths to `127.0.0.1:8000` on the *same* origin deliberately — the session cookie is `SameSite=strict` and would be dropped on a cross-origin request.

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `BGP_ROUTER_CONFIG` | Path to router credentials JSON | `routers.json` |
| `BGP_DB_PATH` | SQLite database file path | `bgp_snapshots.db` |
| `BGP_ANALYZER_API_KEY` | API key for `X-API-Key` auth **and** the admin UI login password | unset (auth disabled) |
| `BGP_CORS_ORIGINS` | Comma-separated allowed CORS origins | unset (CORS disabled) |
| `BGP_ROUTER_PASSWORD` | Default router password override (used when a router entry omits `password`) | unset |
| `BGP_ENABLE_DOCS` | Enable `/docs` and `/redoc` OpenAPI UI (`1`/`true`/`yes`) | unset (docs disabled) |
| `BGP_ASSUME_TLS` | Treat traffic as TLS-protected when a proxy terminates TLS; sets `Secure` cookies + HSTS | unset |
| `BGP_SESSION_TTL` | Absolute session lifetime, seconds | `28800` (8h) |
| `BGP_SESSION_IDLE` | Session idle timeout, seconds | `1800` (30m) |
| `BGP_POLL_WORKERS` | Max concurrent router SSH polls | `5` |
| `BGP_JOB_HISTORY` | Snapshot jobs retained in memory | `50` |
| `BGP_LIMIT_CONCURRENCY` | uvicorn concurrency limit | `100` |
| `BGP_LIMIT_MAX_REQUESTS` | uvicorn max requests before exit | unset (unlimited) |

All bounded integers go through `_env_int()`, which logs and falls back to the default on unparseable or out-of-range values rather than crashing at import.

`BGP_LIMIT_MAX_REQUESTS` is unset by default on purpose. uvicorn *shuts the server down* when the counter is reached; the old hardcoded `10000` meant a dashboard polling job status would silently kill the process within hours. Only set it when a supervisor restarts the process.

## Architecture

The backend lives entirely in `bgp_route_analyzer.py`, organized into these sections in order:

1. **Logging & Config** — `logging.basicConfig()` at import time. Env-driven globals (`DB_PATH`, `API_KEY`, `CORS_ORIGINS`). `ALLOWED_ROUTER_FIELDS` and `SUPPORTED_DEVICE_TYPES` are allowlists used to validate `routers.json`. `MAX_RAW_OUTPUT_SIZE` caps stored CLI output at 10MB. `_env_int()` reads bounded integer settings. A `threading.Lock` (`_snapshot_lock`) prevents concurrent snapshot runs; a `threading.Event` (`_shutdown_event`) plus SIGINT/SIGTERM handlers support graceful shutdown mid-poll.
2. **Session config** — Cookie names, TTL/idle timeouts, `_tls_enabled` (drives the `Secure` cookie flag), the `_sessions` store, and the `_jobs` registry with their locks.
3. **`_load_routers()`** — Loads and validates `routers.json`: canonicalizes the path, warns if the file is group/world-readable, tolerates malformed JSON (logs and returns `[]` rather than crashing at import), requires `host`/`device_type`/`name`/`username` on every entry, rejects unknown fields against `ALLOWED_ROUTER_FIELDS`, validates `device_type` against `SUPPORTED_DEVICE_TYPES`, and applies `BGP_ROUTER_PASSWORD` as a fallback. Loaded once into the module-level `ROUTERS` global (swappable via `--router-config`).
4. **Database** — Three tables: `snapshots`, `prefixes` (FK to snapshots), and `audit_log`. `init_db()` creates tables plus indexes and chmods the DB to `0600`. `get_db()` is a context manager enabling WAL mode, a 5s busy timeout, and `PRAGMA foreign_keys=ON`, with an explicit `rollback()` on any exception. All DB functions take an optional `db_path` (defaults to global `DB_PATH` at call time) for testability.
5. **Audit log** — `record_audit()` (best-effort: swallows and logs its own failures so auditing can never break the audited operation), `list_audit_log()`, `purge_old_audit()`. Audit retention is deliberately separate from snapshot retention.
6. **Session management** — `create_session()`, `get_session()`, `destroy_session()`. Tokens are `secrets.token_urlsafe(32)`; only their SHA-256 digest is stored, so a memory dump yields nothing usable. Sessions are pruned on every access against both absolute TTL and idle timeout, use `time.monotonic()` (immune to wall-clock jumps), and are capped at `MAX_SESSIONS`. Storage is in-process — a restart logs everyone out.
7. **Polling** — `poll_router()` connects via Netmiko with `ssh_strict` defaulting to `True`, runs `show ip bgp`, truncates oversized output, parses with TextFSM. Logs the router name at INFO, host/IP only at DEBUG. Warns if output is non-empty but zero prefixes parse.
8. **Snapshot storage & jobs** — `save_snapshot()`, `_snapshot_one()` (polls one router, never raises, audits both outcomes), `collect_snapshot_results()` (bounded `ThreadPoolExecutor`, capped by `MAX_POLL_WORKERS`), `take_snapshots()`, and the job engine: `start_snapshot_job()` spawns a daemon thread and returns immediately; `get_job()`/`list_jobs()` read from a bounded `OrderedDict`. `_snapshot_lock` is acquired in the caller thread and released in the worker.
9. **Data retention** — `purge_old_snapshots(days)`.
10. **Diff engine** — `diff_snapshots()` compares two snapshots using composite key `(network, next_hop)` to handle multi-path BGP (ECMP). Detects added/removed prefixes and attribute changes. A next-hop change appears as one removed + one added prefix.
11. **Queries** — `list_snapshots()`/`count_snapshots()` share `_snapshot_filters()` (only column names are interpolated; every value stays a bound parameter). `router_inventory()` joins latest+previous snapshot counts with the most recent poll failure per router. `_mask_host()` redacts addresses.
12. **Pydantic models** — Typed models for every endpoint so the OpenAPI schema stays a real contract.
13. **FastAPI API** — Lifespan startup, dual auth (`verify_api_key`), rate limiting keyed off the raw socket IP, CORS, access logging, `SecurityHeadersMiddleware` with route-scoped CSP, and a sanitized global exception handler.
14. **UI mounting** — `mount_ui()` serves `ui/dist` at `/ui`, with a containment check so a traversal path can never escape the build dir, falling back to `index.html` for client-side routes.
15. **CLI** — argparse `_cli()` with mutually exclusive modes. Sets `_tls_enabled`, canonicalizes paths, validates `--port`, requires `--ssl-cert`/`--ssl-key` together.

## API Surface

| Endpoint | Notes |
|---|---|
| `POST /auth/login` | Exchanges the API key for a session cookie. Rate limited 5/min. Public. |
| `POST /auth/logout` | Destroys the session. |
| `GET /auth/status` | Whether auth is required and whether the caller is logged in. Public. |
| `GET /health` | Authenticated (unchanged from before the UI work). |
| `POST /snapshots` | **202** with a job record. `?wait=true` blocks and returns the legacy `{snapshot_ids, message}` shape. |
| `GET /jobs`, `GET /jobs/{id}` | Job status with per-router results. Rate limited 120/min since the UI polls. |
| `GET /routers` | Router inventory + health. Never returns credentials or full host addresses. |
| `GET /snapshots` | Paginated envelope `{items, total, limit, offset}` with `router`/`since`/`until` filters. |
| `GET /snapshots/{id}` | Prefix page via `prefix_limit`/`prefix_offset`; `prefix_count` is the total, not the page size. |
| `GET /diff` | Adds `before_router`, `after_router`, `cross_router`. |
| `GET /audit` | Paginated audit trail. |

Two responses changed shape and are **breaking** for existing consumers: `GET /snapshots` (list → paginated envelope) and `POST /snapshots` (sync result → 202 job; use `?wait=true` to keep the old behavior).

## Authentication Model

Two mechanisms with deliberately different CSRF exposure, both checked in `verify_api_key`:

- **Session cookie** — ambient (the browser attaches it automatically), so mutating methods additionally require an `X-CSRF-Token` header matching the token bound to that session. Compared with `hmac.compare_digest`.
- **`X-API-Key` header** — never sent automatically by a browser, so it is not forgeable cross-site and needs no CSRF token. Existing scripts keep working unchanged.

The session cookie is `HttpOnly` (JS cannot read it, so XSS cannot exfiltrate it) and `SameSite=strict`. The CSRF cookie is deliberately *not* HttpOnly — the SPA must read it to echo it back; possessing it alone proves nothing.

`Secure` is set only when TLS is configured (`_tls_enabled`), because a `Secure` cookie is never sent over plain HTTP and forcing it on would silently break loopback development. Running with an API key but no TLS logs a warning.

When `BGP_ANALYZER_API_KEY` is unset, auth is disabled entirely and the UI shows a persistent warning banner.

## Security Conventions

This codebase has been through dedicated security and operational hardening passes (see `tasks/security-review.md` and `tasks/operational-review.md` for the original findings — useful background if you're touching auth, networking, or DB code, though the file has since evolved past what those docs describe). When modifying this code, preserve these invariants:

- SSH host key verification (`ssh_strict`) defaults to `True`; don't silently relax it.
- API key comparisons must use `hmac.compare_digest`, never `==`/`!=`.
- Router config fields are allowlisted (`ALLOWED_ROUTER_FIELDS`) and `device_type` is validated against `SUPPORTED_DEVICE_TYPES` — extend these sets rather than bypassing validation.
- All SQL is parameterized — never interpolate user input into a query string.
- The rate limiter keys off the real socket IP (`_get_client_ip`), not proxy headers, unless a trusted-proxy config is added deliberately.
- Exception responses stay generic (`"Internal server error"`); detailed errors go to logs only, and only at DEBUG.
- New DB files/config files should end up `0600`, not world-readable.
- Session tokens are stored hashed, never raw. Any new credential in the session store gets the same treatment.
- CSRF is required for cookie-authenticated mutations. A new mutating endpoint inherits this automatically via the global dependency — don't add per-route exemptions.
- The UI CSP has no `unsafe-inline`. That means **no inline `style` attributes and no inline `<style>`/`<script>`** in the SPA: use `styles.css` and real elements (this is why the job progress bar is a native `<progress>`, not a div with a computed width).
- `router_inventory()` must never return credentials, and host addresses stay masked via `_mask_host()` — addresses are DEBUG-only [M3]. There is a test asserting this.
- `mount_ui()`'s containment check (`is_relative_to(resolved_dist)`) is what stops path traversal from serving source files. Keep it if you touch static serving.

## Key Dependencies

- **netmiko** — SSH connections to network devices (Cisco IOS, IOS-XR, Arista, Junos, etc.)
- **textfsm** — Structured parsing of CLI output via templates
- **fastapi + uvicorn** — REST API server (uvicorn runs with `server_header=False`, `limit_concurrency`, `limit_max_requests`)
- **slowapi** — Rate limiting middleware
- **pydantic** — Response models and validation
- **httpx + pytest** — Testing (TestClient requires httpx)
- **sqlite3** — Built-in, no external DB required

Dependencies are pinned with compatible-release specifiers (`~=`) in `requirements.txt`; Dependabot keeps them current (see recent `chore: update ... requirement` commits).

## Testing

117 tests in `tests/`, plus a shared `conftest.py`:
- `test_parsing.py` — TextFSM parser against sample Cisco IOS BGP output
- `test_diff.py` — Diff engine including multi-path and next-hop change scenarios
- `test_db.py` — Database CRUD, ordering, filtering, composite key loading
- `test_config.py` — `_load_routers()` schema validation and `_validate_cors_origins()`
- `test_api.py` — FastAPI endpoints: auth, security headers, snapshot locking, input validation, response shapes, docs-disabled-by-default
- `test_auth.py` — Session store (hashing, idle expiry), login/logout, CSRF enforcement, API-key bypass of CSRF, audit of auth events
- `test_jobs.py` — Parallel polling (concurrency and pool bounds are asserted with real timing), job lifecycle, history eviction, router inventory, pagination
- `test_ui.py` — Static mounting, SPA fallback, path-traversal containment, CSP scoping

`conftest.py` has three fixtures, two of them autouse:
- `test_db` — isolated initialized SQLite file under `tmp_path`
- `reset_rate_limiter` (autouse) — clears slowapi state between tests. **Required**: slowapi keys buckets by client IP and TestClient always presents as `testclient`, so without it every test in a module shares one bucket and later tests fail with 429 depending on execution order.
- `clear_sessions` (autouse) — gives each test a fresh in-memory session store

DB-dependent tests use `tmp_path`. API tests monkeypatch `bgp_route_analyzer.DB_PATH`, `API_KEY`, and `ROUTERS` directly rather than using env vars, since those globals are read once at import time. Job tests monkeypatch `bgp_route_analyzer.poll_router` so nothing touches the network.

## Vendor Customization

To support non-Cisco devices, two things need changing:
1. The command string in `poll_router()` (e.g., `show bgp ipv4 unicast` for IOS-XR)
2. The `TEXTFSM_TEMPLATE` constant to match the vendor's output format

`SUPPORTED_DEVICE_TYPES` also needs the new Netmiko `device_type` value added, or `_load_routers()` will reject the config.

## Database Schema

- `snapshots`: id, router (name), captured_at (ISO timestamp), raw_output (full CLI output, truncated at 10MB)
- `prefixes`: id, snapshot_id (FK, `PRAGMA foreign_keys=ON` enforced), network, next_hop, metric, local_pref, weight, as_path, origin
- `audit_log`: id, timestamp, actor, action, outcome, target, source_ip, detail

Indexes: `idx_prefixes_snapshot`, `idx_snapshots_router_captured`, `idx_snapshots_captured`, `idx_audit_timestamp`, `idx_audit_action`.

Audit actions currently recorded: `login`, `logout`, `csrf_failure`, `snapshot`, `poll_router`, `purge`.

All tables use `CREATE TABLE IF NOT EXISTS`; there is no migration framework, so an existing DB picks up `audit_log` and the new indexes automatically on next `init_db()`, but any future column change needs a manual `ALTER TABLE` or a fresh DB.

## Container Notes

Things that will bite if changed carelessly:

- **`/data` is owned by the runtime user and `chmod 700`.** SQLite in WAL mode writes `-wal`/`-shm` siblings, so the *directory* must be writable — making only the DB file writable is not enough.
- **The healthcheck is a script, not an inline `CMD`.** `/health` requires auth when `BGP_ANALYZER_API_KEY` is set, so `docker-healthcheck.py` sends `X-API-Key`; a plain `curl /health` would fail closed and mark healthy containers unhealthy. It also lets the check be tested outside a container.
- **`--host 0.0.0.0` in `CMD` is correct** inside a network namespace. The app's existing "binding non-loopback without an API key" warning still fires and is still the right signal. Compose publishes to `127.0.0.1` only.
- **App files are root-owned**, writable only by root, while the process runs as UID 10001 — a compromised process cannot rewrite its own code.
- **Compose sets `read_only: true`** with a tmpfs on `/tmp`. Anything new that writes outside `/data` or `/tmp` will fail there.
- **`.dockerignore` excludes `routers.json`, `*.db`, `.env`, and `*.pem`/`*.key`.** Keep it that way — the build context is not a secret store.
- **`ENTRYPOINT` is exec-form** so the app is PID 1 and receives signals directly. Note that in `--serve` mode uvicorn installs its own handlers and job threads are daemons, so SIGTERM ends in-flight polls abruptly — safe (WAL + atomic per-snapshot commits) but *not* the graceful drain `_shutdown_event` gives `--snapshot` runs. Don't document it as graceful.
- **The runtime user has a real home directory** (`/home/bgp/.ssh`). This is load-bearing: `ssh_strict` defaults to `True` and paramiko reads `~/.ssh/known_hosts`, so without somewhere to mount `known_hosts` every poll fails verification and the only workaround would be relaxing `ssh_strict`.
- **`routers.json` must be readable by UID 10001.** A `0600` file owned by another UID is unreadable in the container. `_load_routers()` now catches `OSError` around *all* filesystem access — `exists()` and `stat()` raise too, not just `open()` — because it runs at import, so an escaping error kills the process before argparse and becomes a restart-policy crash loop.

## UI Structure

```
ui/
├── index.html          # shell; references /ui/favicon.svg
├── vite.config.ts      # base: "/ui/", dev proxy to :8000
├── public/favicon.svg
└── src/
    ├── main.tsx        # React root
    ├── App.tsx         # auth gate, tab routing, 403 → re-check auth
    ├── api.ts          # typed client; reads CSRF cookie, sets header
    ├── styles.css      # all styling (CSP forbids inline styles)
    └── components/
        ├── Login.tsx      # clears the key from state after exchange
        ├── Routers.tsx    # inventory cards + trigger + live job polling
        ├── Snapshots.tsx  # paginated list + detail with prefix table
        ├── DiffView.tsx   # diff viewer + AuditLog component
        └── common.tsx     # Pill, Banner, Empty, Time, Delta, Pager
```

State is plain `useState`/`useEffect` — no router or state library. Tab selection lives in `App.tsx`; deep-linking is not implemented (all UI paths serve the same shell).

`Routers.tsx` polls `GET /jobs/{id}` every 1.5s while a job runs, then refreshes the inventory once it settles. On mount it calls `GET /jobs?limit=1` to reattach to a job still running from a previous page load.
