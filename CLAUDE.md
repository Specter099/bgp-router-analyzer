# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGP Route Analyzer — a single-file Python tool that SSH-polls edge routers (via Netmiko), parses BGP tables (via TextFSM), stores time-series snapshots in SQLite, and diffs pre/post change windows. Exposes both a CLI and a security-hardened FastAPI REST API for NOC use.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `routers.json.example` to `routers.json` and fill in router credentials (or set `BGP_ROUTER_PASSWORD` to inject a password without storing it in the file).

## Common Commands

```bash
# CLI operations
python bgp_route_analyzer.py --snapshot              # Poll all routers, save snapshots
python bgp_route_analyzer.py --list                  # List stored snapshots
python bgp_route_analyzer.py --list --router NAME    # Filter by router
python bgp_route_analyzer.py --diff --before ID --after ID  # Diff two snapshots
python bgp_route_analyzer.py --purge DAYS            # Delete snapshots older than N days (>=1)

# API server (binds to 127.0.0.1:8000 by default; docs disabled unless BGP_ENABLE_DOCS=1)
python bgp_route_analyzer.py --serve
python bgp_route_analyzer.py --serve --host HOST --port PORT
python bgp_route_analyzer.py --serve --ssl-cert cert.pem --ssl-key key.pem

# Override database path or router config
python bgp_route_analyzer.py --snapshot --db /path/to/db
python bgp_route_analyzer.py --serve --router-config /path/to/routers.json

# Linting and testing
.venv/bin/ruff check .
.venv/bin/flake8 bgp_route_analyzer.py --max-line-length 120
.venv/bin/mypy bgp_route_analyzer.py --ignore-missing-imports
.venv/bin/python -m pytest tests/ -v
.venv/bin/python -m pytest tests/test_parsing.py::test_parse_returns_correct_count  # single test
```

CI (`.github/workflows/ci.yml`) runs `ruff check`, `flake8`, `mypy` on Python 3.13, and `pytest` on the 3.12/3.13 matrix for every push/PR against `main`. Run the same commands locally before pushing.

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `BGP_ROUTER_CONFIG` | Path to router credentials JSON | `routers.json` |
| `BGP_DB_PATH` | SQLite database file path | `bgp_snapshots.db` |
| `BGP_ANALYZER_API_KEY` | API key for `X-API-Key` header auth | unset (auth disabled) |
| `BGP_CORS_ORIGINS` | Comma-separated allowed CORS origins | unset (CORS disabled) |
| `BGP_ROUTER_PASSWORD` | Default router password override (used when a router entry omits `password`) | unset |
| `BGP_ENABLE_DOCS` | Enable `/docs` and `/redoc` OpenAPI UI (`1`/`true`/`yes`) | unset (docs disabled) |

## Architecture

Everything lives in `bgp_route_analyzer.py` (~890 lines). The file is organized into clearly separated sections, in this order:

1. **Logging & Config** — `logging.basicConfig()` at import time. Env-driven globals (`DB_PATH`, `API_KEY`, `CORS_ORIGINS`). `ALLOWED_ROUTER_FIELDS` and `SUPPORTED_DEVICE_TYPES` are allowlists used to validate `routers.json`. `MAX_RAW_OUTPUT_SIZE` caps stored CLI output at 10MB. A module-level `threading.Lock` (`_snapshot_lock`) prevents concurrent snapshot runs, and a `threading.Event` (`_shutdown_event`) plus SIGINT/SIGTERM handlers support graceful shutdown mid-poll.
2. **`_load_routers()`** — Loads and validates `routers.json`: canonicalizes the path, warns if the file is group/world-readable, tolerates malformed JSON (logs and returns `[]` rather than crashing at import), requires `host`/`device_type`/`name`/`username` on every entry, rejects unknown fields against `ALLOWED_ROUTER_FIELDS`, validates `device_type` against `SUPPORTED_DEVICE_TYPES`, and applies `BGP_ROUTER_PASSWORD` as a fallback when an entry has no `password`. Router list is loaded once into the module-level `ROUTERS` global at import time (and can be swapped via `--router-config`).
3. **Database** — SQLite schema with two tables: `snapshots` (metadata + raw output) and `prefixes` (parsed BGP attributes per snapshot, FK to `snapshots`). `init_db()` creates tables and chmods the DB file to `0600`. `get_db()` is a context manager that enables WAL mode, a 5s busy timeout, and `PRAGMA foreign_keys=ON`, and does an explicit `rollback()` on any exception before closing. All DB functions accept an optional `db_path` parameter (defaults to global `DB_PATH` at call time) for testability.
4. **Polling** — `poll_router()` connects via Netmiko with `ssh_strict` defaulting to `True` (host key verification enabled), runs `show ip bgp`, truncates oversized output, and parses with TextFSM. Logs the router name at INFO and the host/IP only at DEBUG. Warns (but doesn't fail) if output is non-empty but zero prefixes parse. `_parse_bgp_table()` handles the TextFSM template execution.
5. **Snapshot storage** — `save_snapshot()` (normalizes prefix dicts to avoid missing-key SQL errors), `take_snapshots()` (broad `except Exception` per router so one failure doesn't abort the rest; checks `_shutdown_event` between routers), `list_snapshots()`, `_snapshot_info()`, `_load_prefix_map()` (logs a warning on duplicate composite keys).
6. **Data retention** — `purge_old_snapshots(days)` deletes snapshots (and their prefixes) older than a cutoff.
7. **Diff engine** — `diff_snapshots()` compares two snapshots using composite key `(network, next_hop)` to correctly handle multi-path BGP (ECMP). Detects added/removed prefixes and attribute changes (as_path, local_pref, metric, weight, origin). A next-hop change appears as one removed + one added prefix.
8. **Pydantic models** — Typed request/response models for every API endpoint (`SnapshotResponse`, `PrefixInfo`, `DiffResponse`, `SnapshotListItem`, `SnapshotDetailResponse`, etc.) so the OpenAPI schema stays a real contract.
9. **FastAPI API** — Lifespan-based startup (`init_db()`, warns if no API key or no routers configured), API key auth via `hmac.compare_digest` (timing-safe), per-endpoint rate limiting (slowapi, keyed off the raw socket IP — not `X-Forwarded-For` — via `_get_client_ip`), CORS middleware (validated origins; wildcard rejected when an API key is set), access logging middleware, security response headers middleware (`X-Content-Type-Options`, `X-Frame-Options`, CSP, etc.), and a sanitized global exception handler (logs exception type at ERROR, full traceback only at DEBUG). `/docs`/`/redoc` are disabled unless `BGP_ENABLE_DOCS` is set. Endpoints: `GET /health`, `POST /snapshots` (guarded by `_snapshot_lock`, 429 if one is already running), `GET /snapshots`, `GET /snapshots/{id}`, `GET /diff`.
10. **CLI** — argparse-based `_cli()` with mutually exclusive modes: `--snapshot`, `--diff`, `--list`, `--serve`, `--purge DAYS`. Installs signal handlers, canonicalizes `--db`/`--router-config` paths, validates `--port` range, and warns when TLS isn't configured alongside an API key or when binding non-loopback without one.

## Security Conventions

This codebase has been through dedicated security and operational hardening passes (see `tasks/security-review.md` and `tasks/operational-review.md` for the original findings — useful background if you're touching auth, networking, or DB code, though the file has since evolved past what those docs describe). When modifying this code, preserve these invariants:

- SSH host key verification (`ssh_strict`) defaults to `True`; don't silently relax it.
- API key comparisons must use `hmac.compare_digest`, never `==`/`!=`.
- Router config fields are allowlisted (`ALLOWED_ROUTER_FIELDS`) and `device_type` is validated against `SUPPORTED_DEVICE_TYPES` — extend these sets rather than bypassing validation.
- All SQL is parameterized — never interpolate user input into a query string.
- The rate limiter keys off the real socket IP (`_get_client_ip`), not proxy headers, unless a trusted-proxy config is added deliberately.
- Exception responses stay generic (`"Internal server error"`); detailed errors go to logs only, and only at DEBUG.
- New DB files/config files should end up `0600`, not world-readable.

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

Tests are in `tests/` with five modules, plus a shared `conftest.py` (`test_db` fixture — an isolated, initialized SQLite file under `tmp_path`):
- `test_parsing.py` — TextFSM parser against sample Cisco IOS BGP output
- `test_diff.py` — Diff engine including multi-path and next-hop change scenarios
- `test_db.py` — Database CRUD, ordering, filtering, composite key loading
- `test_config.py` — `_load_routers()` schema validation (required/unknown fields, device_type allowlist, malformed JSON, permissions) and `_validate_cors_origins()`
- `test_api.py` — FastAPI endpoints via TestClient: auth, rate-limit-adjacent behavior, security headers, snapshot locking, input validation (path/query param bounds), response shapes, docs-disabled-by-default

All DB-dependent tests use the `tmp_path` fixture for isolated SQLite files. API tests monkeypatch `bgp_route_analyzer.DB_PATH` and `bgp_route_analyzer.API_KEY` (and sometimes `ROUTERS`) directly rather than using env vars, since those globals are read once at import time.

## Vendor Customization

To support non-Cisco devices, two things need changing:
1. The command string in `poll_router()` (e.g., `show bgp ipv4 unicast` for IOS-XR)
2. The `TEXTFSM_TEMPLATE` constant to match the vendor's output format

`SUPPORTED_DEVICE_TYPES` also needs the new Netmiko `device_type` value added, or `_load_routers()` will reject the config.

## Database Schema

- `snapshots`: id, router (name), captured_at (ISO timestamp), raw_output (full CLI output, truncated at 10MB)
- `prefixes`: id, snapshot_id (FK, `PRAGMA foreign_keys=ON` enforced), network, next_hop, metric, local_pref, weight, as_path, origin

Both tables are created via `CREATE TABLE IF NOT EXISTS`; there is no migration framework — schema changes require a manual `ALTER TABLE` path or a fresh DB.
