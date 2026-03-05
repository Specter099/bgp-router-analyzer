# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGP Route Analyzer — a single-file Python tool that SSH-polls edge routers (via Netmiko), parses BGP tables (via TextFSM), stores time-series snapshots in SQLite, and diffs pre/post change windows. Exposes both a CLI and a FastAPI REST API.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `routers.json.example` to `routers.json` and fill in router credentials.

## Common Commands

```bash
# CLI operations
python bgp_route_analyzer.py --snapshot              # Poll all routers, save snapshots
python bgp_route_analyzer.py --list                  # List stored snapshots
python bgp_route_analyzer.py --list --router NAME    # Filter by router
python bgp_route_analyzer.py --diff --before ID --after ID  # Diff two snapshots

# API server (binds to 127.0.0.1:8000 by default)
python bgp_route_analyzer.py --serve
python bgp_route_analyzer.py --serve --host HOST --port PORT
python bgp_route_analyzer.py --serve --ssl-cert cert.pem --ssl-key key.pem

# Override database path or router config
python bgp_route_analyzer.py --snapshot --db /path/to/db
python bgp_route_analyzer.py --serve --router-config /path/to/routers.json

# Linting and testing
.venv/bin/flake8 bgp_route_analyzer.py --max-line-length 120
.venv/bin/mypy bgp_route_analyzer.py --ignore-missing-imports
.venv/bin/python -m pytest tests/ -v
.venv/bin/python -m pytest tests/test_parsing.py::test_parse_returns_correct_count  # single test
```

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `BGP_ROUTER_CONFIG` | Path to router credentials JSON | `routers.json` |
| `BGP_DB_PATH` | SQLite database file path | `bgp_snapshots.db` |
| `BGP_ANALYZER_API_KEY` | API key for `X-API-Key` header auth | unset (auth disabled) |
| `BGP_CORS_ORIGINS` | Comma-separated allowed CORS origins | unset (CORS disabled) |

## Architecture

Everything lives in `bgp_route_analyzer.py`. The file is organized into clearly separated sections:

1. **Config** — Environment-driven configuration. Router credentials loaded from external `routers.json` (never committed). `_load_routers()` reads the JSON file.
2. **Database** — SQLite schema with two tables: `snapshots` (metadata + raw output) and `prefixes` (parsed BGP attributes per snapshot). `init_db()` creates tables; `get_db()` is a context manager. All DB functions accept an optional `db_path` parameter (defaults to global `DB_PATH` at call time) for testability.
3. **Polling** — `poll_router()` connects via Netmiko with configurable `ssh_strict`, runs `show ip bgp`, parses with TextFSM. `_parse_bgp_table()` handles the TextFSM template execution.
4. **Snapshot storage** — `save_snapshot()`, `take_snapshots()`, `list_snapshots()`, `_snapshot_info()`, `_load_prefix_map()`.
5. **Diff engine** — `diff_snapshots()` compares two snapshots using composite key `(network, next_hop)` to correctly handle multi-path BGP (ECMP). Detects added/removed prefixes and attribute changes (as_path, local_pref, metric, weight, origin). A next-hop change appears as one removed + one added prefix.
6. **FastAPI API** — REST endpoints with lifespan-based startup, API key auth (optional), rate limiting (slowapi), CORS middleware, access logging, and global exception handler. Endpoints: `/health`, `POST /snapshots`, `GET /snapshots`, `GET /snapshots/{id}`, `GET /diff`.
7. **CLI** — argparse-based `_cli()` with mutually exclusive modes: `--snapshot`, `--diff`, `--list`, `--serve`.

## Key Dependencies

- **netmiko** — SSH connections to network devices (Cisco IOS, IOS-XR, Arista, Junos, etc.)
- **textfsm** — Structured parsing of CLI output via templates
- **fastapi + uvicorn** — REST API server
- **slowapi** — Rate limiting middleware
- **pydantic** — Response models and validation
- **httpx + pytest** — Testing (TestClient requires httpx)
- **sqlite3** — Built-in, no external DB required

## Testing

Tests are in `tests/` with four modules:
- `test_parsing.py` — TextFSM parser against sample Cisco IOS BGP output
- `test_diff.py` — Diff engine including multi-path and next-hop change scenarios
- `test_db.py` — Database CRUD, ordering, filtering, composite key loading
- `test_api.py` — FastAPI endpoints via TestClient, including auth and validation

All DB-dependent tests use `tmp_path` fixture for isolated SQLite files. API tests monkeypatch `DB_PATH` and `API_KEY`.

## Vendor Customization

To support non-Cisco devices, two things need changing:
1. The command string in `poll_router()` (e.g., `show bgp ipv4 unicast` for IOS-XR)
2. The `TEXTFSM_TEMPLATE` constant to match the vendor's output format

## Database Schema

- `snapshots`: id, router (name), captured_at (ISO timestamp), raw_output (full CLI output)
- `prefixes`: id, snapshot_id (FK), network, next_hop, metric, local_pref, weight, as_path, origin
