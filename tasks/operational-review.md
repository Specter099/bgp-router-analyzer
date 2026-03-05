# Operational Review: BGP Route Analyzer

**Date:** 2026-03-05
**Scope:** Runtime error handling, edge cases, concurrency, data integrity, API robustness, CLI reliability
**File reviewed:** `bgp_route_analyzer.py` (post-security-hardening, ~809 lines)

---

## Executive Summary

The codebase has strong security hardening (timing-safe API key comparison, input validation, security headers, config allowlisting). However, **25 operational findings** were identified that could cause crashes, data corruption, misleading results, or poor operator experience in production. The most critical issues involve module-level crash paths, missing rollback semantics, and a CLI `--db` flag that silently doesn't work with `--serve`.

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 7     |
| MEDIUM   | 12    |
| LOW      | 3     |

---

## CRITICAL Findings

### O-C1. Module-Level `_load_routers()` Crash on Malformed JSON Prevents Import
**Location:** `bgp_route_analyzer.py:165` (calls `_load_routers()` -> line 126 `json.load()`)

`_load_routers()` is called at module level. If `routers.json` exists but contains invalid JSON (e.g., trailing comma), `json.JSONDecodeError` propagates unhandled, making the entire module unimportable. The API server, CLI, and test suite all fail.

**Impact:** A single typo in `routers.json` makes the entire application unlaunchable with a raw traceback.

**Fix:** Catch `json.JSONDecodeError` inside `_load_routers()`:
```python
try:
    with open(resolved) as f:
        raw = json.load(f)
except json.JSONDecodeError as e:
    log.error("Invalid JSON in router config %s: %s", resolved, e)
    return []
```

---

### O-C2. `get_db` Context Manager Has No Explicit Rollback on Exception
**Location:** `bgp_route_analyzer.py:227-240`

When an exception occurs inside `with get_db() as conn:`, `conn.commit()` is skipped but there is no `conn.rollback()`. This relies on SQLite's implicit rollback on `conn.close()`, which is an implementation detail. In `save_snapshot`, if `executemany` for prefixes fails after the snapshot INSERT succeeded, the implicit rollback *should* undo both, but this is fragile across Python/SQLite versions.

**Impact:** Under edge conditions (disk full, malformed prefix data), a snapshot row could persist without its associated prefixes, causing misleading zero-prefix snapshots in diffs.

**Fix:**
```python
try:
    yield conn
    conn.commit()
except BaseException:
    conn.rollback()
    raise
finally:
    conn.close()
```

---

### O-C3. `--db` Flag Not Propagated to Global `DB_PATH` for `--serve`
**Location:** `bgp_route_analyzer.py:740-744` and `:796`

When running `--serve --db /custom/path.db`, the CLI resolves and initializes the custom DB path as a local variable `db`, but never updates the module-level `DB_PATH`. All API endpoint functions (`list_snapshots()`, `_snapshot_info()`, `diff_snapshots()`) use the module-level `DB_PATH` default. The lifespan `init_db()` also uses the default `DB_PATH`.

**Impact:** `python bgp_route_analyzer.py --serve --db /data/bgp.db` silently serves data from `./bgp_snapshots.db` instead of the specified path. Operators would see no snapshots or stale data.

**Fix:** Update the global in `_cli()`:
```python
global DB_PATH
DB_PATH = Path(args.db).resolve()
```

---

## HIGH Findings

### O-H1. Signal Handler Calls Logging (Deadlock Risk)
**Location:** `bgp_route_analyzer.py:101-105`

`log.info()` inside `_signal_handler` acquires the logging module's internal lock. If a signal arrives while another thread holds that lock (e.g., during `log.info` in `poll_router`), the process deadlocks permanently.

**Impact:** Application hangs on SIGINT/SIGTERM instead of shutting down.

**Fix:** Remove the `log.info()` from the signal handler. Only set the flag.

---

### O-H2. `save_snapshot` Uses `assert` for Runtime Condition
**Location:** `bgp_route_analyzer.py:321`

`assert snap_id is not None` is stripped when Python runs with `-O`. Under optimization, a `None` `snap_id` would be used as a foreign key, inserting orphaned prefix rows with `snapshot_id = None`.

**Fix:** Replace with `if snap_id is None: raise RuntimeError(...)`.

---

### O-H3. `take_snapshots` Exception Handler Is Too Narrow
**Location:** `bgp_route_analyzer.py:352`

Only catches `(RuntimeError, sqlite3.Error)`. Missing: `KeyError` (from missing config keys), `OSError` (network failures), `textfsm.TextFSMError`, `ValueError`. Any uncaught exception aborts the entire router loop — all remaining routers are skipped.

**Fix:** Use `except Exception as exc:` to ensure one failing router doesn't abort the entire snapshot cycle.

---

### O-H4. `poll_router` Requires `username` but Config Validation Doesn't
**Location:** `bgp_route_analyzer.py:259` (access) vs `:140` (validation)

`_load_routers` requires `host`, `device_type`, `name` — but not `username`. `poll_router` does `router_cfg["username"]` which raises `KeyError`, not caught by the `except (RuntimeError, sqlite3.Error)` in `take_snapshots`.

**Fix:** Add `"username"` to the required fields in `_load_routers`:
```python
for field in ("host", "device_type", "name", "username"):
```

---

### O-H5. `--purge 0` and `--purge -1` Delete All Data Without Validation
**Location:** `bgp_route_analyzer.py:720-721, 770-772`

No bounds check on the `--purge` argument. `--purge 0` deletes all snapshots. `--purge -1` creates a future cutoff, also deleting everything. No confirmation prompt.

**Fix:** Validate `args.purge >= 1` before executing.

---

### O-H6. `save_snapshot` Missing Keys in Prefix Dicts Causes Unhandled Error
**Location:** `bgp_route_analyzer.py:322-327`

The `executemany` SQL uses named parameters (`:network`, `:next_hop`, etc.). If a prefix dict is missing a key, `sqlite3.ProgrammingError` is raised. Combined with O-C2 (no explicit rollback), this could leave orphaned data.

**Fix:** Normalize prefix dicts before insertion:
```python
row = {field: p.get(field, "") for field in REQUIRED_FIELDS}
```

---

### O-H7. TOCTOU Race in `api_get_snapshot` and `api_diff`
**Location:** `bgp_route_analyzer.py:682-688` and `:702-705`

`_snapshot_info()` and `_load_prefix_map()` each open separate DB connections. A concurrent `purge_old_snapshots` between the two calls could delete the snapshot, causing the response to return metadata but zero prefixes with no error.

**Fix:** Combine both queries into a single `get_db()` connection scope.

---

## MEDIUM Findings

### O-M1. Negative/Zero Snapshot IDs Not Validated on API
**Location:** `bgp_route_analyzer.py:682, 695-696`

`GET /snapshots/{snapshot_id}` and `GET /diff` accept negative/zero IDs. These will never exist but still hit the database.

**Fix:** Add `ge=1` constraint: `snapshot_id: int = PathParam(..., ge=1)`.

---

### O-M2. `api_get_snapshot` and `api_list_snapshots` Missing `response_model`
**Location:** `bgp_route_analyzer.py:669-677, 680-688`

These endpoints return raw `dict`/`list[dict]` with no Pydantic model. API consumers have no schema contract. Changes to the DB query silently alter the response shape.

**Fix:** Create Pydantic response models for both endpoints.

---

### O-M3. Diff Endpoint Allows `before == after`
**Location:** `bgp_route_analyzer.py:691-705`

Diffing a snapshot against itself always returns zero changes. Almost always a user mistake.

**Fix:** Return 400 when `before == after`.

---

### O-M4. CLI `--diff --before 0` Treated as Falsy, Misleading Error
**Location:** `bgp_route_analyzer.py:760`

`if not args.before` is `True` when `args.before == 0`. Should check `is None` instead. Also, negative IDs pass the check but produce empty diffs silently.

**Fix:** `if args.before is None or args.before < 1 or args.after is None or args.after < 1:`

---

### O-M5. TextFSM Silently Returns Empty List on Unexpected Output
**Location:** `bgp_route_analyzer.py:291-297`

If a router returns an HTML error page, login banner, or "command not found", `_parse_bgp_table` returns `[]`. This is saved as a valid snapshot with zero prefixes. In a diff, it looks like all prefixes were withdrawn.

**Fix:** Log a warning in `poll_router` when output is non-empty but zero prefixes are parsed.

---

### O-M6. `_shutdown_requested` Global Bool Is Not Thread-Safe
**Location:** `bgp_route_analyzer.py:98-105, 345`

The signal handler writes `_shutdown_requested` in the main thread; `take_snapshots` reads it in a threadpool worker. No memory barrier guarantees visibility. Works on CPython due to GIL but would break on free-threaded Python (3.13+).

**Fix:** Use `threading.Event` instead of a bare bool.

---

### O-M7. `poll_router` SSH Disconnect Exception Swallows Original Error
**Location:** `bgp_route_analyzer.py:273-276`

If `send_command` raises and then `disconnect()` also raises in the `finally`, the original exception is lost. Makes debugging harder.

**Fix:** Wrap `disconnect()` in `try/except` and log at DEBUG level.

---

### O-M8. `_get_client_ip` Falls Back to `"127.0.0.1"`, Defeating Rate Limiting
**Location:** `bgp_route_analyzer.py:533-534`

When `request.client` is `None` (certain proxy configs), all requests share one rate limit bucket at `127.0.0.1`.

---

### O-M9. SQLite Foreign Keys Not Enforced
**Location:** `bgp_route_analyzer.py:208` (schema) and `get_db` (missing pragma)

`REFERENCES snapshots(id)` is declared but `PRAGMA foreign_keys=ON` is never set. The FK constraint is purely decorative.

**Fix:** Add `conn.execute("PRAGMA foreign_keys=ON")` in `get_db()`.

---

### O-M10. `--port` Not Validated
**Location:** `bgp_route_analyzer.py:729`

Port 0 binds to random port. Ports >65535 cause cryptic `OSError` from uvicorn.

**Fix:** Validate `1 <= args.port <= 65535`.

---

### O-M11. Rate Limiter State Is Ephemeral
**Location:** `bgp_route_analyzer.py:538`

`slowapi` uses in-memory storage. State is lost on restart (including the `limit_max_requests=10000` worker recycling). Multiple workers would have independent rate limit state.

**Fix:** Document the limitation. For hardening, use Redis-backed storage.

---

### O-M12. `_load_prefix_map` Silently Collapses Duplicate Composite Keys
**Location:** `bgp_route_analyzer.py:401`

Dict comprehension keeps only the last entry for duplicate `(network, next_hop)` pairs. No warning is logged. Prefix counts in API responses would be lower than actual stored counts.

**Fix:** Log a warning when duplicates are found.

---

## LOW Findings

### O-L1. Module-Level Import Side Effects
**Location:** `bgp_route_analyzer.py:62-65, 165`

`logging.basicConfig()` and `_load_routers()` run at import time, causing file I/O and logging configuration as side effects of `import bgp_route_analyzer`. Can interfere with test frameworks and library consumers.

---

### O-L2. API_KEY Immutable After Module Load
**Location:** `bgp_route_analyzer.py:72`

API key is read once at import. Rotating the key requires a server restart. Not documented.

---

### O-L3. Cross-Router Diff Not Flagged
**Location:** `bgp_route_analyzer.py:404-448`

Diffing snapshots from different routers produces large add/remove results that could be misinterpreted as a routing incident. No warning is emitted.

---

## Prioritized Remediation Plan

| # | ID | Issue | Effort | Risk |
|---|----|-------|--------|------|
| 1 | O-C3 | `--db` not propagated to `DB_PATH` for `--serve` | Small | Silent data mismatch |
| 2 | O-C2 | No explicit rollback in `get_db` | Small | Data corruption |
| 3 | O-C1 | Malformed JSON crashes import | Small | Total app failure |
| 4 | O-H1 | Signal handler deadlock risk | Small | Hang on shutdown |
| 5 | O-H3 | Exception handler too narrow | Small | Skipped routers |
| 6 | O-H4 | `username` not required in config | Small | KeyError crash |
| 7 | O-H5 | `--purge 0` deletes everything | Small | Data loss |
| 8 | O-H2 | `assert` stripped under `-O` | Small | Silent corruption |
| 9 | O-H6 | Missing prefix keys cause error | Small | Partial snapshots |
| 10 | O-H7 | TOCTOU race in API reads | Medium | Inconsistent responses |
| 11 | O-M1 | Negative snapshot IDs | Small | Unnecessary DB load |
| 12 | O-M4 | CLI diff validation | Small | Misleading results |
| 13 | O-M5 | Empty parse not warned | Small | False alarms |
| 14 | O-M3 | `before == after` allowed | Small | Operator confusion |
| 15 | O-M6 | Non-thread-safe shutdown flag | Small | Future compatibility |
| 16 | O-M7 | Disconnect swallows exception | Small | Hard to debug |
| 17 | O-M9 | FK not enforced | Small | Schema integrity |
| 18 | O-M10 | Port not validated | Small | Confusing errors |
| 19 | O-M2 | Missing response_models | Medium | No API contract |
| 20 | O-M12 | Duplicate keys collapsed | Small | Wrong counts |
