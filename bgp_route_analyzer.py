#!/usr/bin/env python3
"""
BGP Route Analysis Tool
-----------------------
Polls edge routers via SSH using Netmiko, parses BGP tables with TextFSM,
stores snapshots in a time-series SQLite database, and compares prefix
advertisements before/after a change window.

Exposes a REST API via FastAPI so the NOC team can trigger checks from
their incident dashboard, plus a React admin UI served from /ui.

Configuration:
    Router credentials:  routers.json  (see routers.json.example)
    Environment vars:
        BGP_ROUTER_CONFIG       - path to router config JSON  (default: routers.json)
        BGP_DB_PATH             - SQLite database path         (default: bgp_snapshots.db)
        BGP_ANALYZER_API_KEY    - API key / admin password     (optional, disables auth if unset)
        BGP_CORS_ORIGINS        - comma-separated CORS origins (optional)
        BGP_ROUTER_PASSWORD     - default router password      (optional, env-based override)
        BGP_ENABLE_DOCS         - enable OpenAPI docs          (optional, default: disabled)
        BGP_SESSION_TTL         - session lifetime, seconds    (default: 28800)
        BGP_SESSION_IDLE        - session idle timeout, secs   (default: 1800)
        BGP_POLL_WORKERS        - concurrent router polls      (default: 5)
        BGP_JOB_HISTORY         - jobs retained in memory      (default: 50)
        BGP_LIMIT_CONCURRENCY   - uvicorn concurrency limit    (default: 100)
        BGP_LIMIT_MAX_REQUESTS  - uvicorn request limit        (default: unset/unlimited)

Usage:
    python bgp_route_analyzer.py --snapshot
    python bgp_route_analyzer.py --diff --before <id> --after <id>
    python bgp_route_analyzer.py --serve
    python bgp_route_analyzer.py --list | --routers | --audit
    python bgp_route_analyzer.py --purge 30
    python bgp_route_analyzer.py --purge-audit 365
"""

import argparse
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import signal
import sqlite3
import stat
import sys
import textwrap
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncGenerator, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import textfsm
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, Security
from fastapi import Path as PathParam
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
log = logging.getLogger("bgp_analyzer")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH = Path(os.environ.get("BGP_DB_PATH", "bgp_snapshots.db"))
API_KEY = os.environ.get("BGP_ANALYZER_API_KEY")
CORS_ORIGINS = [o.strip() for o in os.environ.get("BGP_CORS_ORIGINS", "").split(",") if o.strip()]

# [C3] Allowlisted fields for router config — reject unknown fields
ALLOWED_ROUTER_FIELDS = frozenset({
    "host", "device_type", "username", "password", "key_file",
    "name", "port", "ssh_strict",
})

# [M5] Supported Netmiko device types
SUPPORTED_DEVICE_TYPES = frozenset({
    "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_s300",
    "arista_eos", "juniper_junos", "juniper_junos_telnet",
    "linux", "linux_ssh", "hp_comware", "hp_procurve",
    "huawei", "dell_force10", "brocade_fastiron",
    "mikrotik_routeros", "paloalto_panos", "fortinet",
    "alcatel_aos", "checkpoint_gaia", "ubiquiti_edgerouter",
})

# [L5] Maximum size for raw router output (10 MB)
MAX_RAW_OUTPUT_SIZE = 10 * 1024 * 1024

# [H2] Lock to prevent concurrent snapshot operations
_snapshot_lock = threading.Lock()

# [L6][O-M6] Graceful shutdown — use threading.Event for thread safety
_shutdown_event = threading.Event()


def _env_int(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    """Read a bounded integer from the environment, falling back on bad input."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        log.warning("%s=%r is not an integer; using default %d", name, raw, default)
        return default
    if value < minimum or (maximum is not None and value > maximum):
        log.warning("%s=%d out of range [%s, %s]; using default %d", name, value, minimum, maximum, default)
        return default
    return value


# ---------------------------------------------------------------------------
# Session authentication
#
# The X-API-Key header is fine for scripts but a poor fit for a browser UI:
# the key ends up readable by JavaScript and therefore exposed to XSS. The
# session layer exchanges the API key once for an HttpOnly cookie that JS
# cannot read. Sessions live in process memory only — they are intentionally
# not persisted, so a restart logs everyone out.
# ---------------------------------------------------------------------------
SESSION_COOKIE_NAME = "bgp_session"  # HttpOnly — never readable by JS
CSRF_COOKIE_NAME = "bgp_csrf"        # readable by JS by design (double-submit)
CSRF_HEADER_NAME = "X-CSRF-Token"

# Absolute session lifetime and idle timeout, both in seconds.
SESSION_TTL_SECONDS = _env_int("BGP_SESSION_TTL", 8 * 3600, minimum=60)
SESSION_IDLE_SECONDS = _env_int("BGP_SESSION_IDLE", 30 * 60, minimum=60)
MAX_SESSIONS = 500

# Controls the `Secure` cookie flag and HSTS. A Secure cookie is never sent
# over plain HTTP, so this cannot simply default to True or loopback HTTP
# development breaks silently.
#
# Set by the CLI when --ssl-cert/--ssl-key are given, or up front by
# BGP_ASSUME_TLS for the common production topology where TLS terminates at a
# reverse proxy and this process only ever sees HTTP. Without that escape
# hatch, a proxied deployment could never issue a Secure session cookie.
_tls_enabled = os.environ.get("BGP_ASSUME_TLS", "").lower() in ("1", "true", "yes")

# token_hash -> session dict. Raw tokens are never stored, only their SHA-256
# digest, so a memory dump or log leak does not yield usable credentials.
_sessions: dict[str, dict] = {}
_session_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Snapshot jobs
# ---------------------------------------------------------------------------
# Bounded thread pool for polling routers concurrently. Kept small by default:
# routers commonly rate-limit or lock out on many simultaneous SSH sessions.
MAX_POLL_WORKERS = _env_int("BGP_POLL_WORKERS", 5, minimum=1, maximum=50)

# Number of finished jobs retained in memory for status polling.
MAX_JOB_HISTORY = _env_int("BGP_JOB_HISTORY", 50, minimum=1, maximum=1000)

_jobs: OrderedDict[str, dict] = OrderedDict()
_jobs_lock = threading.Lock()


def _signal_handler(signum: int, frame: object) -> None:
    """Set shutdown flag for graceful termination.

    Note: logging is intentionally avoided here because it acquires locks
    and is not async-signal-safe (could deadlock if signal arrives during
    another log call). [O-H1]
    """
    _shutdown_event.set()


def _load_routers(config_path: str | None = None) -> list[dict]:
    """Load and validate router configuration from an external JSON file."""
    path = config_path or os.environ.get("BGP_ROUTER_CONFIG", "routers.json")
    resolved = Path(path).resolve()  # [M4] canonicalize path

    # [O-C1] Every filesystem touch below is inside this guard on purpose.
    # _load_routers() runs at module import, so any OSError escaping here kills
    # the process before argparse runs — under a container restart policy that
    # is a crash loop. It is not only open() that can fail: exists() and stat()
    # raise PermissionError when a parent directory denies traversal, which is
    # exactly what bind-mounting a config into a non-root container produces.
    try:
        if not resolved.exists():
            return []

        # [C4] Check file permissions (Unix only)
        if sys.platform != "win32":
            mode = resolved.stat().st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                log.warning(
                    "Router config %s has overly permissive permissions (%o). "
                    "Recommend chmod 600.",
                    resolved, stat.S_IMODE(mode),
                )

        with open(resolved) as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON in router config %s: %s", resolved, e)
        return []
    except OSError as e:
        log.error(
            "Cannot read router config %s: %s. Continuing with no routers configured — "
            "check that the file is readable by the user running this process (uid=%s).",
            resolved, e, getattr(os, "getuid", lambda: "n/a")(),
        )
        return []

    if not isinstance(raw, list):
        raise ValueError(f"Router config must be a JSON array, got {type(raw).__name__}")

    # [C4] Support env var password override
    password_override = os.environ.get("BGP_ROUTER_PASSWORD")

    validated = []
    for i, router in enumerate(raw):
        if not isinstance(router, dict):
            raise ValueError(f"Router config [{i}] must be a JSON object")

        # [C3][O-H4] Validate required fields (username needed for SSH)
        for field in ("host", "device_type", "name", "username"):
            if field not in router:
                raise ValueError(f"Router config [{i}] missing required field: {field}")

        # [C3] Reject unknown fields
        unknown = set(router.keys()) - ALLOWED_ROUTER_FIELDS
        if unknown:
            raise ValueError(f"Router config [{i}] has unknown fields: {unknown}")

        # [M5] Validate device_type
        if router["device_type"] not in SUPPORTED_DEVICE_TYPES:
            raise ValueError(
                f"Router config [{i}] unsupported device_type: {router['device_type']}. "
                f"Supported: {sorted(SUPPORTED_DEVICE_TYPES)}"
            )

        # [C4] Apply env var password override
        if password_override and "password" not in router:
            router = {**router, "password": password_override}

        validated.append(router)

    return validated


ROUTERS: list[dict] = _load_routers()

# TextFSM template for "show ip bgp" (Cisco IOS style).
# Expand or swap out per-vendor as needed.
TEXTFSM_TEMPLATE = textwrap.dedent("""\
    Value NETWORK (\\S+)
    Value NEXT_HOP (\\S+)
    Value METRIC (\\d*)
    Value LOCAL_PREF (\\d*)
    Value WEIGHT (\\d+)
    Value AS_PATH (.*)
    Value STATUS ([sdh>irSR*]*)
    Value ORIGIN ([ie?])

    Start
      ^\\s+${NETWORK}\\s+${NEXT_HOP}\\s+${METRIC}\\s+${LOCAL_PREF}\\s+${WEIGHT}\\s+${AS_PATH}\\s+${ORIGIN} -> Record
      ^\\*>\\s*${NETWORK}\\s+${NEXT_HOP}\\s+${METRIC}\\s+${LOCAL_PREF}\\s+${WEIGHT}\\s+${AS_PATH}\\s+${ORIGIN} -> Record
      ^. -> Continue

    EOF
""")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def init_db(db_path: Path | None = None) -> None:
    """Create tables if they don't exist."""
    if db_path is None:
        db_path = DB_PATH
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                router      TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                raw_output  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS prefixes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
                network     TEXT NOT NULL,
                next_hop    TEXT,
                metric      TEXT,
                local_pref  TEXT,
                weight      TEXT,
                as_path     TEXT,
                origin      TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                actor       TEXT NOT NULL,
                action      TEXT NOT NULL,
                outcome     TEXT NOT NULL,
                target      TEXT,
                source_ip   TEXT,
                detail      TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_prefixes_snapshot ON prefixes(snapshot_id)")
        # Supports the paginated snapshot list, which orders by captured_at and
        # optionally filters by router.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snapshots_router_captured "
            "ON snapshots(router, captured_at DESC)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_captured ON snapshots(captured_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, timestamp DESC)")
        conn.commit()
    # [H4] Set restrictive file permissions on the database
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        log.warning("Could not set database file permissions to 0600: %s", db_path)


@contextmanager
def get_db(db_path: Path | None = None) -> Generator[sqlite3.Connection, None, None]:
    if db_path is None:
        db_path = DB_PATH
    # [M2] Set busy timeout and enable WAL mode for concurrent access
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")  # [O-M9] Enforce FK constraints
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()  # [O-C2] Explicit rollback on exception
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def record_audit(
    action: str,
    actor: str = "system",
    outcome: str = "success",
    target: str | None = None,
    source_ip: str | None = None,
    detail: str | None = None,
    db_path: Path | None = None,
) -> None:
    """Append an entry to the audit log.

    Auditing is best-effort: a failure to write the audit row must never break
    or roll back the operation being audited, so all errors are swallowed and
    logged rather than raised.
    """
    if db_path is None:
        db_path = DB_PATH
    try:
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, actor, action, outcome, target, source_ip, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    actor,
                    action,
                    outcome,
                    target,
                    source_ip,
                    detail,
                ),
            )
    except Exception:
        log.warning("Failed to write audit log entry for action=%s", action, exc_info=True)


def list_audit_log(
    action: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db_path: Path | None = None,
) -> tuple[list[dict], int]:
    """Return (rows, total) of audit entries, newest first."""
    if db_path is None:
        db_path = DB_PATH
    where = ""
    params: list = []
    if action:
        where = " WHERE action = ?"
        params.append(action)
    with get_db(db_path) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()[0]
        rows = conn.execute(
            "SELECT id, timestamp, actor, action, outcome, target, source_ip, detail "
            f"FROM audit_log{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return [dict(r) for r in rows], total


def purge_old_audit(days: int, db_path: Path | None = None) -> int:
    """Delete audit entries older than N days. Returns count deleted.

    Kept separate from snapshot retention on purpose: audit records usually
    need to outlive the operational data they describe.
    """
    if db_path is None:
        db_path = DB_PATH
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with get_db(db_path) as conn:
        cur = conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
        count = cur.rowcount
    log.info("Purged %d audit entry(s) older than %d days", count, days)
    return count


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _prune_sessions_locked(now: float) -> None:
    """Drop expired sessions. Caller must hold _session_lock."""
    expired = [
        h for h, s in _sessions.items()
        if now - s["created_at"] > SESSION_TTL_SECONDS or now - s["last_seen"] > SESSION_IDLE_SECONDS
    ]
    for h in expired:
        del _sessions[h]


def create_session(actor: str, source_ip: str | None) -> tuple[str, str]:
    """Create a session, returning (session_token, csrf_token)."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _session_lock:
        _prune_sessions_locked(now)
        # Bound total sessions so a login flood cannot exhaust memory. Evicting
        # the oldest is safe: it just forces that admin to log in again.
        while len(_sessions) >= MAX_SESSIONS:
            _sessions.pop(next(iter(_sessions)))
        _sessions[_hash_token(token)] = {
            "actor": actor,
            "csrf": csrf,
            "created_at": now,
            "last_seen": now,
            "source_ip": source_ip,
        }
    return token, csrf


def get_session(token: str | None) -> dict | None:
    """Validate a session token and refresh its idle timer."""
    if not token:
        return None
    now = time.monotonic()
    with _session_lock:
        _prune_sessions_locked(now)
        session = _sessions.get(_hash_token(token))
        if session is None:
            return None
        session["last_seen"] = now
        return dict(session)


def destroy_session(token: str | None) -> bool:
    if not token:
        return False
    with _session_lock:
        return _sessions.pop(_hash_token(token), None) is not None


# ---------------------------------------------------------------------------
# Device polling
# ---------------------------------------------------------------------------


def poll_router(router_cfg: dict) -> tuple[str, list[dict]]:
    """
    SSH into a router, run 'show ip bgp', parse with TextFSM.
    Returns (raw_output, list_of_prefix_dicts).
    """
    # [M3] Log router name at INFO, IP only at DEBUG
    log.info("Connecting to %s", router_cfg["name"])
    log.debug("Router %s address: %s", router_cfg["name"], router_cfg["host"])
    try:
        connection = ConnectHandler(
            host=router_cfg["host"],
            username=router_cfg["username"],
            password=router_cfg.get("password", ""),
            device_type=router_cfg["device_type"],
            key_file=router_cfg.get("key_file"),
            ssh_strict=router_cfg.get("ssh_strict", True),  # [C1] Default True
            timeout=30,
        )
    except NetmikoAuthenticationException:
        log.error("Auth failed for %s", router_cfg["name"])
        raise RuntimeError(f"Authentication failed for {router_cfg['name']}") from None
    except NetmikoTimeoutException:
        log.error("Timeout connecting to %s", router_cfg["name"])
        raise RuntimeError(f"Timeout connecting to {router_cfg['name']}") from None

    try:
        # Netmiko types send_command as str | list | dict because it can be
        # asked to return structured data; with no parser requested it is
        # always str, but coerce so the rest of the function is honestly typed.
        raw = str(connection.send_command("show ip bgp", read_timeout=60))
    finally:
        try:
            connection.disconnect()
        except Exception:
            log.debug("Error during disconnect from %s", router_cfg["name"], exc_info=True)  # [O-M7]

    # [L5] Truncate oversized output
    if len(raw) > MAX_RAW_OUTPUT_SIZE:
        log.warning(
            "Raw output from %s exceeds %d bytes, truncating",
            router_cfg["name"], MAX_RAW_OUTPUT_SIZE,
        )
        raw = raw[:MAX_RAW_OUTPUT_SIZE]

    prefixes = _parse_bgp_table(raw)
    # [O-M5] Warn when output is non-empty but no prefixes parsed
    if not prefixes and raw.strip():
        log.warning(
            "Router %s returned output but 0 prefixes parsed — output may not be "
            "a valid BGP table. First 200 chars: %.200s",
            router_cfg["name"], raw.strip(),
        )
    log.info("  -> %d prefixes parsed from %s", len(prefixes), router_cfg["name"])
    return raw, prefixes


def _parse_bgp_table(raw_output: str) -> list[dict]:
    """Parse raw 'show ip bgp' output using TextFSM."""
    template_fh = io.StringIO(TEXTFSM_TEMPLATE)
    fsm = textfsm.TextFSM(template_fh)
    rows = fsm.ParseText(raw_output)
    headers = [h.lower() for h in fsm.header]
    return [dict(zip(headers, row, strict=False)) for row in rows if any(row)]


# ---------------------------------------------------------------------------
# Snapshot storage
# ---------------------------------------------------------------------------


def save_snapshot(
    router_name: str,
    raw_output: str,
    prefixes: list[dict],
    db_path: Path | None = None,
) -> int:
    """Persist a snapshot and its prefixes; return the snapshot id."""
    if db_path is None:
        db_path = DB_PATH
    captured_at = datetime.now(UTC).isoformat()
    with get_db(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO snapshots (router, captured_at, raw_output) VALUES (?, ?, ?)",
            (router_name, captured_at, raw_output),
        )
        snap_id = cur.lastrowid
        if snap_id is None:  # [O-H2] Runtime check, not assert (survives -O)
            raise RuntimeError("INSERT did not return a row id")
        # [O-H6] Normalize prefix dicts to avoid missing-key errors
        prefix_fields = ("network", "next_hop", "metric", "local_pref", "weight", "as_path", "origin")
        normalized = [
            {**{f: p.get(f, "") for f in prefix_fields}, "snap_id": snap_id}
            for p in prefixes
        ]
        conn.executemany(
            """INSERT INTO prefixes
               (snapshot_id, network, next_hop, metric, local_pref, weight, as_path, origin)
               VALUES (:snap_id, :network, :next_hop, :metric, :local_pref, :weight, :as_path, :origin)""",
            normalized,
        )
    log.info("Saved snapshot id=%d for router=%s at %s", snap_id, router_name, captured_at)
    return snap_id


def _redact_host(message: str, router_cfg: dict) -> str:
    """Replace a router's address in an error string with its name.

    poll_router() sanitizes the two Netmiko exceptions it catches explicitly,
    but everything underneath it does not: paramiko's SSHException
    ("Server '10.0.0.1' not found in known_hosts"), NoValidConnectionsError,
    BadHostKeyException and socket.gaierror all embed the raw address. Those
    strings end up in the job record, the audit log, and the /routers
    `last_error` field, which would defeat _mask_host() entirely — so scrub
    them at the boundary where every poll failure converges. [M3]
    """
    host = str(router_cfg.get("host", ""))
    name = str(router_cfg.get("name", "router"))
    if host and host in message:
        message = message.replace(host, f"<{name}>")
    return message


def _snapshot_one(router_cfg: dict, db_path: Path, actor: str, source_ip: str | None) -> dict:
    """Poll and persist a single router. Never raises — returns a result dict.

    Runs inside a worker thread, so it owns its own DB connection (via get_db)
    and must not let an exception escape into the pool.
    """
    name = router_cfg.get("name", "?")
    started = time.monotonic()
    try:
        raw, prefixes = poll_router(router_cfg)
        sid = save_snapshot(name, raw, prefixes, db_path)
        record_audit(
            "poll_router", actor=actor, outcome="success", target=name,
            source_ip=source_ip, detail=f"snapshot_id={sid} prefixes={len(prefixes)}",
            db_path=db_path,
        )
        return {
            "router": name,
            "status": "success",
            "snapshot_id": sid,
            "prefix_count": len(prefixes),
            "error": None,
            "duration_seconds": round(time.monotonic() - started, 2),
        }
    except Exception as exc:  # [O-H3] One failing router must not abort the others
        # Full detail (including the address) goes to the log only, at DEBUG,
        # consistent with [M3]: addresses are never INFO-level or API-visible.
        log.error("Failed to snapshot %s: %s", name, _redact_host(str(exc), router_cfg))
        log.debug("Poll failure detail for %s", name, exc_info=True)
        message = _redact_host(str(exc), router_cfg)[:500]
        record_audit(
            "poll_router", actor=actor, outcome="failure", target=name,
            source_ip=source_ip, detail=message, db_path=db_path,
        )
        return {
            "router": name,
            "status": "failed",
            "snapshot_id": None,
            "prefix_count": 0,
            "error": message,
            "duration_seconds": round(time.monotonic() - started, 2),
        }


def take_snapshots(
    routers: list[dict] | None = None,
    db_path: Path | None = None,
    actor: str = "system",
    source_ip: str | None = None,
    on_result: object = None,
) -> list[int]:
    """Poll all routers concurrently and save snapshots. Returns snapshot ids.

    Routers are polled in parallel through a bounded thread pool: SSH round
    trips dominate the wall-clock time, and polling serially made a large
    fleet take minutes. The pool is capped by MAX_POLL_WORKERS because many
    platforms rate-limit or lock out concurrent SSH sessions.

    `on_result` is an optional callable invoked with each per-router result
    dict as it completes, used to stream progress into a job record.
    """
    if routers is None:
        routers = ROUTERS
    if db_path is None:
        db_path = DB_PATH
    init_db(db_path)

    results = collect_snapshot_results(routers, db_path, actor, source_ip, on_result)
    return [r["snapshot_id"] for r in results if r["snapshot_id"] is not None]


def collect_snapshot_results(
    routers: list[dict],
    db_path: Path,
    actor: str = "system",
    source_ip: str | None = None,
    on_result: object = None,
) -> list[dict]:
    """Poll routers in parallel, returning the full per-router result list."""
    results: list[dict] = []
    if not routers:
        return results

    workers = min(MAX_POLL_WORKERS, len(routers))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bgp-poll") as pool:
        futures = {}
        for router_cfg in routers:
            # [L6][O-M6] Stop dispatching new work once shutdown is requested.
            if _shutdown_event.is_set():
                log.info("Shutdown requested, stopping snapshot collection")
                break
            futures[pool.submit(_snapshot_one, router_cfg, db_path, actor, source_ip)] = router_cfg

        for future in as_completed(futures):
            result = future.result()  # _snapshot_one never raises
            results.append(result)
            if callable(on_result):
                try:
                    on_result(result)
                except Exception:
                    log.warning("Job progress callback failed", exc_info=True)

    # Keep output order stable and independent of completion order.
    results.sort(key=lambda r: r["router"])
    return results


# ---------------------------------------------------------------------------
# Snapshot jobs
#
# POST /snapshots used to block until every router had been polled, which on a
# real fleet meant a request held open for minutes and tripping client-side
# timeouts. Jobs run in a background thread; callers poll GET /jobs/{id}.
# ---------------------------------------------------------------------------


def _record_job(job: dict) -> None:
    with _jobs_lock:
        _jobs[job["id"]] = job
        while len(_jobs) > MAX_JOB_HISTORY:
            _jobs.popitem(last=False)


def get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return _copy_job(job) if job else None


def list_jobs(limit: int = 20) -> list[dict]:
    with _jobs_lock:
        jobs = [_copy_job(j) for j in _jobs.values()]
    jobs.sort(key=lambda j: j["started_at"], reverse=True)
    return jobs[:limit]


def _copy_job(job: dict) -> dict:
    """Deep-enough copy so callers never observe a half-written job."""
    snapshot = dict(job)
    snapshot["routers"] = [dict(r) for r in job["routers"]]
    return snapshot


def start_snapshot_job(
    routers: list[dict],
    db_path: Path,
    actor: str = "system",
    source_ip: str | None = None,
) -> dict:
    """Kick off a background snapshot job. Returns the initial job record.

    Raises RuntimeError if a job is already running — the caller maps that to
    HTTP 429.
    """
    if not _snapshot_lock.acquire(blocking=False):
        raise RuntimeError("A snapshot job is already running")

    job_id = uuid.uuid4().hex
    job: dict = {
        "id": job_id,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "actor": actor,
        "total": len(routers),
        "completed": 0,
        "succeeded": 0,
        "failed": 0,
        "snapshot_ids": [],
        "routers": [],
    }
    _record_job(job)

    def _on_result(result: dict) -> None:
        with _jobs_lock:
            live = _jobs.get(job_id)
            if live is None:  # evicted by history bound; nothing to update
                return
            live["routers"].append(dict(result))
            live["completed"] += 1
            if result["status"] == "success":
                live["succeeded"] += 1
                live["snapshot_ids"].append(result["snapshot_id"])
            else:
                live["failed"] += 1

    def _run() -> None:
        try:
            init_db(db_path)
            collect_snapshot_results(routers, db_path, actor, source_ip, _on_result)
            status = "completed"
            detail = None
        except Exception as exc:
            log.error("Snapshot job %s failed: %s", job_id, exc)
            status = "failed"
            detail = str(exc)[:500]
        finally:
            _snapshot_lock.release()
        with _jobs_lock:
            live = _jobs.get(job_id)
            if live is not None:
                live["status"] = status
                live["finished_at"] = datetime.now(UTC).isoformat()
                if detail:
                    live["error"] = detail
                live["routers"].sort(key=lambda r: r["router"])

    thread = threading.Thread(target=_run, name=f"bgp-job-{job_id[:8]}", daemon=True)
    try:
        thread.start()
    except BaseException:
        # The worker never ran, so it will never release the lock for us.
        _snapshot_lock.release()
        raise
    # Read back under the lock. Copying the live `job` dict directly would race
    # the worker, which is already mutating it: a fast-failing router can append
    # to job["routers"] or insert job["error"] mid-copy, yielding torn rows or a
    # "dictionary changed size during iteration" RuntimeError.
    return get_job(job_id) or _copy_job(job)


# ---------------------------------------------------------------------------
# Data retention
# ---------------------------------------------------------------------------


def purge_old_snapshots(days: int, db_path: Path | None = None) -> int:
    """Delete snapshots older than N days. Returns count of deleted snapshots."""
    if db_path is None:
        db_path = DB_PATH
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with get_db(db_path) as conn:
        conn.execute(
            "DELETE FROM prefixes WHERE snapshot_id IN "
            "(SELECT id FROM snapshots WHERE captured_at < ?)",
            (cutoff,),
        )
        cur = conn.execute("DELETE FROM snapshots WHERE captured_at < ?", (cutoff,))
        count = cur.rowcount
    log.info("Purged %d snapshot(s) older than %d days", count, days)
    return count


# ---------------------------------------------------------------------------
# Diff / comparison
# ---------------------------------------------------------------------------


def _load_prefix_map(
    snapshot_id: int,
    db_path: Path | None = None,
) -> dict[tuple[str, str], dict]:
    """Return {(network, next_hop): prefix_dict} for a given snapshot.

    Uses a composite key so multiple BGP paths per prefix are tracked
    correctly (e.g. ECMP, backup paths).
    """
    if db_path is None:
        db_path = DB_PATH
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT network, next_hop, metric, local_pref, weight, as_path, origin "
            "FROM prefixes WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchall()
    # [O-M12] Warn on duplicate composite keys instead of silently collapsing
    result: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (row["network"], row["next_hop"] or "")
        if key in result:
            log.warning("Duplicate composite key %s in snapshot %d", key, snapshot_id)
        result[key] = dict(row)
    return result


def diff_snapshots(
    before_id: int,
    after_id: int,
    db_path: Path | None = None,
) -> dict:
    """
    Compare two snapshots and return a structured diff:
      - added:    prefixes present in after but not before
      - removed:  prefixes present in before but not after
      - changed:  prefixes present in both but with different attributes
    """
    if db_path is None:
        db_path = DB_PATH
    before = _load_prefix_map(before_id, db_path)
    after = _load_prefix_map(after_id, db_path)

    before_keys = set(before.keys())
    after_keys = set(after.keys())

    added = [after[k] for k in sorted(after_keys - before_keys)]
    removed = [before[k] for k in sorted(before_keys - after_keys)]

    changed = []
    for key in sorted(before_keys & after_keys):
        b, a = before[key], after[key]
        diffs = {
            field: {"before": b[field], "after": a[field]}
            for field in ("as_path", "local_pref", "metric", "weight", "origin")
            if b.get(field) != a.get(field)
        }
        if diffs:
            changed.append({"network": key[0], "next_hop": key[1], "changes": diffs})

    return {
        "before_snapshot_id": before_id,
        "after_snapshot_id": after_id,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _snapshot_info(snapshot_id: int, db_path: Path | None = None) -> dict | None:
    if db_path is None:
        db_path = DB_PATH
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT id, router, captured_at FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    return dict(row) if row else None


def _snapshot_filters(
    router: str | None,
    since: str | None,
    until: str | None,
    alias: str = "",
) -> tuple[str, list]:
    """Build the shared WHERE clause for snapshot list/count queries.

    `alias` is an optional table alias prefix (e.g. "s."). Only column names
    are interpolated — every user value stays a bound parameter.
    """
    clauses: list[str] = []
    params: list = []
    if router:
        clauses.append(f"{alias}router = ?")
        params.append(router)
    if since:
        clauses.append(f"{alias}captured_at >= ?")
        params.append(since)
    if until:
        clauses.append(f"{alias}captured_at <= ?")
        params.append(until)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def list_snapshots(
    router: str | None = None,
    limit: int = 20,
    offset: int = 0,
    since: str | None = None,
    until: str | None = None,
    db_path: Path | None = None,
) -> list[dict]:
    """Return a page of snapshots, newest first.

    Each row carries its prefix_count so the UI can render a list without an
    N+1 query per snapshot.
    """
    if db_path is None:
        db_path = DB_PATH
    where, params = _snapshot_filters(router, since, until, alias="s.")
    query = (
        "SELECT s.id, s.router, s.captured_at, "
        "       (SELECT COUNT(*) FROM prefixes p WHERE p.snapshot_id = s.id) AS prefix_count "
        f"FROM snapshots s{where} ORDER BY s.id DESC LIMIT ? OFFSET ?"
    )
    with get_db(db_path) as conn:
        rows = conn.execute(query, [*params, limit, offset]).fetchall()
    return [dict(r) for r in rows]


def count_snapshots(
    router: str | None = None,
    since: str | None = None,
    until: str | None = None,
    db_path: Path | None = None,
) -> int:
    """Total snapshots matching the same filters as list_snapshots()."""
    if db_path is None:
        db_path = DB_PATH
    where, params = _snapshot_filters(router, since, until)
    with get_db(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM snapshots{where}", params).fetchone()[0]


def _normalize_timestamp(value: str) -> str:
    """Parse an ISO 8601 timestamp and re-render it in UTC.

    captured_at is stored as a UTC ISO string and filtered with string
    comparison, so a caller-supplied bound carrying a non-UTC offset would
    compare lexicographically against a different instant. Converting to UTC
    first makes '2026-01-01T17:00:00+05:00' and '2026-01-01T12:00:00+00:00'
    behave as the same moment, which they are. A naive value is treated as UTC.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()


def list_snapshot_page(
    router: str | None = None,
    limit: int = 20,
    offset: int = 0,
    since: str | None = None,
    until: str | None = None,
    db_path: Path | None = None,
) -> dict:
    """Return one page of snapshots plus the matching total.

    Both queries share a single connection so `total` cannot disagree with the
    page it describes when a snapshot lands between them.
    """
    if db_path is None:
        db_path = DB_PATH
    where, params = _snapshot_filters(router, since, until, alias="s.")
    plain_where, plain_params = _snapshot_filters(router, since, until)
    with get_db(db_path) as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM snapshots{plain_where}", plain_params
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT s.id, s.router, s.captured_at, "
            "       (SELECT COUNT(*) FROM prefixes p WHERE p.snapshot_id = s.id) AS prefix_count "
            f"FROM snapshots s{where} ORDER BY s.id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return {
        "items": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def router_inventory(routers: list[dict] | None = None, db_path: Path | None = None) -> list[dict]:
    """Health summary for every configured router.

    Deliberately returns no credentials and no full host address — the host is
    masked, matching the convention that addresses are DEBUG-only [M3].
    """
    if routers is None:
        routers = ROUTERS
    if db_path is None:
        db_path = DB_PATH

    with get_db(db_path) as conn:
        latest = {
            row["router"]: dict(row)
            for row in conn.execute("""
                SELECT s.router,
                       s.id           AS last_snapshot_id,
                       s.captured_at  AS last_captured_at,
                       (SELECT COUNT(*) FROM prefixes p WHERE p.snapshot_id = s.id) AS prefix_count
                FROM snapshots s
                JOIN (SELECT router, MAX(id) AS max_id FROM snapshots GROUP BY router) m
                  ON m.router = s.router AND m.max_id = s.id
            """).fetchall()
        }
        # Second-most-recent snapshot per router, for a prefix-count delta.
        previous = {
            row["router"]: row["prefix_count"]
            for row in conn.execute("""
                SELECT s.router,
                       (SELECT COUNT(*) FROM prefixes p WHERE p.snapshot_id = s.id) AS prefix_count
                FROM snapshots s
                JOIN (
                    SELECT router, MAX(id) AS max_id FROM snapshots
                    WHERE id NOT IN (SELECT MAX(id) FROM snapshots GROUP BY router)
                    GROUP BY router
                ) m ON m.router = s.router AND m.max_id = s.id
            """).fetchall()
        }
        last_errors = {
            row["target"]: dict(row)
            for row in conn.execute("""
                SELECT a.target, a.timestamp, a.detail
                FROM audit_log a
                JOIN (
                    SELECT target, MAX(id) AS max_id FROM audit_log
                    WHERE action = 'poll_router' AND outcome = 'failure' AND target IS NOT NULL
                    GROUP BY target
                ) m ON m.target = a.target AND m.max_id = a.id
            """).fetchall()
        }

    inventory = []
    for cfg in routers:
        name = cfg.get("name", "?")
        last = latest.get(name)
        err = last_errors.get(name)
        prev_count = previous.get(name)
        count = last["prefix_count"] if last else None

        # An error outranks "never polled": a router that has only ever failed
        # needs to read as broken, not as merely untouched.
        if err and (last is None or err["timestamp"] > last["last_captured_at"]):
            status = "error"
        elif last is None:
            status = "never_polled"
        else:
            status = "ok"

        inventory.append({
            "name": name,
            "device_type": cfg.get("device_type"),
            "host_masked": _mask_host(cfg.get("host", "")),
            "last_snapshot_id": last["last_snapshot_id"] if last else None,
            "last_captured_at": last["last_captured_at"] if last else None,
            "prefix_count": count,
            "previous_prefix_count": prev_count,
            "prefix_delta": (count - prev_count) if (count is not None and prev_count is not None) else None,
            "status": status,
            "last_error": err["detail"] if err else None,
            "last_error_at": err["timestamp"] if err else None,
        })
    inventory.sort(key=lambda r: r["name"])
    return inventory


def _mask_host(host: str) -> str:
    """Mask a host so the UI can distinguish routers without leaking topology."""
    if not host:
        return ""
    if re.fullmatch(r"[0-9.]+", host):  # IPv4
        parts = host.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x"
        return "x.x.x.x"
    if ":" in host:  # IPv6
        return f"{host.split(':')[0]}:…"
    labels = host.split(".")
    if len(labels) > 2:
        return f"{labels[0]}.…{'.'.join(labels[-2:])}"
    if len(labels) == 2:
        # e.g. "router1.local" — still identifying, so keep the domain and
        # elide the host label rather than returning it whole.
        return f"…{labels[-1]}"
    # Single bare label: truncate rather than echo it back in full.
    return f"{host[:2]}…" if len(host) > 3 else "…"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SnapshotResponse(BaseModel):
    snapshot_ids: list[int]
    message: str


class PrefixInfo(BaseModel):
    network: str
    next_hop: str | None = None
    metric: str | None = None
    local_pref: str | None = None
    weight: str | None = None
    as_path: str | None = None
    origin: str | None = None


class AttributeChange(BaseModel):
    before: str | None = None
    after: str | None = None


class PrefixChange(BaseModel):
    network: str
    next_hop: str | None = None
    changes: dict[str, AttributeChange]


class DiffSummary(BaseModel):
    added: int
    removed: int
    changed: int


class DiffResponse(BaseModel):
    before_snapshot_id: int
    after_snapshot_id: int
    summary: DiffSummary
    added: list[PrefixInfo]
    removed: list[PrefixInfo]
    changed: list[PrefixChange]
    before_router: str | None = None
    after_router: str | None = None
    # [O-L3] True when the two snapshots come from different routers, which
    # makes a large add/remove set expected rather than an incident.
    cross_router: bool = False


# [O-M2] Response models for snapshot endpoints
class SnapshotListItem(BaseModel):
    id: int
    router: str
    captured_at: str
    prefix_count: int | None = None


class SnapshotPage(BaseModel):
    items: list[SnapshotListItem]
    total: int
    limit: int
    offset: int


class SnapshotDetailResponse(BaseModel):
    snapshot: SnapshotListItem
    prefix_count: int
    prefixes: list[PrefixInfo]
    prefix_limit: int
    prefix_offset: int


# --- Auth ---------------------------------------------------------------


class LoginRequest(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=512)


class LoginResponse(BaseModel):
    actor: str
    csrf_token: str
    expires_in: int


class AuthStatus(BaseModel):
    auth_required: bool
    authenticated: bool
    actor: str | None = None
    csrf_token: str | None = None


# --- Jobs ---------------------------------------------------------------


class JobRouterResult(BaseModel):
    router: str
    status: str
    snapshot_id: int | None = None
    prefix_count: int = 0
    error: str | None = None
    duration_seconds: float | None = None


class JobStatus(BaseModel):
    id: str
    status: str
    started_at: str
    finished_at: str | None = None
    actor: str
    total: int
    completed: int
    succeeded: int
    failed: int
    snapshot_ids: list[int]
    routers: list[JobRouterResult]
    error: str | None = None


# --- Router inventory ---------------------------------------------------


class RouterHealth(BaseModel):
    name: str
    device_type: str | None = None
    host_masked: str = ""
    last_snapshot_id: int | None = None
    last_captured_at: str | None = None
    prefix_count: int | None = None
    previous_prefix_count: int | None = None
    prefix_delta: int | None = None
    status: str
    last_error: str | None = None
    last_error_at: str | None = None


# --- Audit --------------------------------------------------------------


class AuditEntry(BaseModel):
    id: int
    timestamp: str
    actor: str
    action: str
    outcome: str
    target: str | None = None
    source_ip: str | None = None
    detail: str | None = None


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# FastAPI REST layer
# ---------------------------------------------------------------------------


# [H1] Custom key function that ignores proxy headers
def _get_client_ip(request: Request) -> str:
    """Get client IP directly from socket, ignoring X-Forwarded-For."""
    return request.client.host if request.client else "127.0.0.1"


# Rate limiter — uses direct client IP, not proxy headers
limiter = Limiter(key_func=_get_client_ip)

# Auth dependency
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Endpoints reachable without authentication, kept as small as possible:
# /auth/login cannot require a session, and /auth/status only reveals whether
# auth is configured so the SPA knows to render a login form. /health stays
# authenticated, matching the pre-existing posture.
PUBLIC_PATHS = frozenset({"/auth/login", "/auth/status"})


def _is_ui_path(path: str) -> bool:
    """True for the static admin UI shell (no data, safe to serve unauthenticated)."""
    return path == "/" or path == "/ui" or path.startswith("/ui/")


def _secret_eq(supplied: str | None, expected: str | None) -> bool:
    """Timing-safe secret comparison that tolerates arbitrary input. [C2]

    hmac.compare_digest raises TypeError when handed a str containing
    non-ASCII, which would turn an attacker-controlled header or login body
    into an unauthenticated 500. Comparing encoded bytes keeps the constant-
    time property while making any input a plain failed match.
    """
    if supplied is None or expected is None:
        return False
    return hmac.compare_digest(
        supplied.encode("utf-8", "surrogateescape"),
        expected.encode("utf-8", "surrogateescape"),
    )


async def verify_api_key(
    request: Request,
    key: str | None = Security(api_key_header),
) -> None:
    """Authenticate a request via session cookie or X-API-Key header.

    Two mechanisms, deliberately different in their CSRF exposure:

    * Session cookie — ambient credential attached by the browser on every
      request, so mutating methods additionally require a matching CSRF token.
    * X-API-Key header — never sent automatically by a browser, so it is not
      forgeable cross-site and needs no CSRF token. This keeps curl and
      existing scripts working unchanged.
    """
    request.state.actor = "anonymous"

    if API_KEY is None:
        # Auth disabled entirely (no key configured). Matches prior behavior.
        request.state.actor = "anonymous"
        return

    # The SPA shell itself carries no data — it must load so the operator can
    # reach the login form. Every API call it then makes is authenticated.
    if request.url.path in PUBLIC_PATHS or _is_ui_path(request.url.path):
        return

    client = _get_client_ip(request)

    # 1. Session cookie
    session = get_session(request.cookies.get(SESSION_COOKIE_NAME))
    if session is not None:
        if request.method not in SAFE_METHODS:
            supplied = request.headers.get(CSRF_HEADER_NAME)
            if not _secret_eq(supplied, session["csrf"]):
                log.warning("CSRF token missing/invalid on %s %s from %s",
                            request.method, request.url.path, client)
                record_audit("csrf_failure", actor=session["actor"], outcome="failure",
                             target=request.url.path, source_ip=client)
                raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
        request.state.actor = session["actor"]
        return

    # 2. API key header
    if _secret_eq(key, API_KEY):  # [C2] Timing-safe
        request.state.actor = "api-key"
        return

    # [L3] Log failed authentication attempts
    log.warning("Authentication failure from %s on %s", client, request.url.path)
    raise HTTPException(status_code=403, detail="Invalid or missing credentials")


def _set_session_cookies(response: Response, token: str, csrf: str) -> None:
    """Attach the session and CSRF cookies to a login response."""
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,          # unreadable from JavaScript — XSS cannot steal it
        secure=_tls_enabled,    # see _tls_enabled: forcing this breaks plain-HTTP loopback
        samesite="strict",      # never sent on cross-site navigation
        path="/",
    )
    # Readable by JS on purpose: the SPA echoes it back in the X-CSRF-Token
    # header. Possession of this cookie alone proves nothing.
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf,
        max_age=SESSION_TTL_SECONDS,
        httponly=False,
        secure=_tls_enabled,
        samesite="strict",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


# Access logging middleware
class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        client = request.client.host if request.client else "unknown"
        log.info("%s %s from %s", request.method, request.url.path, client)
        response = await call_next(request)
        return response


# CSP for the admin SPA. It must be allowed to load its own JS/CSS, which the
# API's `default-src 'none'` policy forbids — hence a separate, still-strict
# policy scoped to the UI routes only.
UI_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


# [H3] Security response headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        is_ui = request.url.path == "/" or request.url.path.startswith("/ui")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = UI_CSP if is_ui else API_CSP
        # Hashed asset filenames are safe to cache; everything else holds
        # snapshot data and must not sit in a shared cache.
        if is_ui and "/assets/" in request.url.path:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers["Cache-Control"] = "no-store"
        if _tls_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# [M7] Validate CORS origins
def _validate_cors_origins(origins: list[str]) -> list[str]:
    """Validate CORS origins. Reject wildcard when API key auth is enabled."""
    validated = []
    for origin in origins:
        if origin == "*" and API_KEY:
            log.warning("Rejecting wildcard CORS origin (*) because API key auth is enabled")
            continue
        if origin != "*" and not re.match(r"^https?://[a-zA-Z0-9._:@\[\]-]+$", origin):
            log.warning("Invalid CORS origin ignored: %s", origin)
            continue
        validated.append(origin)
    return validated


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    if not API_KEY:
        log.warning("BGP_ANALYZER_API_KEY not set -- API authentication is disabled")
    if not ROUTERS:
        log.warning("No routers configured -- set BGP_ROUTER_CONFIG or create routers.json")
    yield


# [L2] Gate OpenAPI docs behind environment variable
_docs_enabled = os.environ.get("BGP_ENABLE_DOCS", "").lower() in ("1", "true", "yes")

app = FastAPI(
    title="BGP Route Analyzer",
    description="NOC-facing API to snapshot and diff BGP tables across edge routers.",
    version="1.0.0",
    dependencies=[Depends(verify_api_key)],
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
)

# Middleware & exception handlers
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
app.add_middleware(SecurityHeadersMiddleware)  # [H3] Security headers
app.add_middleware(AccessLogMiddleware)

# [M7] Validate and apply CORS
_validated_origins = _validate_cors_origins(CORS_ORIGINS)
if _validated_origins:
    log.info("CORS enabled for origins: %s", _validated_origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_validated_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key"],
    )


# [H6] Sanitized exception handler — log type only, details at DEBUG
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("Unhandled %s on %s %s", type(exc).__name__, request.method, request.url.path)
    log.debug("Exception details:", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# [M6] Rate limit all endpoints with appropriate thresholds
@app.get("/health")
@limiter.limit("60/minute")
def health(request: Request) -> dict:
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


@app.post("/auth/login", response_model=LoginResponse)
@limiter.limit("5/minute")  # brute-force resistance on the only guessable secret
def api_login(request: Request, response: Response, body: LoginRequest) -> LoginResponse:
    """Exchange the API key for an HttpOnly session cookie."""
    client = _get_client_ip(request)
    if API_KEY is None:
        raise HTTPException(
            status_code=503,
            detail="Authentication is not configured (BGP_ANALYZER_API_KEY unset).",
        )
    if not _secret_eq(body.api_key, API_KEY):  # [C2] Timing-safe
        log.warning("Failed login attempt from %s", client)
        record_audit("login", actor="anonymous", outcome="failure", source_ip=client)
        raise HTTPException(status_code=403, detail="Invalid API key")

    token, csrf = create_session("admin", client)
    _set_session_cookies(response, token, csrf)
    record_audit("login", actor="admin", outcome="success", source_ip=client)
    log.info("Admin session established from %s", client)
    return LoginResponse(actor="admin", csrf_token=csrf, expires_in=SESSION_TTL_SECONDS)


@app.post("/auth/logout")
@limiter.limit("30/minute")
def api_logout(request: Request, response: Response) -> dict:
    """Destroy the current session."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    existed = destroy_session(token)
    _clear_session_cookies(response)
    if existed:
        record_audit("logout", actor=getattr(request.state, "actor", "unknown"),
                     source_ip=_get_client_ip(request))
    return {"status": "logged out"}


@app.get("/auth/status", response_model=AuthStatus)
@limiter.limit("60/minute")
def api_auth_status(request: Request) -> AuthStatus:
    """Report whether auth is required and whether this caller is logged in.

    Lets the SPA decide between showing a login screen and going straight to
    the dashboard, without having to probe a protected endpoint.
    """
    if API_KEY is None:
        return AuthStatus(auth_required=False, authenticated=True, actor="anonymous")
    session = get_session(request.cookies.get(SESSION_COOKIE_NAME))
    if session is None:
        return AuthStatus(auth_required=True, authenticated=False)
    return AuthStatus(
        auth_required=True,
        authenticated=True,
        actor=session["actor"],
        csrf_token=session["csrf"],
    )


# ---------------------------------------------------------------------------
# Snapshot endpoints
# ---------------------------------------------------------------------------


@app.post("/snapshots", status_code=202)
@limiter.limit("5/minute")
def api_take_snapshots(
    request: Request,
    response: Response,
    wait: bool = Query(False, description="Block until polling finishes and return snapshot IDs"),
) -> dict:
    """Start a snapshot job across all configured routers.

    Returns 202 with a job record by default; poll GET /jobs/{id} for progress.
    Pass `?wait=true` for the legacy blocking behavior used by scripts.
    """
    if not ROUTERS:
        raise HTTPException(status_code=503, detail="No routers configured.")
    actor = getattr(request.state, "actor", "unknown")
    client = _get_client_ip(request)

    if wait:
        # [H2] Prevent concurrent snapshot operations
        if not _snapshot_lock.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="Snapshot already in progress.")
        try:
            snap_ids = take_snapshots(actor=actor, source_ip=client)
        finally:
            _snapshot_lock.release()
        record_audit("snapshot", actor=actor, source_ip=client,
                     detail=f"blocking; {len(snap_ids)} snapshot(s)")
        # 202 Accepted describes the async path. This one already finished, so
        # the honest status is 200.
        response.status_code = 200
        return SnapshotResponse(
            snapshot_ids=snap_ids,
            message=f"Captured {len(snap_ids)} snapshot(s).",
        ).model_dump()

    try:
        job = start_snapshot_job(list(ROUTERS), DB_PATH, actor=actor, source_ip=client)
    except RuntimeError:
        raise HTTPException(status_code=429, detail="Snapshot already in progress.") from None
    record_audit("snapshot", actor=actor, source_ip=client, target=job["id"],
                 detail=f"job started for {job['total']} router(s)")
    return job


@app.get("/jobs", response_model=list[JobStatus])
@limiter.limit("120/minute")  # the UI polls this while a job runs
def api_list_jobs(request: Request, limit: int = Query(20, ge=1, le=100)) -> list[dict]:
    """Recent snapshot jobs, newest first. Job history is in-memory only."""
    return list_jobs(limit=limit)


@app.get("/jobs/{job_id}", response_model=JobStatus)
@limiter.limit("120/minute")
def api_get_job(request: Request, job_id: str = PathParam(..., pattern=r"^[0-9a-f]{32}$")) -> dict:
    """Status of a snapshot job, including per-router results as they land."""
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return job


@app.get("/routers", response_model=list[RouterHealth])
@limiter.limit("30/minute")
def api_routers(request: Request) -> list[dict]:
    """Configured routers with health status. Never returns credentials."""
    return router_inventory()


@app.get("/snapshots", response_model=SnapshotPage)
@limiter.limit("30/minute")
def api_list_snapshots(
    request: Request,
    router: str | None = Query(None, pattern=r"^[a-zA-Z0-9._-]{1,64}$", description="Filter by router name"),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    since: str | None = Query(None, description="ISO timestamp lower bound (inclusive)"),
    until: str | None = Query(None, description="ISO timestamp upper bound (inclusive)"),
) -> dict:
    """List stored snapshots, newest first, with a total for pagination."""
    bounds: dict[str, str | None] = {}
    for value, label in ((since, "since"), (until, "until")):
        if value is None:
            bounds[label] = None
            continue
        try:
            bounds[label] = _normalize_timestamp(value)
        except ValueError:
            raise HTTPException(
                status_code=422, detail=f"{label} must be an ISO 8601 timestamp"
            ) from None
    return list_snapshot_page(
        router=router, limit=limit, offset=offset,
        since=bounds["since"], until=bounds["until"],
    )


@app.get("/snapshots/{snapshot_id}", response_model=SnapshotDetailResponse)
@limiter.limit("30/minute")
def api_get_snapshot(
    request: Request,
    snapshot_id: int = PathParam(..., ge=1),  # [O-M1]
    prefix_limit: int = Query(500, ge=1, le=5000),
    prefix_offset: int = Query(0, ge=0),
) -> dict:
    """Return metadata and a page of prefixes for a specific snapshot."""
    # [O-H7] Single DB connection to avoid TOCTOU race with concurrent purge
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, router, captured_at FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found.")
        info = dict(row)
        total = conn.execute(
            "SELECT COUNT(*) FROM prefixes WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()[0]
        prefix_rows = conn.execute(
            "SELECT network, next_hop, metric, local_pref, weight, as_path, origin "
            "FROM prefixes WHERE snapshot_id = ? ORDER BY id LIMIT ? OFFSET ?",
            (snapshot_id, prefix_limit, prefix_offset),
        ).fetchall()
    info["prefix_count"] = total
    return {
        "snapshot": info,
        "prefix_count": total,
        "prefixes": [dict(r) for r in prefix_rows],
        "prefix_limit": prefix_limit,
        "prefix_offset": prefix_offset,
    }


@app.get("/audit", response_model=AuditPage)
@limiter.limit("30/minute")
def api_audit(
    request: Request,
    action: str | None = Query(None, pattern=r"^[a-z_]{1,32}$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """Admin action audit trail, newest first."""
    items, total = list_audit_log(action=action, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/diff", response_model=DiffResponse)
@limiter.limit("10/minute")
def api_diff(
    request: Request,
    before: int = Query(..., ge=1, description="Snapshot ID before change window"),  # [O-M1]
    after: int = Query(..., ge=1, description="Snapshot ID after change window"),
) -> dict:
    """
    Compare two snapshots. Highlights added/removed prefixes and path changes.
    Ideal for post-change verification — catches route leaks and unexpected path shifts.
    """
    # [O-M3] Reject self-comparison
    if before == after:
        raise HTTPException(status_code=400, detail="before and after must be different snapshot IDs.")
    infos = {}
    for sid in (before, after):
        info = _snapshot_info(sid)
        if not info:
            raise HTTPException(status_code=404, detail=f"Snapshot {sid} not found.")
        infos[sid] = info
    # [O-L3] Comparing two different routers produces a huge add/remove set
    # that reads like an outage. Surface it rather than letting it mislead.
    cross_router = infos[before]["router"] != infos[after]["router"]
    if cross_router:
        log.warning(
            "Cross-router diff requested: %s (%s) vs %s (%s)",
            before, infos[before]["router"], after, infos[after]["router"],
        )
    result = diff_snapshots(before, after)
    result["before_router"] = infos[before]["router"]
    result["after_router"] = infos[after]["router"]
    result["cross_router"] = cross_router
    return result


# ---------------------------------------------------------------------------
# Admin UI (static SPA)
#
# Mounted last so it cannot shadow an API route. Serving the built assets from
# the same origin as the API means the session cookie is first-party and no
# CORS configuration is required.
# ---------------------------------------------------------------------------

UI_DIST = Path(__file__).resolve().parent / "ui" / "dist"


def mount_ui(application: FastAPI, dist: Path = UI_DIST) -> bool:
    """Mount the built admin UI if present. Returns True when mounted."""
    index = dist / "index.html"
    if not index.is_file():
        log.info("Admin UI not built (%s missing) — API-only mode. Run: cd ui && npm ci && npm run build", index)
        return False

    assets = dist / "assets"
    if assets.is_dir():
        application.mount("/ui/assets", StaticFiles(directory=assets), name="ui-assets")

    resolved_dist = dist.resolve()

    @application.get("/ui", include_in_schema=False)
    @application.get("/ui/{path:path}", include_in_schema=False)
    def serve_ui(path: str = "") -> FileResponse:
        """Serve a real static file when one matches, else the SPA shell.

        The fallback is what makes client-side routing work: unknown paths are
        UI routes, not missing files.
        """
        if path:
            candidate = (dist / path).resolve()
            # Containment check — never serve anything outside dist, however
            # the path was encoded.
            if candidate.is_file() and candidate.is_relative_to(resolved_dist):
                return FileResponse(candidate)
        return FileResponse(index)

    @application.get("/", include_in_schema=False)
    def serve_root() -> FileResponse:
        return FileResponse(index)

    log.info("Admin UI mounted at /ui")
    return True


_ui_mounted = mount_ui(app)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _cli() -> None:
    global DB_PATH  # [O-C3] Propagate --db to global so API endpoints use it
    parser = argparse.ArgumentParser(description="BGP Route Analysis Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--snapshot", action="store_true", help="Poll routers and save snapshots")
    group.add_argument("--diff", action="store_true", help="Diff two snapshots")
    group.add_argument("--list", action="store_true", help="List stored snapshots")
    group.add_argument("--serve", action="store_true", help="Start FastAPI server")
    group.add_argument("--purge", type=int, metavar="DAYS",
                       help="Delete snapshots older than N days")  # [M8]
    group.add_argument("--purge-audit", type=int, metavar="DAYS",
                       help="Delete audit log entries older than N days")
    group.add_argument("--audit", action="store_true", help="Show recent audit log entries")
    group.add_argument("--routers", action="store_true", help="Show router inventory and health")

    parser.add_argument("--before", type=int, help="Snapshot ID before change window (for --diff)")
    parser.add_argument("--after", type=int, help="Snapshot ID after change window (for --diff)")
    parser.add_argument("--router", help="Filter by router name (for --list)")
    parser.add_argument("--limit", type=int, default=20, help="Max rows to show (for --list/--audit)")
    parser.add_argument("--router-config", help="Path to router config JSON file")
    parser.add_argument("--db", default=str(DB_PATH), help="SQLite database path")
    parser.add_argument("--host", default="127.0.0.1", help="API server host (for --serve)")
    parser.add_argument("--port", type=int, default=8000, help="API server port (for --serve)")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate (for --serve)")
    parser.add_argument("--ssl-key", help="Path to SSL private key (for --serve)")

    args = parser.parse_args()

    # [L6] Install signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # [M4] Validate and canonicalize database path
    db = Path(args.db).resolve()
    if not db.parent.exists():
        print(f"ERROR: Parent directory {db.parent} does not exist.", file=sys.stderr)
        sys.exit(1)
    DB_PATH = db
    init_db(db)

    # Load router config override if specified
    if args.router_config:
        config_path = Path(args.router_config).resolve()  # [M4]
        ROUTERS.clear()
        ROUTERS.extend(_load_routers(str(config_path)))

    if args.snapshot:
        if not ROUTERS:
            print("ERROR: No routers configured. Create routers.json or use --router-config.", file=sys.stderr)
            sys.exit(1)
        ids = take_snapshots(db_path=db, actor="cli", source_ip="local")
        record_audit("snapshot", actor="cli", source_ip="local",
                     detail=f"{len(ids)} snapshot(s)", db_path=db)
        print(f"Snapshots saved: {ids}")

    elif args.diff:
        # [O-M4] Check for None (not falsy) and validate positive IDs
        if args.before is None or args.after is None:
            parser.error("--diff requires --before and --after snapshot IDs")
        if args.before < 1 or args.after < 1:
            parser.error("--diff requires positive snapshot IDs (>= 1)")
        # Validate snapshots exist before diffing
        for sid in (args.before, args.after):
            if _snapshot_info(sid, db) is None:
                print(f"ERROR: Snapshot {sid} not found.", file=sys.stderr)
                sys.exit(1)
        result = diff_snapshots(args.before, args.after, db_path=db)
        print(json.dumps(result, indent=2))

    elif args.list:
        rows = list_snapshots(router=args.router, limit=args.limit, db_path=db)
        total = count_snapshots(router=args.router, db_path=db)
        for r in rows:
            print(f"  [{r['id']:4d}]  {r['router']:30s}  {r['captured_at']}  "
                  f"{r.get('prefix_count', 0):6d} prefixes")
        print(f"\nShowing {len(rows)} of {total} snapshot(s).")

    elif args.routers:
        inventory = router_inventory(db_path=db)
        if not inventory:
            print("No routers configured.")
        for r in inventory:
            print(f"  {r['name']:24s} {r['status']:12s} {r['device_type'] or '-':16s} "
                  f"last={r['last_captured_at'] or 'never'} prefixes={r['prefix_count']}")
            if r["last_error"]:
                print(f"      last error ({r['last_error_at']}): {r['last_error']}")

    elif args.audit:
        entries, total = list_audit_log(limit=args.limit, db_path=db)
        for e in entries:
            print(f"  {e['timestamp']}  {e['actor']:10s} {e['action']:14s} "
                  f"{e['outcome']:8s} {e['target'] or '-'}")
            if e["detail"]:
                print(f"      {e['detail']}")
        print(f"\nShowing {len(entries)} of {total} audit entry(s).")

    elif args.purge is not None:
        # [O-H5] Validate purge days to prevent accidental total deletion
        if args.purge < 1:
            print("ERROR: --purge requires a positive number of days (>= 1).", file=sys.stderr)
            sys.exit(1)
        count = purge_old_snapshots(args.purge, db_path=db)
        record_audit("purge", actor="cli", source_ip="local",
                     detail=f"{count} snapshot(s) older than {args.purge}d", db_path=db)
        print(f"Purged {count} snapshot(s) older than {args.purge} days.")

    elif args.purge_audit is not None:
        if args.purge_audit < 1:
            print("ERROR: --purge-audit requires a positive number of days (>= 1).", file=sys.stderr)
            sys.exit(1)
        count = purge_old_audit(args.purge_audit, db_path=db)
        print(f"Purged {count} audit entry(s) older than {args.purge_audit} days.")

    elif args.serve:
        global _tls_enabled
        # [O-M10] Validate port range
        if not (1 <= args.port <= 65535):
            print(f"ERROR: --port must be between 1 and 65535, got {args.port}.", file=sys.stderr)
            sys.exit(1)

        if bool(args.ssl_cert) != bool(args.ssl_key):
            print("ERROR: --ssl-cert and --ssl-key must be provided together.", file=sys.stderr)
            sys.exit(1)

        # BGP_ASSUME_TLS (already folded into _tls_enabled at import) covers
        # reverse-proxy termination, so don't clear it when no cert is passed.
        _tls_enabled = _tls_enabled or bool(args.ssl_cert and args.ssl_key)

        # [H5] Warn when API key auth is enabled but TLS is not configured
        if API_KEY and not _tls_enabled:
            log.warning(
                "API key authentication is enabled but TLS is not configured. "
                "API keys and session cookies will be transmitted in plaintext, and "
                "session cookies will not carry the Secure flag. Use --ssl-cert and "
                "--ssl-key, or set BGP_ASSUME_TLS=1 if TLS terminates at a proxy."
            )

        # [M1] Warn when binding to non-loopback without API key
        if args.host != "127.0.0.1" and not API_KEY:
            log.warning(
                "Binding to %s without API key authentication. "
                "The API and admin UI will be accessible without authentication.",
                args.host,
            )

        if not _ui_mounted:
            log.info("Admin UI is not built; serving API only. Build it with: cd ui && npm ci && npm run build")

        ssl_kwargs: dict = {}
        if _tls_enabled:
            ssl_kwargs["ssl_certfile"] = args.ssl_cert
            ssl_kwargs["ssl_keyfile"] = args.ssl_key

        # [M9] Hardened Uvicorn settings.
        # limit_max_requests is opt-in: uvicorn *shuts the server down* once the
        # counter is hit, and a dashboard polling job status reaches a five-digit
        # request count in hours. Only set it when a supervisor restarts the
        # process (BGP_LIMIT_MAX_REQUESTS).
        max_requests_raw = os.environ.get("BGP_LIMIT_MAX_REQUESTS")
        max_requests = _env_int("BGP_LIMIT_MAX_REQUESTS", 0, minimum=0) or None
        if max_requests_raw and max_requests:
            log.warning(
                "BGP_LIMIT_MAX_REQUESTS=%d — the server will exit after that many "
                "requests. Ensure a supervisor restarts it.", max_requests,
            )

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            server_header=False,
            limit_concurrency=_env_int("BGP_LIMIT_CONCURRENCY", 100, minimum=1),
            limit_max_requests=max_requests,
            **ssl_kwargs,
        )


if __name__ == "__main__":
    _cli()
