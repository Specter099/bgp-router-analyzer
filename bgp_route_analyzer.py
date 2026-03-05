#!/usr/bin/env python3
"""
BGP Route Analysis Tool
-----------------------
Polls edge routers via SSH using Netmiko, parses BGP tables with TextFSM,
stores snapshots in a time-series SQLite database, and compares prefix
advertisements before/after a change window.

Exposes a REST API via FastAPI so the NOC team can trigger checks from
their incident dashboard.

Configuration:
    Router credentials:  routers.json  (see routers.json.example)
    Environment vars:
        BGP_ROUTER_CONFIG    - path to router config JSON  (default: routers.json)
        BGP_DB_PATH          - SQLite database path         (default: bgp_snapshots.db)
        BGP_ANALYZER_API_KEY - API key for authentication   (optional, disables auth if unset)
        BGP_CORS_ORIGINS     - comma-separated CORS origins (optional)
        BGP_ROUTER_PASSWORD  - default router password      (optional, env-based override)
        BGP_ENABLE_DOCS      - enable OpenAPI docs          (optional, default: disabled)

Usage:
    python bgp_route_analyzer.py --snapshot
    python bgp_route_analyzer.py --diff --before <id> --after <id>
    python bgp_route_analyzer.py --serve
    python bgp_route_analyzer.py --purge 30
"""

import argparse
import hmac
import io
import json
import logging
import os
import re
import signal
import sqlite3
import stat
import sys
import textwrap
import threading
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import textfsm
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from pydantic import BaseModel
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

# [L6] Graceful shutdown flag
_shutdown_requested = False


def _signal_handler(signum: int, frame: object) -> None:
    """Set shutdown flag for graceful termination."""
    global _shutdown_requested
    _shutdown_requested = True
    log.info("Shutdown requested (signal %d), finishing current operation...", signum)


def _load_routers(config_path: str | None = None) -> list[dict]:
    """Load and validate router configuration from an external JSON file."""
    path = config_path or os.environ.get("BGP_ROUTER_CONFIG", "routers.json")
    resolved = Path(path).resolve()  # [M4] canonicalize path
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

    if not isinstance(raw, list):
        raise ValueError(f"Router config must be a JSON array, got {type(raw).__name__}")

    # [C4] Support env var password override
    password_override = os.environ.get("BGP_ROUTER_PASSWORD")

    validated = []
    for i, router in enumerate(raw):
        if not isinstance(router, dict):
            raise ValueError(f"Router config [{i}] must be a JSON object")

        # [C3] Validate required fields
        for field in ("host", "device_type", "name"):
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_prefixes_snapshot ON prefixes(snapshot_id)")
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
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


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
        raw = connection.send_command("show ip bgp", read_timeout=60)
    finally:
        connection.disconnect()

    # [L5] Truncate oversized output
    if len(raw) > MAX_RAW_OUTPUT_SIZE:
        log.warning(
            "Raw output from %s exceeds %d bytes, truncating",
            router_cfg["name"], MAX_RAW_OUTPUT_SIZE,
        )
        raw = raw[:MAX_RAW_OUTPUT_SIZE]

    prefixes = _parse_bgp_table(raw)
    log.info("  -> %d prefixes parsed from %s", len(prefixes), router_cfg["name"])
    return raw, prefixes


def _parse_bgp_table(raw_output: str) -> list[dict]:
    """Parse raw 'show ip bgp' output using TextFSM."""
    template_fh = io.StringIO(TEXTFSM_TEMPLATE)
    fsm = textfsm.TextFSM(template_fh)
    rows = fsm.ParseText(raw_output)
    headers = [h.lower() for h in fsm.header]
    return [dict(zip(headers, row)) for row in rows if any(row)]


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
    captured_at = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO snapshots (router, captured_at, raw_output) VALUES (?, ?, ?)",
            (router_name, captured_at, raw_output),
        )
        snap_id = cur.lastrowid
        assert snap_id is not None, "INSERT did not return a row id"
        conn.executemany(
            """INSERT INTO prefixes
               (snapshot_id, network, next_hop, metric, local_pref, weight, as_path, origin)
               VALUES (:snap_id, :network, :next_hop, :metric, :local_pref, :weight, :as_path, :origin)""",
            [{**p, "snap_id": snap_id} for p in prefixes],
        )
    log.info("Saved snapshot id=%d for router=%s at %s", snap_id, router_name, captured_at)
    return snap_id


def take_snapshots(
    routers: list[dict] | None = None,
    db_path: Path | None = None,
) -> list[int]:
    """Poll all routers and save snapshots. Returns list of snapshot ids."""
    if routers is None:
        routers = ROUTERS
    if db_path is None:
        db_path = DB_PATH
    init_db(db_path)
    snap_ids = []
    for router_cfg in routers:
        # [L6] Check for graceful shutdown
        if _shutdown_requested:
            log.info("Shutdown requested, stopping snapshot collection")
            break
        try:
            raw, prefixes = poll_router(router_cfg)
            sid = save_snapshot(router_cfg["name"], raw, prefixes, db_path)
            snap_ids.append(sid)
        except (RuntimeError, sqlite3.Error) as exc:
            log.error("Failed to snapshot %s: %s", router_cfg.get("name", "?"), exc)
    return snap_ids


# ---------------------------------------------------------------------------
# Data retention
# ---------------------------------------------------------------------------


def purge_old_snapshots(days: int, db_path: Path | None = None) -> int:
    """Delete snapshots older than N days. Returns count of deleted snapshots."""
    if db_path is None:
        db_path = DB_PATH
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
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
    return {(row["network"], row["next_hop"] or ""): dict(row) for row in rows}


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


def list_snapshots(
    router: str | None = None,
    limit: int = 20,
    db_path: Path | None = None,
) -> list[dict]:
    if db_path is None:
        db_path = DB_PATH
    query = "SELECT id, router, captured_at FROM snapshots"
    params: list = []
    if router:
        query += " WHERE router = ?"
        params.append(router)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


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


async def verify_api_key(
    request: Request,
    key: str | None = Security(api_key_header),
) -> None:
    """Verify API key if BGP_ANALYZER_API_KEY is configured."""
    if API_KEY is None:
        return
    if key is None or not hmac.compare_digest(key, API_KEY):  # [C2] Timing-safe comparison
        # [L3] Log failed authentication attempts
        client = request.client.host if request.client else "unknown"
        log.warning("Authentication failure from %s", client)
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


# Access logging middleware
class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        client = request.client.host if request.client else "unknown"
        log.info("%s %s from %s", request.method, request.url.path, client)
        response = await call_next(request)
        return response


# [H3] Security response headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
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
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/snapshots", response_model=SnapshotResponse)
@limiter.limit("5/minute")
def api_take_snapshots(request: Request) -> SnapshotResponse:
    """Poll all configured routers and store BGP table snapshots."""
    if not ROUTERS:
        raise HTTPException(status_code=503, detail="No routers configured.")
    # [H2] Prevent concurrent snapshot operations
    if not _snapshot_lock.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Snapshot already in progress.")
    try:
        snap_ids = take_snapshots()
    finally:
        _snapshot_lock.release()
    return SnapshotResponse(
        snapshot_ids=snap_ids,
        message=f"Captured {len(snap_ids)} snapshot(s).",
    )


@app.get("/snapshots")
@limiter.limit("30/minute")
def api_list_snapshots(
    request: Request,
    router: str | None = Query(None, pattern=r"^[a-zA-Z0-9._-]{1,64}$", description="Filter by router name"),
    limit: int = Query(20, ge=1, le=200),
) -> list[dict]:
    """List stored snapshots, newest first."""
    return list_snapshots(router=router, limit=limit)


@app.get("/snapshots/{snapshot_id}")
@limiter.limit("30/minute")
def api_get_snapshot(request: Request, snapshot_id: int) -> dict:
    """Return metadata for a specific snapshot."""
    info = _snapshot_info(snapshot_id)
    if not info:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found.")
    prefixes = _load_prefix_map(snapshot_id)
    return {"snapshot": info, "prefix_count": len(prefixes), "prefixes": list(prefixes.values())}


@app.get("/diff", response_model=DiffResponse)
@limiter.limit("10/minute")
def api_diff(
    request: Request,
    before: int = Query(..., description="Snapshot ID before change window"),
    after: int = Query(..., description="Snapshot ID after change window"),
) -> dict:
    """
    Compare two snapshots. Highlights added/removed prefixes and path changes.
    Ideal for post-change verification — catches route leaks and unexpected path shifts.
    """
    for sid in (before, after):
        if not _snapshot_info(sid):
            raise HTTPException(status_code=404, detail=f"Snapshot {sid} not found.")
    return diff_snapshots(before, after)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _cli() -> None:
    parser = argparse.ArgumentParser(description="BGP Route Analysis Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--snapshot", action="store_true", help="Poll routers and save snapshots")
    group.add_argument("--diff", action="store_true", help="Diff two snapshots")
    group.add_argument("--list", action="store_true", help="List stored snapshots")
    group.add_argument("--serve", action="store_true", help="Start FastAPI server")
    group.add_argument("--purge", type=int, metavar="DAYS",
                       help="Delete snapshots older than N days")  # [M8]

    parser.add_argument("--before", type=int, help="Snapshot ID before change window (for --diff)")
    parser.add_argument("--after", type=int, help="Snapshot ID after change window (for --diff)")
    parser.add_argument("--router", help="Filter by router name (for --list)")
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
        ids = take_snapshots(db_path=db)
        print(f"Snapshots saved: {ids}")

    elif args.diff:
        if not args.before or not args.after:
            parser.error("--diff requires --before and --after snapshot IDs")
        result = diff_snapshots(args.before, args.after, db_path=db)
        print(json.dumps(result, indent=2))

    elif args.list:
        rows = list_snapshots(router=args.router, db_path=db)
        for r in rows:
            print(f"  [{r['id']:4d}]  {r['router']:30s}  {r['captured_at']}")

    elif args.purge is not None:
        count = purge_old_snapshots(args.purge, db_path=db)
        print(f"Purged {count} snapshot(s) older than {args.purge} days.")

    elif args.serve:
        # [H5] Warn when API key auth is enabled but TLS is not configured
        if API_KEY and not (args.ssl_cert and args.ssl_key):
            log.warning(
                "API key authentication is enabled but TLS is not configured. "
                "API keys will be transmitted in plaintext. Use --ssl-cert and --ssl-key."
            )

        # [M1] Warn when binding to non-loopback without API key
        if args.host != "127.0.0.1" and not API_KEY:
            log.warning(
                "Binding to %s without API key authentication. "
                "The API will be accessible without authentication.",
                args.host,
            )

        ssl_kwargs: dict = {}
        if args.ssl_cert and args.ssl_key:
            ssl_kwargs["ssl_certfile"] = args.ssl_cert
            ssl_kwargs["ssl_keyfile"] = args.ssl_key

        # [M9] Hardened Uvicorn settings
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            server_header=False,
            limit_concurrency=100,
            limit_max_requests=10000,
            **ssl_kwargs,
        )


if __name__ == "__main__":
    _cli()
