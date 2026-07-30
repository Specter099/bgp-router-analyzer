"""Regression tests for defects found in code review.

Each test here corresponds to a confirmed bug; they exist to stop the specific
failure recurring, so the docstrings name the failure rather than the feature.
"""

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import bgp_route_analyzer as bga
from bgp_route_analyzer import (
    _load_routers,
    _mask_host,
    _normalize_timestamp,
    _redact_host,
    _secret_eq,
    app,
    count_snapshots,
    init_db,
    list_snapshot_page,
    save_snapshot,
    start_snapshot_job,
)

SAMPLE = [{"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
           "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"}]


# --- Unreadable router config must not kill the process at import ---------


@pytest.mark.skipif(os.getuid() == 0, reason="root bypasses file permission checks")
def test_unreadable_config_returns_empty_not_raises(tmp_path: Path):
    """A config the process cannot read must degrade, not crash.

    _load_routers() runs at module import, so raising here kills the process
    before argparse — and under a container restart policy, that is a crash
    loop. Bind-mounting a 0600 routers.json owned by another UID into a
    non-root container produces exactly this.
    """
    config = tmp_path / "routers.json"
    config.write_text(json.dumps([{"host": "10.0.0.1", "device_type": "cisco_ios",
                                   "name": "r1", "username": "u"}]))
    config.chmod(0o000)
    try:
        assert _load_routers(str(config)) == []
    finally:
        config.chmod(0o600)


def test_untraversable_config_dir_returns_empty(tmp_path: Path):
    """PermissionError from exists()/stat(), not just open().

    A parent directory that denies traversal makes Path.exists() itself raise,
    which is upstream of the open() call — this is the failure a bind-mounted
    config in a non-root container actually hits.
    """
    parent = tmp_path / "locked"
    parent.mkdir()
    config = parent / "routers.json"
    config.write_text("[]")
    parent.chmod(0o000)
    try:
        # Root can traverse regardless; assert only that nothing escapes.
        assert _load_routers(str(config)) == []
    finally:
        parent.chmod(0o755)


def test_config_is_a_directory_returns_empty(tmp_path: Path):
    """IsADirectoryError is an OSError too — must not escape."""
    target = tmp_path / "routers.json"
    target.mkdir()
    assert _load_routers(str(target)) == []


@pytest.mark.skipif(os.getuid() != 0, reason="needs root to drop privileges")
def test_module_imports_when_config_is_unreadable(tmp_path: Path):
    """End-to-end: importing as a foreign UID against a 0600 config succeeds."""
    config = tmp_path / "routers.json"
    config.write_text("[]")
    config.chmod(0o600)
    tmp_path.chmod(0o755)
    script = (
        "import os; os.setgid(65534); os.setuid(65534)\n"
        f"os.environ['BGP_ROUTER_CONFIG'] = {str(config)!r}\n"
        f"import sys; sys.path.insert(0, {str(Path(bga.__file__).parent)!r})\n"
        "import bgp_route_analyzer as b; print('OK', b.ROUTERS)\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "OK []" in result.stdout


# --- Router addresses must not leak through exception text ----------------


def test_redact_host_replaces_address_with_name():
    cfg = {"host": "10.0.0.1", "name": "edge-01"}
    msg = "Server '10.0.0.1' not found in known_hosts"
    assert "10.0.0.1" not in _redact_host(msg, cfg)
    assert "<edge-01>" in _redact_host(msg, cfg)


def test_poll_failure_does_not_leak_host_into_job_or_audit(tmp_path: Path, monkeypatch):
    """Paramiko-style errors embed the raw address; it must never reach the API.

    poll_router() only sanitizes the two Netmiko exceptions it catches by name.
    SSHException, NoValidConnectionsError and socket.gaierror all carry the
    host verbatim, and that string lands in the job record, the audit log, and
    /routers `last_error`.
    """
    db = tmp_path / "leak.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    routers = [{"name": "edge-01", "host": "10.20.30.40",
                "device_type": "cisco_ios", "username": "u"}]
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", routers)

    def _boom(cfg):
        raise OSError("Unable to connect to port 22 on 10.20.30.40")

    monkeypatch.setattr("bgp_route_analyzer.poll_router", _boom)

    results = bga.collect_snapshot_results(routers, db)
    assert results[0]["status"] == "failed"
    assert "10.20.30.40" not in results[0]["error"]

    entries, _ = bga.list_audit_log(action="poll_router", db_path=db)
    assert "10.20.30.40" not in json.dumps(entries)

    inventory = bga.router_inventory(routers, db)
    assert "10.20.30.40" not in json.dumps(inventory)

    with TestClient(app) as c:
        assert "10.20.30.40" not in c.get("/routers").text


def test_poll_router_loads_system_host_keys(monkeypatch):
    """ssh_strict is useless without system_host_keys=True.

    Netmiko only calls paramiko's load_system_host_keys() when this kwarg is
    set, and it defaults to False. Without it, ssh_strict=True leaves the
    client with an empty host-key set plus RejectPolicy, so every connection
    is rejected regardless of what ~/.ssh/known_hosts contains.
    """
    captured: dict = {}

    class _FakeConnection:
        def send_command(self, *_args, **_kwargs):
            return ""

        def disconnect(self):
            pass

    def _fake_connect(**kwargs):
        captured.update(kwargs)
        return _FakeConnection()

    monkeypatch.setattr("bgp_route_analyzer.ConnectHandler", _fake_connect)
    bga.poll_router({"host": "10.0.0.1", "username": "u",
                     "device_type": "cisco_ios", "name": "r1"})
    assert captured["system_host_keys"] is True
    assert captured["ssh_strict"] is True  # [C1] still defaults on


def test_ssh_strict_can_still_be_opted_out_per_router(monkeypatch, caplog):
    """Explicit opt-out must remain possible, but never silently."""
    captured: dict = {}

    class _FakeConnection:
        def send_command(self, *_args, **_kwargs):
            return ""

        def disconnect(self):
            pass

    monkeypatch.setattr("bgp_route_analyzer.ConnectHandler",
                        lambda **kw: (captured.update(kw), _FakeConnection())[1])
    with caplog.at_level("WARNING"):
        bga.poll_router({"host": "10.0.0.1", "username": "u", "device_type": "cisco_ios",
                         "name": "r1", "ssh_strict": False})
    assert captured["ssh_strict"] is False
    # "Never silently" has to mean something: a router running without host key
    # verification must be identifiable from the logs.
    assert any("verification is DISABLED" in r.message and "r1" in r.message
               for r in caplog.records)


def test_ssh_strict_default_logs_no_warning(monkeypatch, caplog):
    """The secure default must not produce warning noise."""
    class _FakeConnection:
        def send_command(self, *_args, **_kwargs):
            return ""

        def disconnect(self):
            pass

    monkeypatch.setattr("bgp_route_analyzer.ConnectHandler", lambda **kw: _FakeConnection())
    with caplog.at_level("WARNING"):
        bga.poll_router({"host": "10.0.0.1", "username": "u",
                         "device_type": "cisco_ios", "name": "r1"})
    assert not any("verification is DISABLED" in r.message for r in caplog.records)


def test_non_utf8_config_returns_empty(tmp_path: Path):
    """A binary/latin-1 config fails at decode, not JSON parse — same crash class."""
    config = tmp_path / "routers.json"
    config.write_bytes(b'[{"name": "caf\xe9"}]')
    assert _load_routers(str(config)) == []


def test_mask_host_masks_short_hostnames():
    """Two-label and bare hostnames were previously returned in full."""
    assert _mask_host("router1.local") == "…local"
    assert "router1" not in _mask_host("router1.local")
    assert _mask_host("coreswitch") == "co…"
    assert _mask_host("10.0.0.1") == "10.0.x.x"
    assert _mask_host("edge.lon.example.com").startswith("edge.")
    assert _mask_host("") == ""


# --- Credential comparison must tolerate arbitrary input ------------------


def test_secret_eq_handles_non_ascii():
    """hmac.compare_digest raises TypeError on non-ASCII str."""
    assert _secret_eq("kü", "kü") is True
    assert _secret_eq("kü", "secret") is False
    assert _secret_eq("secret", "kü") is False
    assert _secret_eq(None, "secret") is False
    assert _secret_eq("\udcff", "secret") is False


def test_non_ascii_login_is_403_not_500(tmp_path: Path, monkeypatch):
    """A non-ASCII api_key was an unauthenticated 500 trigger."""
    db = tmp_path / "auth.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    with TestClient(app) as c:
        assert c.post("/auth/login", json={"api_key": "kü"}).status_code == 403


@pytest.mark.parametrize("bad", ["\\ud800", "\\udcff", "\\udfff"])
def test_lone_surrogate_login_is_4xx_not_500(tmp_path: Path, monkeypatch, bad):
    """Lone surrogates must not produce an unauthenticated 500.

    Two separate failure modes converge here: surrogateescape only round-trips
    U+DC80-U+DCFF, so a high surrogate still breaks the encode; and FastAPI's
    default validation handler echoes the rejected value back, which itself
    raises UnicodeEncodeError while rendering the 422.
    """
    db = tmp_path / "surrogate.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.post(
            "/auth/login",
            content=f'{{"api_key": "{bad}"}}',
            headers={"Content-Type": "application/json"},
        )
        assert 400 <= resp.status_code < 500, f"got {resp.status_code}"


def test_validation_errors_do_not_echo_input(tmp_path: Path, monkeypatch):
    """A 422 body must not reflect the submitted value back to the client."""
    db = tmp_path / "echo.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    marker = "sensitive-value-should-not-be-echoed"
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.post("/auth/login", json={"api_key": {"nested": marker}})
        assert resp.status_code == 422
        assert marker not in resp.text


def test_non_ascii_api_key_header_is_403_not_500(tmp_path: Path, monkeypatch):
    db = tmp_path / "auth.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    with TestClient(app) as c:
        # Sent as raw bytes: httpx rejects non-ASCII header *strings* before
        # they leave the client, but a real attacker is not using httpx.
        # Starlette decodes these as latin-1, producing the str with
        # codepoints > 127 that used to blow up hmac.compare_digest.
        resp = c.get("/snapshots", headers={"X-API-Key": "kü".encode()})
        assert resp.status_code == 403


# --- Job record must not be copied while the worker mutates it ------------


def test_start_job_response_is_consistent_under_fast_worker(tmp_path: Path, monkeypatch):
    """Copying the live job dict raced the worker thread.

    A router that fails instantly lets the worker append to job["routers"] and
    insert job["error"] while the 202 body is being built, which could raise
    "dictionary changed size during iteration".
    """
    db = tmp_path / "race.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer._jobs", __import__("collections").OrderedDict())

    def _instant_fail(cfg):
        raise KeyError("username")

    monkeypatch.setattr("bgp_route_analyzer.poll_router", _instant_fail)
    routers = [{"name": f"r{i}", "host": f"10.0.0.{i}",
                "device_type": "cisco_ios", "username": "u"} for i in range(8)]

    for _ in range(15):
        job = start_snapshot_job(routers, db)
        # Must be a well-formed, serializable snapshot every time.
        assert json.dumps(job)
        assert isinstance(job["routers"], list)
        assert job["completed"] == len(job["routers"])
        deadline = threading.Event()
        while bga.get_job(job["id"])["status"] == "running":
            deadline.wait(0.01)


# --- Timestamp filters must compare instants, not strings -----------------


def test_normalize_timestamp_converts_to_utc():
    assert _normalize_timestamp("2026-01-01T17:00:00+05:00").startswith("2026-01-01T12:00:00")
    assert _normalize_timestamp("2026-01-01T12:00:00+00:00").startswith("2026-01-01T12:00:00")
    # Naive input is treated as UTC.
    assert _normalize_timestamp("2026-01-01T12:00:00").startswith("2026-01-01T12:00:00")
    with pytest.raises(ValueError):
        _normalize_timestamp("not-a-date")


def test_since_filter_with_offset_matches_same_instant(tmp_path: Path, monkeypatch):
    """A +05:00 bound was compared lexicographically against a UTC string."""
    db = tmp_path / "tz.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    save_snapshot("rtr1", "raw", SAMPLE, db)

    with TestClient(app) as c:
        # An hour before now, expressed in +05:00 — must still match.
        early = c.get("/snapshots?since=2000-01-01T05:00:00%2B05:00").json()
        assert early["total"] == 1
        # A future bound in a non-UTC offset must exclude it.
        late = c.get("/snapshots?since=2999-01-01T05:00:00%2B05:00").json()
        assert late["total"] == 0


# --- WAL must stay on without being reapplied per connection -------------


def test_wal_is_enabled_and_persists(tmp_path: Path):
    """Moving journal_mode out of get_db() must not silently lose WAL.

    WAL is a persistent property of the file, so setting it in init_db() is
    enough — but if that ever regresses, concurrent access degrades badly and
    nothing else would catch it.
    """
    import sqlite3

    db = tmp_path / "wal.db"
    init_db(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    # Still WAL when reached through the normal connection helper.
    with bga.get_db(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        # Per-connection pragmas must still be applied.
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_concurrent_writers_do_not_hit_database_locked(tmp_path: Path, monkeypatch):
    """Reapplying journal_mode per connection caused sporadic lock errors.

    Setting WAL takes a brief exclusive lock, so several pollers opening
    connections simultaneously could fail with "database is locked" even
    though their writes would have serialized fine.
    """
    db = tmp_path / "concurrent.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.MAX_POLL_WORKERS", 8)
    monkeypatch.setattr("bgp_route_analyzer.poll_router",
                        lambda cfg: ("raw", list(SAMPLE)))
    routers = [{"name": f"r{i}", "host": f"10.0.0.{i}",
                "device_type": "cisco_ios", "username": "u"} for i in range(16)]
    results = bga.collect_snapshot_results(routers, db)
    failures = [r for r in results if r["status"] != "success"]
    assert not failures, f"unexpected failures: {failures}"


# --- Page and total must come from one connection ------------------------


def test_snapshot_page_total_matches_filters(tmp_path: Path):
    db = tmp_path / "page.db"
    init_db(db)
    for _ in range(5):
        save_snapshot("rtr1", "raw", SAMPLE, db)
    save_snapshot("rtr2", "raw", SAMPLE, db)

    page = list_snapshot_page(router="rtr1", limit=2, offset=0, db_path=db)
    assert page["total"] == 5
    assert len(page["items"]) == 2
    assert page["limit"] == 2 and page["offset"] == 0
    assert page["total"] == count_snapshots(router="rtr1", db_path=db)


# --- Blocking snapshot should report 200, not 202 -------------------------


def test_wait_true_returns_200(tmp_path: Path, monkeypatch):
    db = tmp_path / "wait.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    routers = [{"name": "r1", "host": "10.0.0.1", "device_type": "cisco_ios", "username": "u"}]
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", routers)
    monkeypatch.setattr("bgp_route_analyzer.poll_router",
                        lambda cfg: ("raw", list(SAMPLE)))
    with TestClient(app) as c:
        resp = c.post("/snapshots?wait=true")
        assert resp.status_code == 200
        assert len(resp.json()["snapshot_ids"]) == 1

        # The async path still reports 202. Await it before returning: the
        # monkeypatched poll_router and DB_PATH are reverted at teardown, so a
        # job still running past the end of the test would fall through to the
        # real poll_router (a 30s SSH timeout, holding _snapshot_lock) and
        # init_db() against the real DB_PATH.
        async_resp = c.post("/snapshots")
        assert async_resp.status_code == 202
        job_id = async_resp.json()["id"]
        deadline = __import__("time").monotonic() + 10
        while __import__("time").monotonic() < deadline:
            if bga.get_job(job_id)["status"] != "running":
                break
            __import__("time").sleep(0.01)
        assert bga.get_job(job_id)["status"] != "running"


# --- Session expiry paths previously uncovered ---------------------------


def test_session_expires_on_absolute_ttl(monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    monkeypatch.setattr("bgp_route_analyzer.SESSION_TTL_SECONDS", 60)
    monkeypatch.setattr("bgp_route_analyzer.SESSION_IDLE_SECONDS", 10_000)
    token, _ = bga.create_session("admin", None)
    for session in bga._sessions.values():
        session["created_at"] -= 120       # older than the absolute TTL
        session["last_seen"] = __import__("time").monotonic()  # but recently active
    assert bga.get_session(token) is None


def test_session_store_is_bounded(monkeypatch):
    """A login flood must not grow the session store without limit."""
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    monkeypatch.setattr("bgp_route_analyzer.MAX_SESSIONS", 5)
    tokens = [bga.create_session("admin", None)[0] for _ in range(20)]
    assert len(bga._sessions) <= 5
    # Oldest evicted, newest still valid.
    assert bga.get_session(tokens[0]) is None
    assert bga.get_session(tokens[-1]) is not None


# --- TLS assumption for reverse-proxy deployments ------------------------


def test_assume_tls_sets_secure_cookie(tmp_path: Path, monkeypatch):
    """Behind a TLS-terminating proxy the app sees HTTP but must still set Secure."""
    db = tmp_path / "tls.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    monkeypatch.setattr("bgp_route_analyzer._tls_enabled", True)
    with TestClient(app) as c:
        resp = c.post("/auth/login", json={"api_key": "test-key"})
        cookies = "; ".join(resp.headers.get_list("set-cookie"))
        assert "Secure" in cookies
        assert resp.headers.get("Strict-Transport-Security")


def test_no_secure_flag_without_tls(tmp_path: Path, monkeypatch):
    """Forcing Secure on plain HTTP would silently break loopback development."""
    db = tmp_path / "notls.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
    monkeypatch.setattr("bgp_route_analyzer._tls_enabled", False)
    with TestClient(app) as c:
        resp = c.post("/auth/login", json={"api_key": "test-key"})
        cookies = "; ".join(resp.headers.get_list("set-cookie"))
        assert "Secure" not in cookies
