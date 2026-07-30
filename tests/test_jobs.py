"""Background snapshot jobs, parallel polling, and router inventory."""

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bgp_route_analyzer import (
    _snapshot_lock,
    app,
    collect_snapshot_results,
    count_snapshots,
    get_job,
    init_db,
    list_snapshots,
    record_audit,
    router_inventory,
    save_snapshot,
    start_snapshot_job,
)

ROUTERS = [
    {"name": "rtr1", "host": "10.0.0.1", "device_type": "cisco_ios", "username": "u"},
    {"name": "rtr2", "host": "10.0.0.2", "device_type": "cisco_ios", "username": "u"},
    {"name": "rtr3", "host": "edge.core.example.com", "device_type": "arista_eos", "username": "u"},
]

SAMPLE_PREFIXES = [
    {"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
     "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"},
]


@pytest.fixture
def job_db(tmp_path: Path, monkeypatch) -> Path:
    db = tmp_path / "jobs.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", list(ROUTERS))
    monkeypatch.setattr("bgp_route_analyzer._jobs", __import__("collections").OrderedDict())
    return db


def _fake_poll(delay: float = 0.0, fail_on: set[str] | None = None):
    """Build a poll_router stand-in that never touches the network."""
    fail_on = fail_on or set()

    def _poll(cfg: dict):
        if delay:
            time.sleep(delay)
        if cfg["name"] in fail_on:
            raise RuntimeError(f"Timeout connecting to {cfg['name']}")
        return f"raw output for {cfg['name']}", list(SAMPLE_PREFIXES)

    return _poll


# --- Parallel polling ---------------------------------------------------


def test_collect_results_covers_every_router(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    results = collect_snapshot_results(list(ROUTERS), job_db)
    assert [r["router"] for r in results] == ["rtr1", "rtr2", "rtr3"]
    assert all(r["status"] == "success" for r in results)
    assert all(r["snapshot_id"] is not None for r in results)


def test_one_failing_router_does_not_abort_others(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll(fail_on={"rtr2"}))
    results = collect_snapshot_results(list(ROUTERS), job_db)
    by_name = {r["router"]: r for r in results}
    assert by_name["rtr2"]["status"] == "failed"
    assert "Timeout" in by_name["rtr2"]["error"]
    assert by_name["rtr1"]["status"] == "success"
    assert by_name["rtr3"]["status"] == "success"


def test_polling_runs_concurrently(job_db, monkeypatch):
    """All three routers must be in flight at once, not polled one after another.

    Asserted by observing overlap rather than wall-clock time: a timing budget
    turns into a flaky test on a loaded CI runner.
    """
    monkeypatch.setattr("bgp_route_analyzer.MAX_POLL_WORKERS", 3)
    barrier = threading.Barrier(3, timeout=10)

    def _poll(cfg):
        # Only passes if all three threads reach this point together; a serial
        # implementation would deadlock here and raise BrokenBarrierError.
        barrier.wait()
        return "raw", list(SAMPLE_PREFIXES)

    monkeypatch.setattr("bgp_route_analyzer.poll_router", _poll)
    results = collect_snapshot_results(list(ROUTERS), job_db)
    assert [r["status"] for r in results] == ["success"] * 3


def test_worker_pool_is_bounded(job_db, monkeypatch):
    """Never exceed MAX_POLL_WORKERS concurrent SSH sessions."""
    monkeypatch.setattr("bgp_route_analyzer.MAX_POLL_WORKERS", 2)
    active = 0
    peak = 0
    lock = threading.Lock()

    def _poll(cfg):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return "raw", list(SAMPLE_PREFIXES)

    monkeypatch.setattr("bgp_route_analyzer.poll_router", _poll)
    collect_snapshot_results(list(ROUTERS), job_db)
    assert peak <= 2


def test_shutdown_event_stops_dispatch(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    event = threading.Event()
    event.set()
    monkeypatch.setattr("bgp_route_analyzer._shutdown_event", event)
    assert collect_snapshot_results(list(ROUTERS), job_db) == []


def test_poll_failures_are_audited(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll(fail_on={"rtr2"}))
    collect_snapshot_results(list(ROUTERS), job_db)
    from bgp_route_analyzer import list_audit_log

    entries, _ = list_audit_log(action="poll_router", db_path=job_db)
    failures = [e for e in entries if e["outcome"] == "failure"]
    assert len(failures) == 1
    assert failures[0]["target"] == "rtr2"


# --- Job lifecycle ------------------------------------------------------


def _await_job(job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = get_job(job_id)
        assert job is not None
        if job["status"] != "running":
            return job
        time.sleep(0.01)
    raise AssertionError(f"Job {job_id} did not finish within {timeout}s")


def test_job_completes_and_reports_per_router_results(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll(fail_on={"rtr3"}))
    job = start_snapshot_job(list(ROUTERS), job_db, actor="admin")
    assert job["status"] == "running"
    assert job["total"] == 3

    final = _await_job(job["id"])
    assert final["status"] == "completed"
    assert final["completed"] == 3
    assert final["succeeded"] == 2
    assert final["failed"] == 1
    assert len(final["snapshot_ids"]) == 2
    assert final["finished_at"] is not None


def test_job_releases_lock_when_done(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    job = start_snapshot_job(list(ROUTERS), job_db)
    _await_job(job["id"])
    assert _snapshot_lock.acquire(blocking=False)
    _snapshot_lock.release()


def test_concurrent_job_rejected(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll(delay=0.2))
    job = start_snapshot_job(list(ROUTERS), job_db)
    with pytest.raises(RuntimeError, match="already running"):
        start_snapshot_job(list(ROUTERS), job_db)
    _await_job(job["id"])


def test_job_history_is_bounded(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    monkeypatch.setattr("bgp_route_analyzer.MAX_JOB_HISTORY", 2)
    ids = []
    for _ in range(4):
        job = start_snapshot_job(list(ROUTERS), job_db)
        ids.append(job["id"])
        _await_job(job["id"])
    from bgp_route_analyzer import _jobs

    assert len(_jobs) == 2
    assert get_job(ids[0]) is None
    assert get_job(ids[-1]) is not None


# --- Job API ------------------------------------------------------------


def test_post_snapshots_returns_202_with_job(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    with TestClient(app) as c:
        resp = c.post("/snapshots")
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "running"
        final = _await_job(body["id"])
        assert final["status"] == "completed"

        status = c.get(f"/jobs/{body['id']}")
        assert status.status_code == 200
        assert status.json()["succeeded"] == 3


def test_post_snapshots_wait_returns_legacy_shape(job_db, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.poll_router", _fake_poll())
    with TestClient(app) as c:
        resp = c.post("/snapshots?wait=true")
        # 200, not 202: the work is already done by the time this returns.
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["snapshot_ids"]) == 3
        assert "Captured 3" in body["message"]


def test_job_not_found(job_db):
    with TestClient(app) as c:
        assert c.get(f"/jobs/{'a' * 32}").status_code == 404


def test_job_id_must_be_hex(job_db):
    with TestClient(app) as c:
        assert c.get("/jobs/not-a-job-id").status_code == 422


# --- Router inventory ---------------------------------------------------


def test_inventory_reports_never_polled(job_db):
    inventory = router_inventory(list(ROUTERS), job_db)
    assert [r["status"] for r in inventory] == ["never_polled"] * 3
    assert all(r["prefix_count"] is None for r in inventory)


def test_inventory_reports_counts_and_delta(job_db):
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES * 3, job_db)
    entry = {r["name"]: r for r in router_inventory(list(ROUTERS), job_db)}["rtr1"]
    assert entry["status"] == "ok"
    assert entry["prefix_count"] == 3
    assert entry["previous_prefix_count"] == 1
    assert entry["prefix_delta"] == 2


def test_inventory_surfaces_last_error(job_db):
    save_snapshot("rtr2", "raw", SAMPLE_PREFIXES, job_db)
    record_audit("poll_router", actor="admin", outcome="failure",
                 target="rtr2", detail="Timeout connecting to rtr2", db_path=job_db)
    entry = {r["name"]: r for r in router_inventory(list(ROUTERS), job_db)}["rtr2"]
    assert entry["status"] == "error"
    assert "Timeout" in entry["last_error"]


def test_error_outranks_never_polled(job_db):
    """A router that has only ever failed must read as broken, not untouched."""
    record_audit("poll_router", actor="admin", outcome="failure",
                 target="rtr3", detail="Timeout connecting to rtr3", db_path=job_db)
    entry = {r["name"]: r for r in router_inventory(list(ROUTERS), job_db)}["rtr3"]
    assert entry["status"] == "error"
    assert entry["last_snapshot_id"] is None


def test_recovery_clears_error_status(job_db):
    """A successful poll after a failure returns the router to ok."""
    record_audit("poll_router", actor="admin", outcome="failure",
                 target="rtr1", detail="boom", db_path=job_db)
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)
    entry = {r["name"]: r for r in router_inventory(list(ROUTERS), job_db)}["rtr1"]
    assert entry["status"] == "ok"


def test_inventory_never_leaks_credentials(job_db):
    routers = [{**ROUTERS[0], "password": "hunter2", "key_file": "/root/.ssh/id_rsa"}]
    payload = str(router_inventory(routers, job_db))
    assert "hunter2" not in payload
    assert "id_rsa" not in payload
    # Full host address is masked too — addresses are DEBUG-only [M3].
    assert "10.0.0.1" not in payload


def test_inventory_masks_hosts(job_db):
    inventory = {r["name"]: r for r in router_inventory(list(ROUTERS), job_db)}
    assert inventory["rtr1"]["host_masked"] == "10.0.x.x"
    assert inventory["rtr3"]["host_masked"] == "edge.…example.com"


def test_routers_endpoint(job_db):
    with TestClient(app) as c:
        resp = c.get("/routers")
        assert resp.status_code == 200
        assert [r["name"] for r in resp.json()] == ["rtr1", "rtr2", "rtr3"]


# --- Pagination ---------------------------------------------------------


def test_snapshot_pagination(job_db):
    for _ in range(5):
        save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)

    assert count_snapshots(db_path=job_db) == 5
    page1 = list_snapshots(limit=2, offset=0, db_path=job_db)
    page2 = list_snapshots(limit=2, offset=2, db_path=job_db)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})
    # Newest first
    assert page1[0]["id"] > page2[0]["id"]


def test_snapshot_list_includes_prefix_count(job_db):
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES * 4, job_db)
    assert list_snapshots(db_path=job_db)[0]["prefix_count"] == 4


def test_snapshot_date_filter(job_db):
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)
    assert count_snapshots(since="2000-01-01T00:00:00+00:00", db_path=job_db) == 1
    assert count_snapshots(since="2999-01-01T00:00:00+00:00", db_path=job_db) == 0
    assert count_snapshots(until="2000-01-01T00:00:00+00:00", db_path=job_db) == 0


def test_snapshot_list_endpoint_pagination(job_db):
    for _ in range(3):
        save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)
    with TestClient(app) as c:
        body = c.get("/snapshots?limit=2&offset=1").json()
        assert body["total"] == 3
        assert body["offset"] == 1
        assert len(body["items"]) == 2


def test_invalid_date_filter_rejected(job_db):
    with TestClient(app) as c:
        assert c.get("/snapshots?since=not-a-date").status_code == 422


def test_prefix_pagination_in_snapshot_detail(job_db):
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES * 10, job_db)
    with TestClient(app) as c:
        body = c.get("/snapshots/1?prefix_limit=3&prefix_offset=0").json()
        assert body["prefix_count"] == 10       # total, not page size
        assert len(body["prefixes"]) == 3
        assert body["prefix_limit"] == 3


def test_diff_flags_cross_router_comparison(job_db):
    save_snapshot("rtr1", "raw", SAMPLE_PREFIXES, job_db)
    save_snapshot("rtr2", "raw", SAMPLE_PREFIXES, job_db)
    with TestClient(app) as c:
        body = c.get("/diff?before=1&after=2").json()
        assert body["cross_router"] is True
        assert body["before_router"] == "rtr1"
        assert body["after_router"] == "rtr2"
