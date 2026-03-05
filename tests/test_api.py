from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bgp_route_analyzer import app, init_db, save_snapshot


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    db = tmp_path / "api_test.db"
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)  # disable auth for tests
    with TestClient(app) as c:
        yield c


@pytest.fixture
def seeded_client(tmp_path: Path, monkeypatch):
    """Client with pre-seeded snapshot data."""
    db = tmp_path / "api_test.db"
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    init_db(db)

    prefixes_before = [
        {"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"},
    ]
    prefixes_after = [
        {"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65001 65099", "origin": "i"},
        {"network": "192.168.1.0/24", "next_hop": "2.2.2.2", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65002", "origin": "i"},
    ]
    save_snapshot("rtr1", "raw1", prefixes_before, db)
    save_snapshot("rtr1", "raw2", prefixes_after, db)

    with TestClient(app) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


def test_list_snapshots_empty(client):
    resp = client.get("/snapshots")
    assert resp.status_code == 200
    assert resp.json() == []


def test_snapshot_not_found(client):
    resp = client.get("/snapshots/999")
    assert resp.status_code == 404


def test_list_snapshots_with_data(seeded_client):
    resp = seeded_client.get("/snapshots")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_get_snapshot(seeded_client):
    resp = seeded_client.get("/snapshots/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot"]["router"] == "rtr1"
    assert data["prefix_count"] == 1


def test_diff_endpoint(seeded_client):
    resp = seeded_client.get("/diff?before=1&after=2")
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["added"] == 1
    assert data["summary"]["changed"] == 1


def test_diff_not_found(client):
    resp = client.get("/diff?before=999&after=998")
    assert resp.status_code == 404


def test_list_snapshots_router_filter(seeded_client):
    resp = seeded_client.get("/snapshots?router=rtr1")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    resp = seeded_client.get("/snapshots?router=nonexistent")
    assert resp.status_code == 200
    assert len(resp.json()) == 0


def test_list_snapshots_invalid_router_name(client):
    resp = client.get("/snapshots?router=;DROP TABLE")
    assert resp.status_code == 422  # validation error


def test_post_snapshots_no_routers(client, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [])
    resp = client.post("/snapshots")
    assert resp.status_code == 503


def test_api_key_auth_required(tmp_path: Path, monkeypatch):
    db = tmp_path / "auth_test.db"
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-secret-key")

    with TestClient(app) as c:
        # No key -> 403
        resp = c.get("/health")
        assert resp.status_code == 403

        # Wrong key -> 403
        resp = c.get("/health", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 403

        # Correct key -> 200
        resp = c.get("/health", headers={"X-API-Key": "test-secret-key"})
        assert resp.status_code == 200


# --- New tests for security findings ---


def test_security_headers_present(client):
    """[H3] All responses should include security headers."""
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Content-Security-Policy"] == "default-src 'none'"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_snapshot_lock_prevents_concurrent(client, monkeypatch):
    """[H2] Second concurrent snapshot request should return 429."""
    from bgp_route_analyzer import _snapshot_lock

    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [{"name": "test"}])
    # Acquire the lock to simulate an in-progress snapshot
    _snapshot_lock.acquire()
    try:
        resp = client.post("/snapshots")
        assert resp.status_code == 429
        assert "already in progress" in resp.json()["detail"]
    finally:
        _snapshot_lock.release()


def test_docs_disabled_by_default(client):
    """[L2] OpenAPI docs should be disabled by default."""
    resp = client.get("/docs")
    assert resp.status_code == 404

    resp = client.get("/redoc")
    assert resp.status_code == 404


# --- New tests for operational findings ---


def test_snapshot_id_zero_rejected(client):
    """[O-M1] Zero snapshot ID should be rejected."""
    resp = client.get("/snapshots/0")
    assert resp.status_code == 422


def test_snapshot_id_negative_rejected(client):
    """[O-M1] Negative snapshot ID should be rejected."""
    resp = client.get("/snapshots/-1")
    assert resp.status_code == 422


def test_diff_before_equals_after(seeded_client):
    """[O-M3] Diffing a snapshot against itself should return 400."""
    resp = seeded_client.get("/diff?before=1&after=1")
    assert resp.status_code == 400
    assert "different" in resp.json()["detail"]


def test_diff_negative_ids_rejected(client):
    """[O-M1] Negative diff IDs should be rejected."""
    resp = client.get("/diff?before=-1&after=2")
    assert resp.status_code == 422

    resp = client.get("/diff?before=1&after=0")
    assert resp.status_code == 422


def test_get_snapshot_response_shape(seeded_client):
    """[O-M2] Response should match SnapshotDetailResponse model."""
    resp = seeded_client.get("/snapshots/1")
    assert resp.status_code == 200
    data = resp.json()
    assert "snapshot" in data
    assert "prefix_count" in data
    assert "prefixes" in data
    assert "id" in data["snapshot"]
    assert "router" in data["snapshot"]
    assert "captured_at" in data["snapshot"]


def test_list_snapshots_response_shape(seeded_client):
    """[O-M2] List response should match SnapshotListItem model."""
    resp = seeded_client.get("/snapshots")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    item = data[0]
    assert "id" in item
    assert "router" in item
    assert "captured_at" in item
