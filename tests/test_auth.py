"""Session authentication, CSRF, and audit-trail tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bgp_route_analyzer import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    app,
    create_session,
    destroy_session,
    get_session,
    init_db,
    list_audit_log,
    record_audit,
)

KEY = "test-secret-key"


@pytest.fixture
def auth_client(tmp_path: Path, monkeypatch):
    """Client with API key auth enabled and a clean session store."""
    db = tmp_path / "auth.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", KEY)
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [])
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    with TestClient(app) as c:
        yield c


# --- Session store ------------------------------------------------------


def test_session_roundtrip(monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    token, csrf = create_session("admin", "1.2.3.4")
    session = get_session(token)
    assert session is not None
    assert session["actor"] == "admin"
    assert session["csrf"] == csrf
    assert destroy_session(token) is True
    assert get_session(token) is None


def test_session_token_not_stored_raw(monkeypatch):
    """Raw tokens must never sit in memory — only their digest."""
    store: dict = {}
    monkeypatch.setattr("bgp_route_analyzer._sessions", store)
    token, _ = create_session("admin", None)
    assert token not in store
    assert len(store) == 1


def test_session_expires_on_idle(monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    monkeypatch.setattr("bgp_route_analyzer.SESSION_IDLE_SECONDS", 60)
    token, _ = create_session("admin", None)
    # Push last_seen far enough into the past to trip the idle timeout.
    store = __import__("bgp_route_analyzer")._sessions
    for session in store.values():
        session["last_seen"] -= 120
    assert get_session(token) is None


def test_unknown_token_rejected(monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    assert get_session("not-a-real-token") is None
    assert get_session(None) is None


# --- Login / logout -----------------------------------------------------


def test_login_sets_httponly_cookie(auth_client):
    resp = auth_client.post("/auth/login", json={"api_key": KEY})
    assert resp.status_code == 200
    assert resp.json()["actor"] == "admin"

    cookie_header = "; ".join(resp.headers.get_list("set-cookie"))
    assert SESSION_COOKIE_NAME in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header.replace("samesite", "SameSite")


def test_login_wrong_key_rejected(auth_client):
    resp = auth_client.post("/auth/login", json={"api_key": "wrong"})
    assert resp.status_code == 403
    assert SESSION_COOKIE_NAME not in auth_client.cookies


def test_login_grants_access_to_protected_endpoint(auth_client):
    # Unauthenticated read is refused.
    assert auth_client.get("/snapshots").status_code == 403
    # After login the cookie alone is enough for a GET.
    assert auth_client.post("/auth/login", json={"api_key": KEY}).status_code == 200
    assert auth_client.get("/snapshots").status_code == 200


def test_logout_invalidates_session(auth_client):
    login = auth_client.post("/auth/login", json={"api_key": KEY})
    csrf = login.json()["csrf_token"]
    assert auth_client.get("/snapshots").status_code == 200

    assert auth_client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert auth_client.get("/snapshots").status_code == 403


def test_auth_status_reports_state(auth_client):
    before = auth_client.get("/auth/status").json()
    assert before["auth_required"] is True
    assert before["authenticated"] is False

    auth_client.post("/auth/login", json={"api_key": KEY})
    after = auth_client.get("/auth/status").json()
    assert after["authenticated"] is True
    assert after["actor"] == "admin"
    assert after["csrf_token"]


def test_auth_status_when_auth_disabled(tmp_path: Path, monkeypatch):
    db = tmp_path / "noauth.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    with TestClient(app) as c:
        body = c.get("/auth/status").json()
    assert body["auth_required"] is False
    assert body["authenticated"] is True


def test_login_unavailable_when_no_key_configured(tmp_path: Path, monkeypatch):
    db = tmp_path / "noauth.db"
    init_db(db)
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", db)
    monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
    with TestClient(app) as c:
        assert c.post("/auth/login", json={"api_key": "x"}).status_code == 503


# --- CSRF ---------------------------------------------------------------


def test_mutation_without_csrf_token_rejected(auth_client, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [{"name": "r1"}])
    auth_client.post("/auth/login", json={"api_key": KEY})
    # Session cookie is attached automatically; no CSRF header supplied.
    resp = auth_client.post("/snapshots")
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]


def test_mutation_with_wrong_csrf_token_rejected(auth_client, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [{"name": "r1"}])
    auth_client.post("/auth/login", json={"api_key": KEY})
    resp = auth_client.post("/snapshots", headers={"X-CSRF-Token": "bogus"})
    assert resp.status_code == 403


def test_get_requests_need_no_csrf_token(auth_client):
    auth_client.post("/auth/login", json={"api_key": KEY})
    assert auth_client.get("/snapshots").status_code == 200


def test_api_key_header_bypasses_csrf(auth_client, monkeypatch):
    """Scripts using X-API-Key are not CSRF-exposed and must keep working."""
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [])
    resp = auth_client.post("/snapshots", headers={"X-API-Key": KEY})
    # 503 (no routers) proves it got past auth without a CSRF token.
    assert resp.status_code == 503


def test_csrf_cookie_is_readable_by_js(auth_client):
    """The CSRF cookie must NOT be HttpOnly — the SPA has to read it."""
    resp = auth_client.post("/auth/login", json={"api_key": KEY})
    csrf_cookie = [c for c in resp.headers.get_list("set-cookie") if CSRF_COOKIE_NAME in c]
    assert csrf_cookie
    assert "HttpOnly" not in csrf_cookie[0]


# --- Audit log ----------------------------------------------------------


def test_login_success_and_failure_are_audited(auth_client, tmp_path: Path):
    auth_client.post("/auth/login", json={"api_key": "wrong"})
    auth_client.post("/auth/login", json={"api_key": KEY})

    entries, total = list_audit_log(action="login")
    assert total == 2
    outcomes = {e["outcome"] for e in entries}
    assert outcomes == {"success", "failure"}


def test_audit_endpoint_paginates(auth_client):
    for i in range(5):
        record_audit("snapshot", actor="admin", detail=f"entry {i}")
    auth_client.post("/auth/login", json={"api_key": KEY})

    resp = auth_client.get("/audit?action=snapshot&limit=2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2
    assert body["limit"] == 2


def test_audit_write_failure_does_not_raise(monkeypatch):
    """Auditing is best-effort and must never break the audited operation."""
    monkeypatch.setattr("bgp_route_analyzer.DB_PATH", Path("/nonexistent/dir/x.db"))
    record_audit("snapshot", actor="admin")  # must not raise


def test_csrf_failure_is_audited(auth_client, monkeypatch):
    monkeypatch.setattr("bgp_route_analyzer.ROUTERS", [{"name": "r1"}])
    auth_client.post("/auth/login", json={"api_key": KEY})
    auth_client.post("/snapshots")  # no CSRF header

    entries, total = list_audit_log(action="csrf_failure")
    assert total == 1
    assert entries[0]["outcome"] == "failure"
