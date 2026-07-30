"""Static admin UI mounting, path containment, and CSP scoping."""

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from bgp_route_analyzer import API_CSP, UI_CSP, mount_ui


@pytest.fixture
def ui_app(tmp_path: Path) -> tuple[FastAPI, Path]:
    """A minimal app with a fake built UI on disk."""
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id='root'></div>")
    (dist / "favicon.svg").write_text("<svg/>")
    (dist / "assets" / "index-abc123.js").write_text("console.log(1)")
    # A secret sitting next to dist — the classic traversal target.
    (tmp_path / "secret.txt").write_text("SUPER SECRET")

    application = FastAPI()
    assert mount_ui(application, dist) is True
    return application, tmp_path


def test_mount_returns_false_without_build(tmp_path: Path):
    """API-only mode when the UI has not been built."""
    assert mount_ui(FastAPI(), tmp_path / "missing") is False


def test_serves_index_at_root_and_ui(ui_app):
    application, _ = ui_app
    with TestClient(application) as c:
        for path in ("/", "/ui"):
            resp = c.get(path)
            assert resp.status_code == 200
            assert "id='root'" in resp.text


def test_client_side_routes_fall_back_to_index(ui_app):
    """Unknown paths are UI routes, not 404s."""
    application, _ = ui_app
    with TestClient(application) as c:
        resp = c.get("/ui/snapshots/42/deep/route")
        assert resp.status_code == 200
        assert "id='root'" in resp.text


def test_serves_real_static_files(ui_app):
    application, _ = ui_app
    with TestClient(application) as c:
        assert c.get("/ui/favicon.svg").text == "<svg/>"
        assert c.get("/ui/assets/index-abc123.js").status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/ui/../secret.txt",
        "/ui/%2e%2e/secret.txt",
        "/ui/..%2fsecret.txt",
        "/ui/a/../../secret.txt",
        "/ui/....//secret.txt",
    ],
)
def test_path_traversal_cannot_escape_dist(ui_app, path):
    """Traversal attempts must never serve a file outside the build dir."""
    application, _ = ui_app
    with TestClient(application) as c:
        resp = c.get(path)
        assert "SUPER SECRET" not in resp.text


def test_ui_csp_allows_own_assets_but_nothing_inline():
    assert "script-src 'self'" in UI_CSP
    assert "style-src 'self'" in UI_CSP
    assert "unsafe-inline" not in UI_CSP
    assert "unsafe-eval" not in UI_CSP
    assert "frame-ancestors 'none'" in UI_CSP


def test_api_csp_stays_locked_down():
    assert API_CSP.startswith("default-src 'none'")
    assert "script-src" not in API_CSP
