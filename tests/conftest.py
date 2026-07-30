from pathlib import Path

import pytest

from bgp_route_analyzer import init_db, limiter


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a temporary database for testing."""
    db = tmp_path / "test.db"
    init_db(db)
    return db


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear rate-limit state between tests.

    slowapi keys buckets by client IP and TestClient always presents as
    "testclient", so without this every test in a module shares one bucket and
    later tests fail with 429 depending on execution order.
    """
    storage = getattr(limiter, "_storage", None)
    if storage is not None and hasattr(storage, "reset"):
        storage.reset()
    yield


@pytest.fixture(autouse=True)
def clear_sessions(monkeypatch):
    """Give every test an isolated in-memory session store."""
    monkeypatch.setattr("bgp_route_analyzer._sessions", {})
    yield
