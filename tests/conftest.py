from pathlib import Path

import pytest

from bgp_route_analyzer import init_db


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a temporary database for testing."""
    db = tmp_path / "test.db"
    init_db(db)
    return db
