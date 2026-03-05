from datetime import datetime, timedelta, timezone
from pathlib import Path

from bgp_route_analyzer import (
    _load_prefix_map,
    _snapshot_info,
    init_db,
    list_snapshots,
    purge_old_snapshots,
    save_snapshot,
)


def test_init_db_creates_tables(tmp_path: Path):
    db = tmp_path / "new.db"
    init_db(db)
    assert db.exists()


def test_init_db_idempotent(test_db: Path):
    init_db(test_db)  # second call should not raise
    init_db(test_db)  # third call should not raise


def test_save_and_retrieve_snapshot(test_db: Path):
    prefixes = [
        {"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"},
    ]
    sid = save_snapshot("rtr1", "raw output here", prefixes, test_db)
    assert sid is not None
    assert sid > 0

    info = _snapshot_info(sid, test_db)
    assert info is not None
    assert info["router"] == "rtr1"


def test_snapshot_info_not_found(test_db: Path):
    assert _snapshot_info(9999, test_db) is None


def test_list_snapshots_returns_newest_first(test_db: Path):
    p = [{"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "",
          "local_pref": "", "weight": "0", "as_path": "", "origin": "i"}]
    save_snapshot("rtr1", "raw1", p, test_db)
    save_snapshot("rtr2", "raw2", p, test_db)
    save_snapshot("rtr3", "raw3", p, test_db)

    rows = list_snapshots(db_path=test_db)
    assert len(rows) == 3
    assert rows[0]["router"] == "rtr3"  # newest first


def test_list_snapshots_filter_by_router(test_db: Path):
    p = [{"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "",
          "local_pref": "", "weight": "0", "as_path": "", "origin": "i"}]
    save_snapshot("rtr1", "raw1", p, test_db)
    save_snapshot("rtr2", "raw2", p, test_db)

    rows = list_snapshots(router="rtr1", db_path=test_db)
    assert len(rows) == 1
    assert rows[0]["router"] == "rtr1"


def test_load_prefix_map_composite_key(test_db: Path):
    prefixes = [
        {"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"},
        {"network": "10.0.0.0/8", "next_hop": "2.2.2.2", "metric": "0",
         "local_pref": "100", "weight": "0", "as_path": "65002", "origin": "i"},
    ]
    sid = save_snapshot("rtr1", "raw", prefixes, test_db)
    pmap = _load_prefix_map(sid, test_db)

    # Both paths should be present (composite key)
    assert len(pmap) == 2
    assert ("10.0.0.0/8", "1.1.1.1") in pmap
    assert ("10.0.0.0/8", "2.2.2.2") in pmap


def test_init_db_sets_file_permissions(tmp_path: Path):
    """[H4] Database file should have restrictive permissions."""
    import os
    import stat
    import sys

    db = tmp_path / "perm_test.db"
    init_db(db)
    if sys.platform != "win32":
        mode = os.stat(db).st_mode
        assert not (mode & stat.S_IRGRP), "DB should not be group-readable"
        assert not (mode & stat.S_IROTH), "DB should not be world-readable"


def test_purge_old_snapshots(test_db: Path):
    """[M8] Purge should delete snapshots older than N days."""
    import sqlite3

    p = [{"network": "10.0.0.0/8", "next_hop": "1.1.1.1", "metric": "0",
          "local_pref": "100", "weight": "0", "as_path": "65001", "origin": "i"}]

    # Insert a snapshot with old timestamp
    old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    with sqlite3.connect(test_db) as conn:
        conn.execute(
            "INSERT INTO snapshots (router, captured_at, raw_output) VALUES (?, ?, ?)",
            ("old_rtr", old_time, "old raw"),
        )
        conn.commit()

    # Insert a recent snapshot normally
    save_snapshot("new_rtr", "new raw", p, test_db)

    # Purge snapshots older than 30 days
    count = purge_old_snapshots(30, db_path=test_db)
    assert count == 1

    # Only the recent snapshot should remain
    rows = list_snapshots(db_path=test_db)
    assert len(rows) == 1
    assert rows[0]["router"] == "new_rtr"
