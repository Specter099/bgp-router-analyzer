from pathlib import Path

from bgp_route_analyzer import diff_snapshots, save_snapshot


def _make_prefix(network: str, next_hop: str = "1.1.1.1", **overrides) -> dict:
    base = {
        "network": network,
        "next_hop": next_hop,
        "metric": "0",
        "local_pref": "100",
        "weight": "0",
        "as_path": "65001",
        "origin": "i",
    }
    base.update(overrides)
    return base


def test_diff_detects_added_prefix(test_db: Path):
    id1 = save_snapshot("rtr1", "raw1", [_make_prefix("10.0.0.0/8")], test_db)
    id2 = save_snapshot("rtr1", "raw2", [
        _make_prefix("10.0.0.0/8"),
        _make_prefix("192.168.1.0/24", "2.2.2.2"),
    ], test_db)

    result = diff_snapshots(id1, id2, test_db)
    assert result["summary"]["added"] == 1
    assert result["summary"]["removed"] == 0
    assert result["added"][0]["network"] == "192.168.1.0/24"


def test_diff_detects_removed_prefix(test_db: Path):
    id1 = save_snapshot("rtr1", "raw1", [
        _make_prefix("10.0.0.0/8"),
        _make_prefix("172.16.0.0/12", "2.2.2.2"),
    ], test_db)
    id2 = save_snapshot("rtr1", "raw2", [_make_prefix("10.0.0.0/8")], test_db)

    result = diff_snapshots(id1, id2, test_db)
    assert result["summary"]["removed"] == 1
    assert result["removed"][0]["network"] == "172.16.0.0/12"


def test_diff_detects_changed_attribute(test_db: Path):
    id1 = save_snapshot("rtr1", "raw1", [_make_prefix("10.0.0.0/8", as_path="65001")], test_db)
    id2 = save_snapshot("rtr1", "raw2", [_make_prefix("10.0.0.0/8", as_path="65001 65099")], test_db)

    result = diff_snapshots(id1, id2, test_db)
    assert result["summary"]["changed"] == 1
    assert result["changed"][0]["network"] == "10.0.0.0/8"
    assert result["changed"][0]["changes"]["as_path"]["before"] == "65001"
    assert result["changed"][0]["changes"]["as_path"]["after"] == "65001 65099"


def test_diff_no_changes(test_db: Path):
    prefixes = [_make_prefix("10.0.0.0/8"), _make_prefix("172.16.0.0/12", "2.2.2.2")]
    id1 = save_snapshot("rtr1", "raw1", prefixes, test_db)
    id2 = save_snapshot("rtr1", "raw2", prefixes, test_db)

    result = diff_snapshots(id1, id2, test_db)
    assert result["summary"]["added"] == 0
    assert result["summary"]["removed"] == 0
    assert result["summary"]["changed"] == 0


def test_diff_handles_multi_path(test_db: Path):
    """Multiple paths for the same network should be tracked independently."""
    id1 = save_snapshot("rtr1", "raw1", [
        _make_prefix("10.0.0.0/8", "1.1.1.1"),
        _make_prefix("10.0.0.0/8", "2.2.2.2"),
    ], test_db)
    id2 = save_snapshot("rtr1", "raw2", [
        _make_prefix("10.0.0.0/8", "1.1.1.1"),
        _make_prefix("10.0.0.0/8", "3.3.3.3"),
    ], test_db)

    result = diff_snapshots(id1, id2, test_db)
    # Path via 2.2.2.2 removed, path via 3.3.3.3 added
    assert result["summary"]["removed"] == 1
    assert result["summary"]["added"] == 1
    assert result["removed"][0]["next_hop"] == "2.2.2.2"
    assert result["added"][0]["next_hop"] == "3.3.3.3"


def test_diff_next_hop_change_shows_as_add_remove(test_db: Path):
    """A next-hop change for a prefix shows as one removed + one added."""
    id1 = save_snapshot("rtr1", "raw1", [_make_prefix("10.0.0.0/8", "1.1.1.1")], test_db)
    id2 = save_snapshot("rtr1", "raw2", [_make_prefix("10.0.0.0/8", "2.2.2.2")], test_db)

    result = diff_snapshots(id1, id2, test_db)
    assert result["summary"]["added"] == 1
    assert result["summary"]["removed"] == 1
    assert result["summary"]["changed"] == 0
