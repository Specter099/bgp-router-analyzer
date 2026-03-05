import json
import pytest
from pathlib import Path

from bgp_route_analyzer import _load_routers, _validate_cors_origins


class TestLoadRouters:
    """[C3] Router config schema validation tests."""

    def test_valid_config(self, tmp_path: Path):
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "cisco_ios",
            "name": "rtr1",
            "username": "admin",
            "password": "secret",
            "ssh_strict": True,
        }]))
        routers = _load_routers(str(config))
        assert len(routers) == 1
        assert routers[0]["name"] == "rtr1"

    def test_missing_required_field(self, tmp_path: Path):
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "cisco_ios",
            # missing "name"
        }]))
        with pytest.raises(ValueError, match="missing required field: name"):
            _load_routers(str(config))

    def test_unknown_fields_rejected(self, tmp_path: Path):
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "cisco_ios",
            "name": "rtr1",
            "evil_param": "injected",
        }]))
        with pytest.raises(ValueError, match="unknown fields"):
            _load_routers(str(config))

    def test_unsupported_device_type(self, tmp_path: Path):
        """[M5] Invalid device_type should be rejected."""
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "not_a_real_device",
            "name": "rtr1",
        }]))
        with pytest.raises(ValueError, match="unsupported device_type"):
            _load_routers(str(config))

    def test_nonexistent_file_returns_empty(self):
        routers = _load_routers("/nonexistent/path/routers.json")
        assert routers == []

    def test_not_a_list_rejected(self, tmp_path: Path):
        config = tmp_path / "routers.json"
        config.write_text(json.dumps({"host": "10.0.0.1"}))
        with pytest.raises(ValueError, match="must be a JSON array"):
            _load_routers(str(config))

    def test_password_env_override(self, tmp_path: Path, monkeypatch):
        """[C4] BGP_ROUTER_PASSWORD should fill in missing passwords."""
        monkeypatch.setenv("BGP_ROUTER_PASSWORD", "env-secret")
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "cisco_ios",
            "name": "rtr1",
        }]))
        routers = _load_routers(str(config))
        assert routers[0]["password"] == "env-secret"

    def test_password_env_does_not_override_explicit(self, tmp_path: Path, monkeypatch):
        """[C4] Explicit password in config should not be overridden by env var."""
        monkeypatch.setenv("BGP_ROUTER_PASSWORD", "env-secret")
        config = tmp_path / "routers.json"
        config.write_text(json.dumps([{
            "host": "10.0.0.1",
            "device_type": "cisco_ios",
            "name": "rtr1",
            "password": "config-secret",
        }]))
        routers = _load_routers(str(config))
        assert routers[0]["password"] == "config-secret"


class TestValidateCorsOrigins:
    """[M7] CORS origin validation tests."""

    def test_valid_origins(self):
        origins = _validate_cors_origins(["https://example.com", "http://localhost:3000"])
        assert len(origins) == 2

    def test_invalid_origin_rejected(self):
        origins = _validate_cors_origins(["not-a-url", "https://valid.com"])
        assert len(origins) == 1
        assert origins[0] == "https://valid.com"

    def test_wildcard_rejected_with_api_key(self, monkeypatch):
        monkeypatch.setattr("bgp_route_analyzer.API_KEY", "test-key")
        origins = _validate_cors_origins(["*", "https://valid.com"])
        assert "*" not in origins
        assert "https://valid.com" in origins

    def test_wildcard_allowed_without_api_key(self, monkeypatch):
        monkeypatch.setattr("bgp_route_analyzer.API_KEY", None)
        origins = _validate_cors_origins(["*"])
        assert origins == ["*"]
