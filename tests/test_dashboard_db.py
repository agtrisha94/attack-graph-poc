import pytest

from dashboard.db import _driver_config


def test_driver_config_reads_env(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://example:7687")
    monkeypatch.setenv("NEO4J_USER", "test-user")
    monkeypatch.setenv("NEO4J_PASSWORD", "test-pass")

    assert _driver_config() == {
        "uri": "bolt://example:7687", "user": "test-user", "password": "test-pass",
    }


def test_driver_config_defaults_uri_and_user(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("NEO4J_USER", raising=False)
    monkeypatch.setenv("NEO4J_PASSWORD", "test-pass")

    config = _driver_config()

    assert config["uri"] == "bolt://localhost:7687"
    assert config["user"] == "neo4j"


def test_driver_config_requires_password(monkeypatch):
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)

    with pytest.raises(KeyError):
        _driver_config()
