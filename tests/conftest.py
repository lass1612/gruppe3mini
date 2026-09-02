from __future__ import annotations

import pytest

import app as app_module
from database import Database


@pytest.fixture
def test_app(tmp_path, monkeypatch):
    test_database = Database(tmp_path / "test.db")
    monkeypatch.setattr(app_module, "db", test_database)
    monkeypatch.delenv("IP_SENTINEL_USER", raising=False)
    monkeypatch.delenv("IP_SENTINEL_PASSWORD", raising=False)
    app_module.app.config.update(TESTING=True)

    app_module.stop_schedule_internal()
    yield app_module.app
    app_module.stop_schedule_internal()


@pytest.fixture
def client(test_app):
    return test_app.test_client()
