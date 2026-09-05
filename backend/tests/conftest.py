from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from socwerk.config import Settings
from socwerk.main import create_app


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    repository_root = Path(__file__).resolve().parents[2]
    settings = Settings(
        data_dir=repository_root / "scenarios",
        database_path=tmp_path / "test.db",
        allowed_origins=("http://localhost:5173",),
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def start(client: TestClient, scenario_id: str = "suspicious-login") -> str:
    response = client.post("/api/sessions", json={"scenario_id": scenario_id})
    assert response.status_code == 201
    return response.json()["id"]
