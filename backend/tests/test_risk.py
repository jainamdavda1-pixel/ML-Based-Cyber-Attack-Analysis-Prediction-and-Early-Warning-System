import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_calculate_risk():
    response = client.post(
        "/api/v1/risk",
        json={"dataset": "cicids2017", "benign_probability": 0.05}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["attack_probability"] == 0.95
    assert data["risk_score"] == 95.0
    assert data["risk_level"] == "Critical"

def test_early_warning_threshold_info():
    response = client.get("/api/v1/risk/early-warning")
    assert response.status_code == 200
    data = response.json()
    assert data["validation_threshold"] == 0.94
    assert "test_metrics_frozen" in data
