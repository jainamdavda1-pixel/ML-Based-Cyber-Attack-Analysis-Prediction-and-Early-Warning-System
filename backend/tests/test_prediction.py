import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_single_prediction_cicids():
    payload = {
        "dataset": "cicids2017",
        "features": {
            "Destination Port": 80,
            "Flow Duration": 1200,
            "Total Fwd Packets": 5
        }
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "prediction" in data
    assert "is_attack" in data
    assert "risk_score" in data
    assert "risk_level" in data

def test_metrics_endpoint():
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "cicids2017" in data
    assert "unsw_nb15" in data
