import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.ml.model_registry import model_registry

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "models_status" in data

def test_available_models():
    response = client.get("/api/v1/models")
    assert response.status_code == 200
    data = response.json()
    assert "datasets" in data
    dataset_ids = [d["id"] for d in data["datasets"]]
    assert "cicids2017" in dataset_ids
    assert "unsw-nb15" in dataset_ids

def test_model_registry_readiness():
    readiness = model_registry.get_readiness()
    assert "cicids2017" in readiness
    assert "unsw-nb15" in readiness
    assert readiness["cicids2017"]["ready"] is True
    assert readiness["unsw-nb15"]["ready"] is True
