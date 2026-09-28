import time
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_monitoring_interfaces():
    resp = client.get("/api/v1/monitoring/interfaces")
    assert resp.status_code == 200
    assert "permitted_interfaces" in resp.json()

def test_monitoring_lifecycle():
    # Check status
    status_resp = client.get("/api/v1/monitoring/status")
    assert status_resp.status_code == 200
    
    # Start on test0 simulated interface
    start_resp = client.post("/api/v1/monitoring/start", json={"interface": "test0", "dataset": "cicids2017"})
    assert start_resp.status_code == 200
    assert start_resp.json()["status"] in ["started", "already_running"]

    # Wait briefly for worker cycle
    time.sleep(1.2)

    # Check live flows
    flows_resp = client.get("/api/v1/monitoring/flows?limit=10")
    assert flows_resp.status_code == 200

    # Stop monitoring
    stop_resp = client.post("/api/v1/monitoring/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] in ["stopped", "not_running"]
