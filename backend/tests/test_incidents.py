from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_incident_management():
    # List incidents
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 200
    incidents = resp.json()

    # If incidents exist, test update and explanation
    if len(incidents) > 0:
        inc_id = incidents[0]["incident_id"]
        
        # Test update incident
        patch_resp = client.patch(
            f"/api/v1/incidents/{inc_id}",
            json={"status": "Investigating", "notes": "Analyst triage in progress", "analyst": "SOC Lead"}
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "Investigating"

        # Test explanation
        exp_resp = client.get(f"/api/v1/incidents/{inc_id}/explanations")
        assert exp_resp.status_code == 200
        assert "explanation" in exp_resp.json()
