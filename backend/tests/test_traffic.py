import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_upload_csv_traffic():
    # Construct a sample CICIDS2017 CSV flow
    csv_content = (
        "Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWE Flag Count,ECE Flag Count,Down/Up Ratio,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size,Fwd Header Length.1,Fwd Avg Bytes/Bulk,Fwd Avg Packets/Bulk,Fwd Avg Bulk Rate,Bwd Avg Bytes/Bulk,Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min\n"
        "80,120000,3,3,120,450,60,20,40,20,200,50,150,75,4750,50,24000,10000,35000,5000,100000,50000,10000,60000,40000,90000,45000,5000,50000,40000,0,0,0,0,60,60,25,25,20,200,95,70,4900,0,1,0,1,1,0,0,0,1,100,40,150,60,0,0,0,0,0,0,3,120,3,450,29200,28960,2,20,0,0,0,0,0,0,0,0\n"
    )
    
    files = {"file": ("test_flow.csv", csv_content.encode("utf-8"), "text/csv")}
    data = {"dataset": "cicids2017"}
    
    response = client.post("/api/v1/traffic/upload", files=files, data=data)
    assert response.status_code == 200
    res_json = response.json()
    assert "job_id" in res_json
    assert res_json["status"] == "completed"
    assert "summary" in res_json
    assert res_json["summary"]["total_rows"] == 1

def test_list_and_get_job():
    # First get list of jobs
    resp = client.get("/api/v1/traffic/jobs")
    assert resp.status_code == 200
    jobs = resp.json()
    assert len(jobs) > 0

    job_id = jobs[0]["job_id"]
    detail_resp = client.get(f"/api/v1/traffic/jobs/{job_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["job_id"] == job_id

    # Download job results
    dl_resp = client.get(f"/api/v1/traffic/jobs/{job_id}/download?format=csv")
    assert dl_resp.status_code == 200
    assert "text/csv" in dl_resp.headers["content-type"]
