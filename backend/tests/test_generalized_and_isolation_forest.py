import io
import json
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.ml.model_registry import model_registry
from app.ml.registry_metadata import GENERALIZED_10_FEATURES, GENERALIZED_CLASSES, MODEL_REGISTRY_METADATA
from app.models.generalized_xgboost import generalized_xgb_wrapper
from app.models.isolation_forest import isolation_forest_wrapper
from app.services.prediction_service import PredictionService
from app.services.shared_pipeline import SharedPipelineService
from app.services.compatibility_engine import CompatibilityEngine, CompatibilityStatus
from app.services.flow_aggregator import CanonicalFlowAggregator
from app.services.live_collector import LiveCollectorService
from app.database.connection import SessionLocal

client = TestClient(app)

def test_model_loading_and_threshold_verification():
    """Verify loading, exact 10 features, and calibrated threshold configs for both models."""
    # 1. Generalized XGBoost
    assert generalized_xgb_wrapper.is_loaded(), "Generalized XGBoost should be loaded"
    assert generalized_xgb_wrapper.features == GENERALIZED_10_FEATURES
    assert len(generalized_xgb_wrapper.features) == 10
    assert abs(generalized_xgb_wrapper.threshold - 0.1743) < 1e-4

    # 2. Isolation Forest
    assert isolation_forest_wrapper.is_loaded(), "Isolation Forest should be loaded"
    assert isolation_forest_wrapper.features == GENERALIZED_10_FEATURES
    assert len(isolation_forest_wrapper.features) == 10
    assert abs(isolation_forest_wrapper.threshold - 0.02341647450041217) < 1e-6
    assert isolation_forest_wrapper.anomaly_rule == "decision_function_score < threshold"

    # 3. Model Registry Readiness and Metadata
    readiness = model_registry.get_readiness()
    assert readiness["generalized_xgb"]["ready"] is True
    assert readiness["isolation_forest"]["ready"] is True
    assert readiness["cicids2017"]["ready"] is True
    assert readiness["unsw-nb15"]["ready"] is True

    # 4. Registry Pipeline Retrieval
    gen_pipe = model_registry.get_pipeline("generalized")
    iso_pipe = model_registry.get_pipeline("isolation_forest")
    assert gen_pipe is not None
    assert iso_pipe is not None
    assert gen_pipe.is_ready() is True
    assert iso_pipe.is_ready() is True


def test_single_prediction_generalized_xgboost():
    """Test single flow prediction for Generalized XGBoost (Benign and Attack vectors)."""
    db = SessionLocal()
    try:
        # Typical benign flow
        benign_sample = {
            "duration_seconds": 0.5,
            "forward_packets": 5,
            "backward_packets": 4,
            "forward_bytes": 350,
            "backward_bytes": 1200,
            "total_packets": 9,
            "total_bytes": 1550,
            "packets_per_second": 18.0,
            "bytes_per_second": 3100.0,
            "average_packet_size": 172.2
        }
        res_benign = PredictionService.predict_single(db, "generalized-xgb", benign_sample)
        assert res_benign["dataset"] == "generalized-xgb"
        assert "prediction" in res_benign
        assert "confidence" in res_benign
        assert "risk_score" in res_benign
        assert len(res_benign["top_features"]) == 10

        # High-probability attack flow pattern
        attack_sample = {
            "duration_seconds": 120.0,
            "forward_packets": 20,
            "backward_packets": 0,
            "forward_bytes": 1200,
            "backward_bytes": 0,
            "total_packets": 20,
            "total_bytes": 1200,
            "packets_per_second": 0.16,
            "bytes_per_second": 10.0,
            "average_packet_size": 60.0
        }
        res_attack = PredictionService.predict_single(db, "generalized", attack_sample)
        assert res_attack["dataset"] == "generalized-xgb"
        assert res_attack["is_attack"] is True
        assert res_attack["prediction"] == "Attack"
        assert res_attack["attack_probability"] >= generalized_xgb_wrapper.threshold
        assert res_attack["risk_level"] in ["High", "Critical"]
    finally:
        db.close()


def test_single_prediction_isolation_forest():
    """Test single flow anomaly detection for Isolation Forest."""
    db = SessionLocal()
    try:
        # Inlier normal flow
        inlier_sample = {
            "duration_seconds": 1.2,
            "forward_packets": 8,
            "backward_packets": 6,
            "forward_bytes": 600,
            "backward_bytes": 2400,
            "total_packets": 14,
            "total_bytes": 3000,
            "packets_per_second": 11.6,
            "bytes_per_second": 2500.0,
            "average_packet_size": 214.28
        }
        res_inlier = PredictionService.predict_single(db, "isolation-forest", inlier_sample)
        assert res_inlier["dataset"] == "isolation-forest"
        assert "decision_function_score" in res_inlier
        assert "decision_threshold" in res_inlier

        # Extreme anomalous flow (huge outlier values)
        outlier_sample = {
            "duration_seconds": 9999.0,
            "forward_packets": 900000,
            "backward_packets": 1,
            "forward_bytes": 500000000,
            "backward_bytes": 40,
            "total_packets": 900001,
            "total_bytes": 500000040,
            "packets_per_second": 90.0,
            "bytes_per_second": 50005.0,
            "average_packet_size": 555.5
        }
        res_outlier = PredictionService.predict_single(db, "iforest", outlier_sample)
        assert res_outlier["dataset"] == "isolation-forest"
        assert res_outlier["decision_function_score"] < isolation_forest_wrapper.threshold
        assert res_outlier["is_attack"] is True
        assert res_outlier["prediction"] == "Anomaly"
    finally:
        db.close()


def test_predict_api_endpoint_generalized_and_isolation():
    """Test /api/v1/predict endpoint with Generalized XGBoost and Isolation Forest payloads."""
    payload_gen = {
        "dataset": "generalized-xgb",
        "features": {
            "duration_seconds": 0.2,
            "forward_packets": 3,
            "backward_packets": 2,
            "forward_bytes": 180,
            "backward_bytes": 500,
            "total_packets": 5,
            "total_bytes": 680,
            "packets_per_second": 25.0,
            "bytes_per_second": 3400.0,
            "average_packet_size": 136.0
        }
    }
    resp_gen = client.post("/api/v1/predict", json=payload_gen)
    assert resp_gen.status_code == 200, resp_gen.text
    assert resp_gen.json()["dataset"] == "generalized-xgb"

    payload_iso = {
        "dataset": "isolation-forest",
        "features": {
            "duration_seconds": 0.2,
            "forward_packets": 3,
            "backward_packets": 2,
            "forward_bytes": 180,
            "backward_bytes": 500,
            "total_packets": 5,
            "total_bytes": 680,
            "packets_per_second": 25.0,
            "bytes_per_second": 3400.0,
            "average_packet_size": 136.0
        }
    }
    resp_iso = client.post("/api/v1/predict", json=payload_iso)
    assert resp_iso.status_code == 200, resp_iso.text
    assert resp_iso.json()["dataset"] == "isolation-forest"


def test_csv_batch_adaptation_and_inference_generalized():
    """Test CSV batch processing with alias mapping and derivation to 10 Generalized features."""
    df_raw = pd.DataFrame({
        "dur": [0.1, 120.0, 2.5],
        "spkts": [4, 20, 10],
        "dpkts": [3, 0, 8],
        "sbytes": [300, 1200, 800],
        "dbytes": [600, 0, 1500]
    })
    csv_bytes = df_raw.to_csv(index=False).encode("utf-8")

    # 1. Compatibility Profile
    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="generalized")
    assert profile["status"] in [CompatibilityStatus.TRANSFORMABLE, CompatibilityStatus.TRANSFORMED_COMPATIBLE]
    assert "generalized-xgboost-binary" in profile["compatible_models"]

    # 2. Transformed DataFrame has exactly 10 features
    clean_df = CompatibilityEngine.transform_dataframe(df_raw, "generalized")
    assert list(clean_df.columns) == GENERALIZED_10_FEATURES
    assert len(clean_df) == 3

    # 3. Batch API Prediction
    files = {"file": ("test_generalized.csv", csv_bytes, "text/csv")}
    data = {"dataset": "generalized"}
    resp = client.post("/api/v1/predict/batch", files=files, data=data)
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["total_records"] == 3
    assert len(result["sample_predictions"]) == 3
    assert "benign_count" in result
    assert "attack_count" in result


def test_pcap_flow_processing_generalized_and_isolation():
    """Test PCAP flow batch inference for Generalized XGBoost and Isolation Forest."""
    db = SessionLocal()
    try:
        # Create canonical flow states using flow aggregator
        agg = CanonicalFlowAggregator(flow_timeout_seconds=15.0)
        # Ingest packets
        agg.ingest_packet(src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=50000, dst_port=80, proto="TCP", pkt_len=100, pkt_time=1000.0, tcp_flags=0x02)
        agg.ingest_packet(src_ip="10.0.0.1", dst_ip="192.168.1.50", src_port=80, dst_port=50000, proto="TCP", pkt_len=200, pkt_time=1000.1, tcp_flags=0x12)
        agg.ingest_packet(src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=50000, dst_port=80, proto="TCP", pkt_len=150, pkt_time=1000.2, tcp_flags=0x10)
        
        flow_dicts = agg.drain_all_flows()
        assert len(flow_dicts) >= 1

        # 1. Process via Generalized XGBoost
        results_gen = SharedPipelineService.process_flow_batch(
            db=db,
            flows=flow_dicts,
            dataset="generalized",
            source_type="pcap",
            persist=True
        )
        assert len(results_gen) == len(flow_dicts)
        assert results_gen[0]["dataset"] == "Generalized-XGB"
        assert "risk_score" in results_gen[0]

        # 2. Process via Isolation Forest with fresh flow_ids
        iso_flow_dicts = [dict(f, flow_id=f"iso-{f['flow_id']}") for f in flow_dicts]
        results_iso = SharedPipelineService.process_flow_batch(
            db=db,
            flows=iso_flow_dicts,
            dataset="isolation_forest",
            source_type="pcap",
            persist=True
        )
        assert len(results_iso) == len(iso_flow_dicts)
        assert results_iso[0]["dataset"] == "Isolation-Forest"
        assert "risk_level" in results_iso[0]
    finally:
        db.close()


def test_live_capture_flow_pipeline_generalized():
    """Test LiveCollectorService processing flow batches with Generalized and Isolation Forest models."""
    live_service = LiveCollectorService()
    
    import uuid
    # Simulate flow batches generated by live packet capture with distinct flow_ids
    flow_obj_1 = {
        "flow_id": f"live-test-gen-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc),
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.1",
        "src_port": 49999,
        "dst_port": 443,
        "protocol": "TCP",
        "duration": 0.5,
        "packet_count": 6,
        "byte_count": 800,
        "features": {
            "duration_seconds": 0.5,
            "forward_packets": 3.0,
            "backward_packets": 3.0,
            "forward_bytes": 300.0,
            "backward_bytes": 500.0,
            "total_packets": 6.0,
            "total_bytes": 800.0,
            "packets_per_second": 12.0,
            "bytes_per_second": 1600.0,
            "average_packet_size": 133.33
        }
    }

    flow_obj_2 = {
        "flow_id": f"live-test-iso-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc),
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.1",
        "src_port": 49999,
        "dst_port": 443,
        "protocol": "TCP",
        "duration": 0.5,
        "packet_count": 6,
        "byte_count": 800,
        "features": {
            "duration_seconds": 0.5,
            "forward_packets": 3.0,
            "backward_packets": 3.0,
            "forward_bytes": 300.0,
            "backward_bytes": 500.0,
            "total_packets": 6.0,
            "total_bytes": 800.0,
            "packets_per_second": 12.0,
            "bytes_per_second": 1600.0,
            "average_packet_size": 133.33
        }
    }

    # Process live batch with generalized model
    live_service._process_flows([flow_obj_1], dataset="generalized", session_id="test-session-1")
    assert live_service._total_flows >= 1

    # Process live batch with isolation forest
    live_service._process_flows([flow_obj_2], dataset="isolation_forest", session_id="test-session-2")
    assert live_service._total_flows >= 2
