import time
import pytest
from app.services.live_collector import live_collector_service
from app.services.flow_aggregator import CanonicalFlowAggregator
from app.services.shared_pipeline import SharedPipelineService
from app.database.connection import SessionLocal
from app.models.generalized_xgboost import generalized_xgb_wrapper
from app.models.isolation_forest import isolation_forest_wrapper

def test_dynamic_interface_discovery():
    ifaces = live_collector_service.get_permitted_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    names = [i["name"] for i in ifaces]
    assert "test0" in names
    test0_info = next(i for i in ifaces if i["name"] == "test0")
    assert test0_info["is_virtual"] is True
    assert test0_info["is_permitted"] is True

def test_canonical_10_feature_extraction_from_packets():
    aggregator = CanonicalFlowAggregator(flow_timeout_seconds=5.0)
    now = time.time()
    
    # Ingest 3 forward packets and 2 backward packets
    aggregator.ingest_packet("192.168.1.10", "1.1.1.1", 54321, 443, "TCP", 100, now, tcp_flags=2, win_size=64240, header_len=40)
    aggregator.ingest_packet("1.1.1.1", "192.168.1.10", 443, 54321, "TCP", 60, now + 0.02, tcp_flags=18, win_size=65535, header_len=40)
    aggregator.ingest_packet("192.168.1.10", "1.1.1.1", 54321, 443, "TCP", 250, now + 0.05, tcp_flags=24, win_size=64240, header_len=40)
    aggregator.ingest_packet("1.1.1.1", "192.168.1.10", 443, 54321, "TCP", 800, now + 0.08, tcp_flags=24, win_size=65535, header_len=40)
    flow, is_term = aggregator.ingest_packet("192.168.1.10", "1.1.1.1", 54321, 443, "TCP", 60, now + 0.10, tcp_flags=17, win_size=64240, header_len=40)
    
    assert is_term is True
    assert flow is not None
    features = flow["features"]
    
    # Verify exact 10 canonical features
    assert features["forward_packets"] == 3
    assert features["backward_packets"] == 2
    assert features["total_packets"] == 5
    assert features["forward_bytes"] == 410
    assert features["backward_bytes"] == 860
    assert features["total_bytes"] == 1270
    assert features["duration_seconds"] == pytest.approx(0.10, abs=0.01)
    assert features["average_packet_size"] == pytest.approx(1270 / 5, abs=1.0)
    assert features["packets_per_second"] > 0
    assert features["bytes_per_second"] > 0

def test_flow_expiration_timeout():
    aggregator = CanonicalFlowAggregator(flow_timeout_seconds=2.0)
    now = time.time()
    
    # Ingest packet without termination
    flow, is_term = aggregator.ingest_packet("10.0.0.5", "10.0.0.1", 1234, 80, "TCP", 200, now)
    assert is_term is False
    assert flow is None
    
    # Check expiration before timeout
    expired_early = aggregator.expire_inactive_flows(now + 1.0)
    assert len(expired_early) == 0
    
    # Check expiration after timeout
    expired_late = aggregator.expire_inactive_flows(now + 3.0)
    assert len(expired_late) == 1
    assert expired_late[0]["packet_count"] == 1
    assert expired_late[0]["byte_count"] == 200
    assert expired_late[0]["termination_reason"] == "inactivity_timeout"

def test_dual_model_inference_on_real_flows():
    db = SessionLocal()
    try:
        now = time.time()
        aggregator = CanonicalFlowAggregator(flow_timeout_seconds=5.0)
        flow, _ = aggregator.ingest_packet("192.168.1.50", "8.8.8.8", 43210, 53, "UDP", 85, now)
        flow, is_term = aggregator.ingest_packet("8.8.8.8", "192.168.1.50", 53, 43210, "UDP", 140, now + 0.05)
        drained = aggregator.drain_all_flows()
        
        assert len(drained) == 1
        results = SharedPipelineService.process_flow_batch(
            db=db,
            flows=drained,
            dataset="generalized",
            source_type="live",
            persist=False
        )
        assert len(results) == 1
        res = results[0]
        
        # Verify dual model telemetry fields
        assert "prediction" in res
        assert "attack_probability" in res
        assert "risk_score" in res
        assert "risk_level" in res
        assert "anomaly_score" in res
        assert "is_anomaly" in res
        assert isinstance(res["anomaly_score"], float)
        assert isinstance(res["is_anomaly"], bool)
        assert "generalized_prob" in res
        assert "generalized_prediction" in res
    finally:
        db.close()

def test_live_collector_lifecycle_start_stop():
    # Test starting on virtual simulation interface test0
    start_res = live_collector_service.start_monitoring("test0", dataset="generalized")
    assert start_res["status"] == "started"
    assert live_collector_service.get_status()["running"] is True
    
    # Wait for simulation loop to capture packets and flows
    time.sleep(2.5)
    
    status = live_collector_service.get_status()
    assert status["total_packets"] > 0
    assert status["total_flows"] > 0
    assert status["uptime_seconds"] > 0
    
    # Verify live flows buffer
    flows = live_collector_service.get_live_flows(10)
    assert len(flows) > 0
    assert "anomaly_score" in flows[0]
    
    # Test stopping
    stop_res = live_collector_service.stop_monitoring()
    assert stop_res["status"] == "stopped"
    assert live_collector_service.get_status()["running"] is False

def test_live_collector_invalid_interface_rejection():
    live_collector_service.stop_monitoring()
    with pytest.raises(ValueError) as exc:
        live_collector_service.start_monitoring("invalid_iface_9999", dataset="generalized")
    assert "not recognized or permitted" in str(exc.value)
