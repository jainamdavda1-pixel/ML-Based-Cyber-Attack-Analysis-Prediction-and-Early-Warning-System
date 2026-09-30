import pytest
import time
from app.services.flow_aggregator import CanonicalFlowAggregator, CanonicalFlowState

def test_flow_canonical_key_grouping():
    aggregator = CanonicalFlowAggregator(flow_timeout_seconds=5.0)

    # Ingest forward packet A -> B
    f1, is_term1 = aggregator.ingest_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=80,
        proto="TCP",
        pkt_len=64,
        pkt_time=100.0,
        tcp_flags=2,  # SYN
        win_size=65535,
        header_len=40
    )
    assert not is_term1
    assert f1 is None
    assert len(aggregator._active_flows) == 1

    # Ingest return/backward packet B -> A
    f2, is_term2 = aggregator.ingest_packet(
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=54321,
        proto="TCP",
        pkt_len=120,
        pkt_time=100.02,
        tcp_flags=18,  # SYN-ACK
        win_size=65535,
        header_len=40
    )
    assert not is_term2
    assert f2 is None
    # Still grouped into the single bidirectional flow
    assert len(aggregator._active_flows) == 1

    # Ingest FIN packet to terminate flow
    f3, is_term3 = aggregator.ingest_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=80,
        proto="TCP",
        pkt_len=64,
        pkt_time=100.10,
        tcp_flags=17,  # FIN-ACK
        win_size=65535,
        header_len=40
    )
    assert is_term3
    assert f3 is not None
    assert f3["src_ip"] == "192.168.1.10"
    assert f3["dst_ip"] == "10.0.0.5"
    assert f3["packet_count"] == 3
    assert f3["byte_count"] == 64 + 120 + 64
    assert f3["protocol"] == "TCP"
    assert "features" in f3
    assert f3["features"]["Destination Port"] == 80.0
    assert f3["features"]["Total Fwd Packets"] == 2.0
    assert f3["features"]["Total Backward Packets"] == 1.0

def test_flow_inactivity_expiration():
    aggregator = CanonicalFlowAggregator(flow_timeout_seconds=3.0)

    aggregator.ingest_packet(
        src_ip="172.16.0.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        proto="UDP",
        pkt_len=75,
        pkt_time=10.0
    )

    # At t=11.0, not expired (only 1s passed)
    expired = aggregator.expire_inactive_flows(11.0)
    assert len(expired) == 0

    # At t=14.0, expired (4s passed >= 3.0s timeout)
    expired = aggregator.expire_inactive_flows(14.0)
    assert len(expired) == 1
    assert expired[0]["src_ip"] == "172.16.0.1"
    assert expired[0]["termination_reason"] == "inactivity_timeout"
    assert len(aggregator._active_flows) == 0
