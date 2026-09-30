import time
import uuid
import threading
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.core.config import settings
from app.database.connection import SessionLocal
from app.database.repositories import MonitoringRepository
from app.services.shared_pipeline import SharedPipelineService
from app.services.flow_aggregator import CanonicalFlowAggregator

logger = logging.getLogger(__name__)

class LiveCollectorService:
    """
    Background passive network traffic collector.
    Captures live packets on permitted network interfaces, aggregates them
    statefully into bidirectional flows using CanonicalFlowAggregator,
    performs ML inference on completed/mature flows, and records telemetry.
    """

    def __init__(self):
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._interface: Optional[str] = None
        self._session_id: Optional[str] = None
        self._start_time: Optional[float] = None
        
        # Bounded flow buffers
        self._recent_flows = deque(maxlen=200)
        self._total_packets = 0
        self._total_flows = 0
        self._total_attacks = 0
        self._rejected_flows = 0
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()

    def get_permitted_interfaces(self) -> List[str]:
        return settings.PERMITTED_INTERFACES

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            uptime = round(time.time() - self._start_time, 1) if self._running and self._start_time else 0.0
            return {
                "running": self._running,
                "interface": self._interface,
                "session_id": self._session_id,
                "uptime_seconds": uptime,
                "total_packets": self._total_packets,
                "total_flows": self._total_flows,
                "total_attacks": self._total_attacks,
                "rejected_flows": self._rejected_flows,
                "last_error": self._last_error,
                "permitted_interfaces": settings.PERMITTED_INTERFACES
            }

    def get_live_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            flows_copy = list(self._recent_flows)
        return flows_copy[-limit:]

    def start_monitoring(self, interface: str, dataset: str = "cicids2017") -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return {"status": "already_running", "interface": self._interface, "session_id": self._session_id}

            if interface not in settings.PERMITTED_INTERFACES and interface != "test0":
                raise ValueError(f"Interface '{interface}' is not in the permitted allowlist: {settings.PERMITTED_INTERFACES}")

            self._interface = interface
            self._running = True
            self._stop_event.clear()
            self._start_time = time.time()
            self._total_packets = 0
            self._total_flows = 0
            self._total_attacks = 0
            self._rejected_flows = 0
            self._last_error = None
            self._session_id = f"mon-{uuid.uuid4().hex[:10]}"

        # Record session in DB
        db = SessionLocal()
        try:
            MonitoringRepository.start_session(db, interface)
        except Exception as e:
            logger.error(f"Failed to record monitoring session in DB: {e}")
        finally:
            db.close()

        # Start background capture worker thread
        self._thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, dataset, self._session_id),
            daemon=True
        )
        self._thread.start()

        return {
            "status": "started",
            "interface": interface,
            "session_id": self._session_id,
            "dataset": dataset
        }

    def stop_monitoring(self) -> Dict[str, Any]:
        with self._lock:
            if not self._running:
                return {"status": "not_running"}
            self._running = False
            self._stop_event.set()
            sess_id = self._session_id
            pkts = self._total_packets
            flows = self._total_flows
            attacks = self._total_attacks

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        db = SessionLocal()
        try:
            if sess_id:
                MonitoringRepository.stop_session(db, sess_id, pkts, flows, attacks)
        except Exception as e:
            logger.error(f"Failed to update monitoring session in DB: {e}")
        finally:
            db.close()

        return {
            "status": "stopped",
            "session_id": sess_id,
            "total_packets": pkts,
            "total_flows": flows,
            "total_attacks": attacks
        }

    def _capture_worker(self, interface: str, dataset: str, session_id: str):
        logger.info(f"Starting stateful live network capture on interface {interface} for dataset {dataset}")

        if interface == "test0":
            self._run_simulated_capture(dataset, session_id)
            return

        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
            
            aggregator = CanonicalFlowAggregator(flow_timeout_seconds=10.0, max_active_flows=5000)
            last_expire_check = time.time()

            def packet_handler(pkt):
                nonlocal last_expire_check
                if self._stop_event.is_set():
                    return

                with self._lock:
                    self._total_packets += 1

                if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                    return

                ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else ("ICMP" if pkt.haslayer(ICMP) else "OTHER"))

                src_port = 0
                dst_port = 0
                tcp_flags = 0
                win_size = 0
                header_len = 0

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    src_port = int(tcp.sport)
                    dst_port = int(tcp.dport)
                    tcp_flags = int(tcp.flags)
                    win_size = int(tcp.window)
                    header_len = len(tcp)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    src_port = int(udp.sport)
                    dst_port = int(udp.dport)
                    header_len = 8

                pkt_time = float(pkt.time)
                pkt_len = len(pkt)

                completed_flow, is_term = aggregator.ingest_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    pkt_len=pkt_len,
                    pkt_time=pkt_time,
                    tcp_flags=tcp_flags,
                    win_size=win_size,
                    header_len=header_len
                )

                ready_flows = []
                if is_term and completed_flow:
                    ready_flows.append(completed_flow)

                # Periodically expire inactive flows every 2 seconds
                now = time.time()
                if now - last_expire_check >= 2.0:
                    expired = aggregator.expire_inactive_flows(now)
                    if expired:
                        ready_flows.extend(expired)
                    last_expire_check = now

                if ready_flows:
                    self._process_flows(ready_flows, dataset, session_id)

            sniff(
                iface=interface if interface != "any" else None,
                prn=packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False,
                timeout=None
            )

            # Drain on stop
            remaining = aggregator.drain_all_flows()
            if remaining:
                self._process_flows(remaining, dataset, session_id)

        except PermissionError:
            err_msg = f"Insufficient OS permissions for live packet capture on '{interface}'. Passive monitoring requires elevated packet capture privileges."
            logger.error(err_msg)
            with self._lock:
                self._last_error = err_msg
                self._running = False
        except Exception as e:
            err_msg = f"Live capture error on interface '{interface}': {str(e)}"
            logger.error(err_msg)
            with self._lock:
                self._last_error = err_msg
                self._running = False

    def _process_flows(self, flows: List[Dict[str, Any]], dataset: str, session_id: str):
        db = SessionLocal()
        try:
            res = SharedPipelineService.process_flow_batch(
                db=db,
                flows=flows,
                dataset=dataset,
                session_id=session_id,
                source_type="live",
                persist=True
            )
            if res:
                with self._lock:
                    for r in res:
                        self._total_flows += 1
                        if r.get("is_attack"):
                            self._total_attacks += 1
                        self._recent_flows.append(r)
        except Exception as err:
            logger.error(f"Inference error in live worker: {err}")
        finally:
            db.close()

    def _run_simulated_capture(self, dataset: str, session_id: str):
        """Generates realistic bidirectional flows for simulated testing."""
        logger.info("Running test network monitoring simulation with CanonicalFlowAggregator")
        import random
        
        sample_endpoints = [
            ("192.168.1.45", "10.0.0.1", 443, "TCP"),
            ("192.168.1.102", "192.168.1.1", 53, "UDP"),
            ("172.16.0.15", "10.0.0.5", 80, "TCP"),
            ("10.0.0.22", "10.0.0.1", 22, "TCP")
        ]

        aggregator = CanonicalFlowAggregator(flow_timeout_seconds=2.0, max_active_flows=100)

        while not self._stop_event.is_set():
            time.sleep(1.0)
            src_ip, dst_ip, dport, proto = random.choice(sample_endpoints)
            sport = random.randint(1024, 65535)
            now = time.time()

            # Simulate forward handshake packet
            aggregator.ingest_packet(src_ip, dst_ip, sport, dport, proto, 64, now, tcp_flags=2, win_size=65535, header_len=40)
            # Simulate backward handshake ACK packet
            aggregator.ingest_packet(dst_ip, src_ip, dport, sport, proto, 64, now + 0.01, tcp_flags=18, win_size=65535, header_len=40)
            # Simulate data packet forward
            aggregator.ingest_packet(src_ip, dst_ip, sport, dport, proto, random.randint(120, 1400), now + 0.05, tcp_flags=24, win_size=65535, header_len=40)
            # Simulate data packet backward
            aggregator.ingest_packet(dst_ip, src_ip, dport, sport, proto, random.randint(120, 1400), now + 0.08, tcp_flags=24, win_size=65535, header_len=40)
            # Terminate flow with FIN
            flow_feat, is_term = aggregator.ingest_packet(src_ip, dst_ip, sport, dport, proto, 64, now + 0.12, tcp_flags=17, win_size=65535, header_len=40)

            with self._lock:
                self._total_packets += 5

            if is_term and flow_feat:
                self._process_flows([flow_feat], dataset, session_id)

live_collector_service = LiveCollectorService()
