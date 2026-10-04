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
        self._capture_thread: Optional[threading.Thread] = None
        self._timer_thread: Optional[threading.Thread] = None
        self._interface: Optional[str] = None
        self._dataset: Optional[str] = None
        self._session_id: Optional[str] = None
        self._start_time: Optional[float] = None
        self._stop_time: Optional[float] = None
        self._last_event_time: Optional[str] = None
        
        # Bounded flow buffers
        self._recent_flows = deque(maxlen=settings.MAX_LIVE_BUFFER_SIZE)
        self._total_packets = 0
        self._total_flows = 0
        self._total_attacks = 0
        self._total_anomalies = 0
        self._rejected_flows = 0
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()
        self._aggregator: Optional[CanonicalFlowAggregator] = None

    def get_permitted_interfaces(self) -> List[Dict[str, Any]]:
        """
        Dynamically detects network interfaces present on the host OS
        and combines them with permitted allowlist configurations.
        """
        detected_ifaces = []
        try:
            from scapy.all import get_if_list
            scapy_list = get_if_list()
        except Exception:
            scapy_list = []

        # Always include test0 simulation interface for safe testing
        detected_ifaces.append({
            "name": "test0",
            "description": "test0 - Virtual Simulation (Internal traffic generator for testing)",
            "is_virtual": True,
            "is_permitted": True
        })

        for iface in scapy_list:
            if iface.startswith("en"):
                desc = f"{iface} - Primary Ethernet / Wi-Fi Adapter"
            elif iface.startswith("lo"):
                desc = f"{iface} - Local Loopback Interface"
            elif iface.startswith("utun") or iface.startswith("tun"):
                desc = f"{iface} - VPN / Virtual Tunnel Device"
            elif iface.startswith("bridge"):
                desc = f"{iface} - Bridge Network Interface"
            elif iface.startswith("awdl") or iface.startswith("llw"):
                desc = f"{iface} - Apple Wireless Direct Link"
            elif iface.startswith("eth"):
                desc = f"{iface} - Ethernet Controller"
            elif iface.startswith("wlan"):
                desc = f"{iface} - 802.11 Wireless Adapter"
            else:
                desc = f"{iface} - Network Device"

            is_permitted = iface in settings.PERMITTED_INTERFACES or any(
                p in iface for p in ["en", "eth", "lo", "wlan", "bridge"]
            )
            detected_ifaces.append({
                "name": iface,
                "description": desc,
                "is_virtual": False,
                "is_permitted": is_permitted
            })

        return detected_ifaces

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            uptime = round(time.time() - self._start_time, 1) if self._running and self._start_time else 0.0
            flows_per_sec = round(self._total_flows / uptime, 2) if uptime > 0 else 0.0
            return {
                "running": self._running,
                "interface": self._interface,
                "dataset": self._dataset,
                "session_id": self._session_id,
                "start_time": datetime.fromtimestamp(self._start_time, tz=timezone.utc).isoformat() if self._start_time else None,
                "stop_time": datetime.fromtimestamp(self._stop_time, tz=timezone.utc).isoformat() if self._stop_time else None,
                "uptime_seconds": uptime,
                "total_packets": self._total_packets,
                "total_flows": self._total_flows,
                "total_attacks": self._total_attacks,
                "total_anomalies": self._total_anomalies,
                "flows_per_second": flows_per_sec,
                "rejected_flows": self._rejected_flows,
                "last_event_time": self._last_event_time,
                "last_error": self._last_error,
                "permitted_interfaces": [i["name"] for i in self.get_permitted_interfaces()]
            }

    def get_live_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            flows_copy = list(self._recent_flows)
        return flows_copy[-limit:]

    def start_monitoring(self, interface: str, dataset: str = "generalized") -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return {
                    "status": "already_running",
                    "interface": self._interface,
                    "session_id": self._session_id,
                    "dataset": self._dataset
                }

            permitted_names = [i["name"] for i in self.get_permitted_interfaces()]
            if interface not in permitted_names and interface not in settings.PERMITTED_INTERFACES:
                raise ValueError(f"Interface '{interface}' is not recognized or permitted. Available interfaces: {permitted_names}")

            self._interface = interface
            self._dataset = dataset
            self._running = True
            self._stop_event.clear()
            self._start_time = time.time()
            self._stop_time = None
            self._total_packets = 0
            self._total_flows = 0
            self._total_attacks = 0
            self._total_anomalies = 0
            self._rejected_flows = 0
            self._last_error = None
            self._session_id = f"mon-{uuid.uuid4().hex[:10]}"
            self._aggregator = CanonicalFlowAggregator(flow_timeout_seconds=3.0, max_active_flows=5000)

        # Record session in DB
        db = SessionLocal()
        try:
            MonitoringRepository.start_session(db, interface)
        except Exception as e:
            logger.error(f"Failed to record monitoring session in DB: {e}")
        finally:
            db.close()

        # Start background capture worker thread
        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, dataset, self._session_id),
            name="LivePacketCaptureThread",
            daemon=True
        )
        self._capture_thread.start()

        # Start periodic flow expiration worker thread
        self._timer_thread = threading.Thread(
            target=self._expiration_worker,
            args=(dataset, self._session_id),
            name="LiveFlowExpirationThread",
            daemon=True
        )
        self._timer_thread.start()

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
            self._stop_time = time.time()
            sess_id = self._session_id

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
        if self._timer_thread and self._timer_thread.is_alive():
            self._timer_thread.join(timeout=1.0)

        # Drain any lingering flows
        if self._aggregator:
            remaining = self._aggregator.drain_all_flows()
            if remaining:
                self._process_flows(remaining, self._dataset or "generalized", sess_id or "mon-drain")

        with self._lock:
            pkts = self._total_packets
            flows = self._total_flows
            attacks = self._total_attacks
            anomalies = self._total_anomalies

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
            "total_attacks": attacks,
            "total_anomalies": anomalies
        }

    def _capture_worker(self, interface: str, dataset: str, session_id: str):
        logger.info(f"Starting stateful live network capture on interface '{interface}' with pipeline '{dataset}'")

        if interface == "test0":
            self._run_simulated_capture(dataset, session_id)
            return

        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
            
            aggregator = self._aggregator

            def packet_handler(pkt):
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

                if aggregator:
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

                    if is_term and completed_flow:
                        self._process_flows([completed_flow], dataset, session_id)

            sniff(
                iface=interface if interface != "any" else None,
                prn=packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False,
                timeout=None
            )

        except PermissionError:
            err_msg = f"Permission denied for live packet capture on interface '{interface}'. On macOS/Linux, capturing live network interfaces requires elevated privileges or BPF device read access."
            logger.error(err_msg)
            with self._lock:
                self._last_error = err_msg
                self._running = False
        except Exception as e:
            err_msg = f"Capture error on interface '{interface}': {str(e)}"
            logger.error(err_msg)
            with self._lock:
                self._last_error = err_msg
                self._running = False

    def _expiration_worker(self, dataset: str, session_id: str):
        """
        Periodically inspects active flows and evicts those exceeding inactivity threshold.
        Ensures flows are scored and dispatched even during low-traffic periods.
        """
        while not self._stop_event.is_set():
            time.sleep(1.0)
            if not self._running:
                break
            
            if self._aggregator:
                now = time.time()
                expired = self._aggregator.expire_inactive_flows(now)
                if expired:
                    self._process_flows(expired, dataset, session_id)

    def _process_flows(self, flows: List[Dict[str, Any]], dataset: str, session_id: str):
        if not flows:
            return

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
                now_str = datetime.now(timezone.utc).isoformat()
                with self._lock:
                    self._last_event_time = now_str
                    for r in res:
                        self._total_flows += 1
                        if r.get("is_attack"):
                            self._total_attacks += 1
                        if r.get("is_anomaly"):
                            self._total_anomalies += 1
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

        aggregator = self._aggregator or CanonicalFlowAggregator(flow_timeout_seconds=2.0, max_active_flows=100)

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
