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
from app.services.traffic_parser import TrafficParserService

logger = logging.getLogger(__name__)

class LiveCollectorService:
    """
    Background passive network traffic collector.
    Captures live packets from permitted network interfaces, aggregates them
    into flows, runs ML classification via SharedPipeline, and tracks real-time statistics.
    """

    def __init__(self):
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._interface: Optional[str] = None
        self._session_id: Optional[str] = None
        self._start_time: Optional[float] = None
        
        # Bounded buffers
        self._recent_flows = deque(maxlen=200)
        self._total_packets = 0
        self._total_flows = 0
        self._total_attacks = 0
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

        # Start capture worker thread
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

        # Update DB session
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
        logger.info(f"Starting live network capture on interface {interface}")

        # If test interface or loopback simulation
        if interface == "test0":
            self._run_simulated_capture(dataset, session_id)
            return

        try:
            from scapy.all import sniff, IP, TCP, UDP
            
            def packet_handler(pkt):
                if self._stop_event.is_set():
                    return
                with self._lock:
                    self._total_packets += 1

                # Construct single packet flow feature approximation
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    src_port = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0)
                    dst_port = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0)
                    proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")

                    flow_raw = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto,
                        "start_time": time.time(),
                        "end_time": time.time(),
                        "fwd_packets": [len(pkt)],
                        "bwd_packets": [],
                        "fwd_times": [time.time()],
                        "bwd_times": [],
                        "all_times": [time.time()],
                        "fwd_flags": [int(pkt[TCP].flags)] if pkt.haslayer(TCP) else [0],
                        "bwd_flags": [],
                        "fwd_win": int(pkt[TCP].window) if pkt.haslayer(TCP) else 0,
                        "bwd_win": 0,
                        "fwd_header_len": len(pkt[TCP]) if pkt.haslayer(TCP) else 0,
                        "bwd_header_len": 0
                    }

                    flow_feat = TrafficParserService._compute_flow_features(flow_raw)

                    # Process in batch of 1
                    db = SessionLocal()
                    try:
                        res = SharedPipelineService.process_flow_batch(
                            db=db,
                            flows=[flow_feat],
                            dataset=dataset,
                            session_id=session_id,
                            source_type="live",
                            persist=True
                        )
                        if res:
                            with self._lock:
                                self._total_flows += 1
                                if res[0]["is_attack"]:
                                    self._total_attacks += 1
                                self._recent_flows.append(res[0])
                    except Exception as err:
                        logger.error(f"Inference error in live worker: {err}")
                    finally:
                        db.close()

            sniff(
                iface=interface if interface != "any" else None,
                prn=packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False,
                timeout=None
            )

        except PermissionError as pe:
            err_msg = f"Insufficient OS permissions for live packet capture on '{interface}'. Root/Administrator privileges required."
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

    def _run_simulated_capture(self, dataset: str, session_id: str):
        """Generates benign and test attack packets for testing without root socket permissions."""
        logger.info("Running test network monitoring simulation")
        import random
        
        sample_ips = [
            ("192.168.1.45", "10.0.0.1", 443, "TCP"),
            ("192.168.1.102", "192.168.1.1", 53, "UDP"),
            ("172.16.0.15", "10.0.0.5", 80, "TCP"),
            ("10.0.0.22", "10.0.0.1", 22, "TCP")
        ]

        while not self._stop_event.is_set():
            time.sleep(1.0)
            src_ip, dst_ip, dport, proto = random.choice(sample_ips)
            sport = random.randint(1024, 65535)

            with self._lock:
                self._total_packets += random.randint(5, 20)

            flow_raw = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "start_time": time.time() - 0.5,
                "end_time": time.time(),
                "fwd_packets": [random.randint(64, 1400) for _ in range(random.randint(2, 6))],
                "bwd_packets": [random.randint(64, 1400) for _ in range(random.randint(2, 6))],
                "fwd_times": [time.time() - 0.3, time.time() - 0.1],
                "bwd_times": [time.time() - 0.2, time.time()],
                "all_times": [time.time() - 0.3, time.time() - 0.2, time.time() - 0.1, time.time()],
                "fwd_flags": [2, 16],
                "bwd_flags": [18, 16],
                "fwd_win": 65535,
                "bwd_win": 65535,
                "fwd_header_len": 40,
                "bwd_header_len": 40
            }

            flow_feat = TrafficParserService._compute_flow_features(flow_raw)
            db = SessionLocal()
            try:
                res = SharedPipelineService.process_flow_batch(
                    db=db,
                    flows=[flow_feat],
                    dataset=dataset,
                    session_id=session_id,
                    source_type="live",
                    persist=True
                )
                if res:
                    with self._lock:
                        self._total_flows += 1
                        if res[0]["is_attack"]:
                            self._total_attacks += 1
                        self._recent_flows.append(res[0])
            except Exception as err:
                logger.error(f"Error in simulated capture: {err}")
            finally:
                db.close()

live_collector_service = LiveCollectorService()
