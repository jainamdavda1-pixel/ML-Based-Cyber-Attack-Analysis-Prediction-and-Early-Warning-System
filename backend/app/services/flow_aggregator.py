import time
import math
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

class CanonicalFlowState:
    """
    Stateful bidirectional network flow representation.
    Maintains exact timestamps, forward/backward packet sequences,
    TCP flag statistics, and derived mathematical metrics.
    """
    def __init__(self, initiator_ip: str, responder_ip: str, initiator_port: int, responder_port: int, protocol: str, start_time: float):
        self.flow_id = f"flow-{uuid.uuid4().hex[:12]}"
        self.initiator_ip = initiator_ip
        self.responder_ip = responder_ip
        self.initiator_port = initiator_port
        self.responder_port = responder_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen_time = start_time
        
        # Directional packet length lists
        self.fwd_lengths: List[int] = []
        self.bwd_lengths: List[int] = []
        
        # Directional packet timestamps
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []
        
        # Directional TCP flags
        self.fwd_flags: List[int] = []
        self.bwd_flags: List[int] = []
        
        # TCP Header / Window details
        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0
        self.fwd_init_win = 0
        self.bwd_init_win = 0
        self.is_terminated = False
        self.termination_reason = "active"

    def add_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, pkt_len: int, pkt_time: float, tcp_flags: int = 0, win_size: int = 0, header_len: int = 0):
        self.last_seen_time = max(self.last_seen_time, pkt_time)
        self.all_timestamps.append(pkt_time)

        is_forward = (src_ip == self.initiator_ip and src_port == self.initiator_port)
        if is_forward:
            self.fwd_lengths.append(pkt_len)
            self.fwd_timestamps.append(pkt_time)
            self.fwd_flags.append(tcp_flags)
            self.fwd_header_bytes += header_len
            if self.fwd_init_win == 0 and win_size > 0:
                self.fwd_init_win = win_size
        else:
            self.bwd_lengths.append(pkt_len)
            self.bwd_timestamps.append(pkt_time)
            self.bwd_flags.append(tcp_flags)
            self.bwd_header_bytes += header_len
            if self.bwd_init_win == 0 and win_size > 0:
                self.bwd_init_win = win_size

        # Check for TCP termination flags (FIN or RST)
        if tcp_flags & 0x01:  # FIN
            self.is_terminated = True
            self.termination_reason = "tcp_fin"
        elif tcp_flags & 0x04:  # RST
            self.is_terminated = True
            self.termination_reason = "tcp_rst"

    def export_features(self) -> Dict[str, Any]:
        duration_sec = max(0.000001, self.last_seen_time - self.start_time)
        fwd_pkts = self.fwd_lengths
        bwd_pkts = self.bwd_lengths
        all_pkts = fwd_pkts + bwd_pkts

        fwd_cnt = len(fwd_pkts)
        bwd_cnt = len(bwd_pkts)
        tot_cnt = fwd_cnt + bwd_cnt

        fwd_bytes = sum(fwd_pkts)
        bwd_bytes = sum(bwd_pkts)
        tot_bytes = fwd_bytes + bwd_bytes

        # Inter-arrival time (IAT) calculation
        def compute_iats(times: List[float]) -> List[float]:
            if len(times) <= 1:
                return [0.0]
            s_times = sorted(times)
            return [s_times[i] - s_times[i - 1] for i in range(1, len(s_times))]

        flow_iats = compute_iats(self.all_timestamps)
        fwd_iats = compute_iats(self.fwd_timestamps)
        bwd_iats = compute_iats(self.bwd_timestamps)

        # Packet length statistics
        pkt_len_mean = float(np.mean(all_pkts)) if all_pkts else 0.0
        pkt_len_std = float(np.std(all_pkts)) if len(all_pkts) > 1 else 0.0
        pkt_len_var = float(np.var(all_pkts)) if len(all_pkts) > 1 else 0.0
        pkt_len_min = float(min(all_pkts)) if all_pkts else 0.0
        pkt_len_max = float(max(all_pkts)) if all_pkts else 0.0

        fwd_len_mean = float(np.mean(fwd_pkts)) if fwd_pkts else 0.0
        fwd_len_std = float(np.std(fwd_pkts)) if len(fwd_pkts) > 1 else 0.0
        fwd_len_min = float(min(fwd_pkts)) if fwd_pkts else 0.0
        fwd_len_max = float(max(fwd_pkts)) if fwd_pkts else 0.0

        bwd_len_mean = float(np.mean(bwd_pkts)) if bwd_pkts else 0.0
        bwd_len_std = float(np.std(bwd_pkts)) if len(bwd_pkts) > 1 else 0.0
        bwd_len_min = float(min(bwd_pkts)) if bwd_pkts else 0.0
        bwd_len_max = float(max(bwd_pkts)) if bwd_pkts else 0.0

        # TCP flags unpacking
        all_flags = self.fwd_flags + self.bwd_flags
        fin_cnt = sum(1 for f in all_flags if f & 0x01)
        syn_cnt = sum(1 for f in all_flags if f & 0x02)
        rst_cnt = sum(1 for f in all_flags if f & 0x04)
        psh_cnt = sum(1 for f in all_flags if f & 0x08)
        ack_cnt = sum(1 for f in all_flags if f & 0x10)
        urg_cnt = sum(1 for f in all_flags if f & 0x20)
        ece_cnt = sum(1 for f in all_flags if f & 0x40)
        cwe_cnt = sum(1 for f in all_flags if f & 0x80)

        # Microsecond scaling for CICIDS standard
        dur_micro = duration_sec * 1000000.0
        flow_bytes_per_sec = tot_bytes / duration_sec if duration_sec > 0 else 0.0
        flow_pkts_per_sec = tot_cnt / duration_sec if duration_sec > 0 else 0.0
        fwd_pkts_per_sec = fwd_cnt / duration_sec if duration_sec > 0 else 0.0
        bwd_pkts_per_sec = bwd_cnt / duration_sec if duration_sec > 0 else 0.0

        features = {
            # CICIDS2017 70 features
            'ACK Flag Count': float(ack_cnt),
            'Active Max': 0.0,
            'Active Mean': 0.0,
            'Active Min': 0.0,
            'Active Std': 0.0,
            'Average Packet Size': pkt_len_mean,
            'Avg Bwd Segment Size': bwd_len_mean,
            'Avg Fwd Segment Size': fwd_len_mean,
            'Bwd Header Length': float(self.bwd_header_bytes),
            'Bwd IAT Max': float(max(bwd_iats)) * 1000000.0,
            'Bwd IAT Mean': float(np.mean(bwd_iats)) * 1000000.0,
            'Bwd IAT Min': float(min(bwd_iats)) * 1000000.0,
            'Bwd IAT Std': float(np.std(bwd_iats)) * 1000000.0 if len(bwd_iats) > 1 else 0.0,
            'Bwd IAT Total': float(sum(bwd_iats)) * 1000000.0,
            'Bwd Packet Length Max': bwd_len_max,
            'Bwd Packet Length Mean': bwd_len_mean,
            'Bwd Packet Length Min': bwd_len_min,
            'Bwd Packet Length Std': bwd_len_std,
            'Bwd Packets/s': bwd_pkts_per_sec,
            'CWE Flag Count': float(cwe_cnt),
            'Destination Port': float(self.responder_port),
            'Down/Up Ratio': (float(bwd_cnt) / float(fwd_cnt)) if fwd_cnt > 0 else 0.0,
            'ECE Flag Count': float(ece_cnt),
            'FIN Flag Count': float(fin_cnt),
            'Flow Bytes/s': flow_bytes_per_sec,
            'Flow Duration': dur_micro,
            'Flow IAT Max': float(max(flow_iats)) * 1000000.0,
            'Flow IAT Mean': float(np.mean(flow_iats)) * 1000000.0,
            'Flow IAT Min': float(min(flow_iats)) * 1000000.0,
            'Flow IAT Std': float(np.std(flow_iats)) * 1000000.0 if len(flow_iats) > 1 else 0.0,
            'Flow Packets/s': flow_pkts_per_sec,
            'Fwd Header Length': float(self.fwd_header_bytes),
            'Fwd Header Length.1': float(self.fwd_header_bytes),
            'Fwd IAT Max': float(max(fwd_iats)) * 1000000.0,
            'Fwd IAT Mean': float(np.mean(fwd_iats)) * 1000000.0,
            'Fwd IAT Min': float(min(fwd_iats)) * 1000000.0,
            'Fwd IAT Std': float(np.std(fwd_iats)) * 1000000.0 if len(fwd_iats) > 1 else 0.0,
            'Fwd IAT Total': float(sum(fwd_iats)) * 1000000.0,
            'Fwd PSH Flags': float(psh_cnt if fwd_cnt > 0 else 0),
            'Fwd Packet Length Max': fwd_len_max,
            'Fwd Packet Length Mean': fwd_len_mean,
            'Fwd Packet Length Min': fwd_len_min,
            'Fwd Packet Length Std': fwd_len_std,
            'Fwd Packets/s': fwd_pkts_per_sec,
            'Fwd URG Flags': float(urg_cnt if fwd_cnt > 0 else 0),
            'Idle Max': 0.0,
            'Idle Mean': 0.0,
            'Idle Min': 0.0,
            'Idle Std': 0.0,
            'Init_Win_bytes_backward': float(self.bwd_init_win),
            'Init_Win_bytes_forward': float(self.fwd_init_win),
            'Max Packet Length': pkt_len_max,
            'Min Packet Length': pkt_len_min,
            'PSH Flag Count': float(psh_cnt),
            'Packet Length Mean': pkt_len_mean,
            'Packet Length Std': pkt_len_std,
            'Packet Length Variance': pkt_len_var,
            'RST Flag Count': float(rst_cnt),
            'SYN Flag Count': float(syn_cnt),
            'Subflow Bwd Bytes': float(bwd_bytes),
            'Subflow Bwd Packets': float(bwd_cnt),
            'Subflow Fwd Bytes': float(fwd_bytes),
            'Subflow Fwd Packets': float(fwd_cnt),
            'Total Backward Packets': float(bwd_cnt),
            'Total Fwd Packets': float(fwd_cnt),
            'Total Length of Bwd Packets': float(bwd_bytes),
            'Total Length of Fwd Packets': float(fwd_bytes),
            'URG Flag Count': float(urg_cnt),
            'act_data_pkt_fwd': float(fwd_cnt),
            'min_seg_size_forward': 20.0 if self.protocol == "TCP" else 8.0,

            # UNSW-NB15 42 features
            'dur': duration_sec,
            'proto': 6.0 if self.protocol == "TCP" else (17.0 if self.protocol == "UDP" else 1.0),
            'service': 0.0,
            'state': 2.0 if (syn_cnt > 0 and ack_cnt > 0) else 1.0,
            'spkts': float(fwd_cnt),
            'dpkts': float(bwd_cnt),
            'sbytes': float(fwd_bytes),
            'dbytes': float(bwd_bytes),
            'rate': float(tot_cnt / duration_sec) if duration_sec > 0 else 0.0,
            'sttl': 64.0,
            'dttl': 64.0,
            'sload': float((fwd_bytes * 8) / duration_sec) if duration_sec > 0 else 0.0,
            'dload': float((bwd_bytes * 8) / duration_sec) if duration_sec > 0 else 0.0,
            'sloss': 0.0,
            'dloss': 0.0,
            'sinpkt': float(np.mean(fwd_iats) * 1000.0) if fwd_iats else 0.0,
            'dinpkt': float(np.mean(bwd_iats) * 1000.0) if bwd_iats else 0.0,
            'sjit': float(np.std(fwd_iats) * 1000.0) if len(fwd_iats) > 1 else 0.0,
            'djit': float(np.std(bwd_iats) * 1000.0) if len(bwd_iats) > 1 else 0.0,
            'swin': float(self.fwd_init_win),
            'stcpb': 0.0,
            'dtcpb': 0.0,
            'dwin': float(self.bwd_init_win),
            'tcprtt': float(fwd_iats[0] if fwd_iats else 0.0),
            'synack': float(fwd_iats[0] / 2.0 if fwd_iats else 0.0),
            'ackdat': float(fwd_iats[0] / 2.0 if fwd_iats else 0.0),
            'smean': fwd_len_mean,
            'dmean': bwd_len_mean,
            'trans_depth': 0.0,
            'response_body_len': 0.0,
            'ct_srv_src': 1.0,
            'ct_state_ttl': 1.0,
            'ct_dst_ltm': 1.0,
            'ct_src_dport_ltm': 1.0,
            'ct_dst_sport_ltm': 1.0,
            'ct_dst_src_ltm': 1.0,
            'is_ftp_login': 0.0,
            'ct_ftp_cmd': 0.0,
            'ct_flw_http_mthd': 0.0,
            'ct_src_ltm': 1.0,
            'ct_srv_dst': 1.0,
            'is_sm_ips_ports': 1.0 if (self.initiator_ip == self.responder_ip and self.initiator_port == self.responder_port) else 0.0
        }

        ts = datetime.fromtimestamp(self.start_time, tz=timezone.utc) if self.start_time > 0 else datetime.now(timezone.utc)

        return {
            "flow_id": self.flow_id,
            "timestamp": ts,
            "src_ip": self.initiator_ip,
            "dst_ip": self.responder_ip,
            "src_port": self.initiator_port,
            "dst_port": self.responder_port,
            "protocol": self.protocol,
            "duration": round(duration_sec, 6),
            "packet_count": tot_cnt,
            "byte_count": tot_bytes,
            "is_terminated": self.is_terminated,
            "termination_reason": self.termination_reason,
            "features": features
        }

class CanonicalFlowAggregator:
    """
    Stateful Flow Table Manager with timeout eviction, connection tracking,
    and bounded memory management.
    """
    def __init__(self, flow_timeout_seconds: float = 15.0, max_active_flows: int = 5000):
        self.flow_timeout_seconds = flow_timeout_seconds
        self.max_active_flows = max_active_flows
        self._active_flows: Dict[Tuple, CanonicalFlowState] = {}

    def get_canonical_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[Tuple, bool]:
        """
        Returns a normalized 5-tuple key and whether the packet direction is forward.
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto), True
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto), False

    def ingest_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, pkt_len: int, pkt_time: float, tcp_flags: int = 0, win_size: int = 0, header_len: int = 0) -> Tuple[Optional[Dict[str, Any]], bool]:
        """
        Ingests a packet into the active flow table.
        If the flow terminates (FIN/RST), returns (flow_features, True).
        """
        key, is_fwd = self.get_canonical_key(src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self._active_flows:
            # Check capacity
            if len(self._active_flows) >= self.max_active_flows:
                # Evict oldest flow
                oldest_key = min(self._active_flows.keys(), key=lambda k: self._active_flows[k].last_seen_time)
                del self._active_flows[oldest_key]

            # The packet creating this flow record is the true flow initiator
            initiator_ip = src_ip
            responder_ip = dst_ip
            initiator_port = src_port
            responder_port = dst_port

            flow = CanonicalFlowState(initiator_ip, responder_ip, initiator_port, responder_port, proto, pkt_time)
            self._active_flows[key] = flow
        else:
            flow = self._active_flows[key]

        flow.add_packet(src_ip, dst_ip, src_port, dst_port, pkt_len, pkt_time, tcp_flags, win_size, header_len)

        # If terminated, pop and return
        if flow.is_terminated:
            del self._active_flows[key]
            return flow.export_features(), True

        return None, False

    def expire_inactive_flows(self, current_time: float) -> List[Dict[str, Any]]:
        """
        Finds and evicts flows that have been inactive longer than flow_timeout_seconds.
        """
        expired = []
        keys_to_del = []
        for key, flow in self._active_flows.items():
            if current_time - flow.last_seen_time >= self.flow_timeout_seconds:
                flow.is_terminated = True
                flow.termination_reason = "inactivity_timeout"
                expired.append(flow.export_features())
                keys_to_del.append(key)

        for k in keys_to_del:
            del self._active_flows[k]

        return expired

    def drain_all_flows(self) -> List[Dict[str, Any]]:
        """
        Drains all remaining active flows (used on session stop or end of PCAP file).
        """
        drained = [flow.export_features() for flow in self._active_flows.values()]
        self._active_flows.clear()
        return drained
