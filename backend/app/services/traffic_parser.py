import os
import time
import math
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
import numpy as np

logger = logging.getLogger(__name__)

class TrafficParserService:
    """
    Parses PCAP and PCAPNG files into network flows and extracts statistical
    features compatible with CICIDS2017 and UNSW-NB15 feature schemas.
    """

    @staticmethod
    def parse_pcap_to_flows(pcap_path: str, max_packets: int = 10000) -> List[Dict[str, Any]]:
        try:
            from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
        except ImportError:
            raise RuntimeError("Scapy is required for PCAP parsing. Please install scapy.")

        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        # Store packets grouped by 5-tuple flow key: (ip1, ip2, port1, port2, proto)
        # We normalize direction so bidirectional conversation is aggregated into one flow record.
        flows_dict: Dict[Tuple, Dict[str, Any]] = {}

        packet_count = 0
        try:
            with PcapReader(pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1
                    if packet_count > max_packets:
                        logger.warning(f"Hit max packet limit {max_packets} while parsing {pcap_path}")
                        break

                    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                        continue

                    ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto_num = ip_layer.proto if hasattr(ip_layer, "proto") else 0
                    proto_name = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else ("ICMP" if pkt.haslayer(ICMP) else "OTHER"))

                    src_port = 0
                    dst_port = 0
                    tcp_flags = 0
                    win_size = 0
                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        src_port = int(tcp.sport)
                        dst_port = int(tcp.dport)
                        tcp_flags = int(tcp.flags)
                        win_size = int(tcp.window)
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        src_port = int(udp.sport)
                        dst_port = int(udp.dport)

                    pkt_time = float(pkt.time)
                    pkt_len = len(pkt)

                    # Normalize flow key
                    if (src_ip, src_port) <= (dst_ip, dst_port):
                        flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
                        is_forward = True
                    else:
                        flow_key = (dst_ip, src_ip, dst_port, src_port, proto_name)
                        is_forward = False

                    if flow_key not in flows_dict:
                        flows_dict[flow_key] = {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": proto_name,
                            "start_time": pkt_time,
                            "end_time": pkt_time,
                            "fwd_packets": [],
                            "bwd_packets": [],
                            "fwd_times": [],
                            "bwd_times": [],
                            "all_times": [],
                            "fwd_flags": [],
                            "bwd_flags": [],
                            "fwd_win": win_size if is_forward else 0,
                            "bwd_win": 0 if is_forward else win_size,
                            "fwd_header_len": 0,
                            "bwd_header_len": 0,
                        }

                    f = flows_dict[flow_key]
                    f["end_time"] = max(f["end_time"], pkt_time)
                    f["all_times"].append(pkt_time)

                    if is_forward:
                        f["fwd_packets"].append(pkt_len)
                        f["fwd_times"].append(pkt_time)
                        f["fwd_flags"].append(tcp_flags)
                        if pkt.haslayer(TCP):
                            f["fwd_header_len"] += len(pkt[TCP])
                    else:
                        f["bwd_packets"].append(pkt_len)
                        f["bwd_times"].append(pkt_time)
                        f["bwd_flags"].append(tcp_flags)
                        if f["bwd_win"] == 0 and win_size > 0:
                            f["bwd_win"] = win_size
                        if pkt.haslayer(TCP):
                            f["bwd_header_len"] += len(pkt[TCP])

        except Exception as e:
            logger.error(f"Error reading PCAP {pcap_path}: {e}")

        # Convert raw flow structures into feature maps
        extracted_flows = []
        for key, raw in flows_dict.items():
            flow_feat = TrafficParserService._compute_flow_features(raw)
            extracted_flows.append(flow_feat)

        return extracted_flows

    @staticmethod
    def _compute_flow_features(raw: Dict[str, Any]) -> Dict[str, Any]:
        duration = max(0.000001, raw["end_time"] - raw["start_time"])
        fwd_pkts = raw["fwd_packets"]
        bwd_pkts = raw["bwd_packets"]
        all_pkts = fwd_pkts + bwd_pkts

        fwd_cnt = len(fwd_pkts)
        bwd_cnt = len(bwd_pkts)
        tot_cnt = fwd_cnt + bwd_cnt

        fwd_bytes = sum(fwd_pkts)
        bwd_bytes = sum(bwd_pkts)
        tot_bytes = fwd_bytes + bwd_bytes

        # IAT calculations
        def get_iats(times: List[float]):
            if len(times) <= 1:
                return [0.0]
            s_times = sorted(times)
            return [s_times[i] - s_times[i - 1] for i in range(1, len(s_times))]

        flow_iats = get_iats(raw["all_times"])
        fwd_iats = get_iats(raw["fwd_times"])
        bwd_iats = get_iats(raw["bwd_times"])

        # Packet length stats
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
        all_flags = raw["fwd_flags"] + raw["bwd_flags"]
        fin_cnt = sum(1 for f in all_flags if f & 0x01)
        syn_cnt = sum(1 for f in all_flags if f & 0x02)
        rst_cnt = sum(1 for f in all_flags if f & 0x04)
        psh_cnt = sum(1 for f in all_flags if f & 0x08)
        ack_cnt = sum(1 for f in all_flags if f & 0x10)
        urg_cnt = sum(1 for f in all_flags if f & 0x20)
        ece_cnt = sum(1 for f in all_flags if f & 0x40)
        cwe_cnt = sum(1 for f in all_flags if f & 0x80)

        # Microsecond scaling for CICIDS standard
        dur_micro = duration * 1000000.0
        flow_bytes_per_sec = tot_bytes / duration if duration > 0 else 0.0
        flow_pkts_per_sec = tot_cnt / duration if duration > 0 else 0.0
        fwd_pkts_per_sec = fwd_cnt / duration if duration > 0 else 0.0
        bwd_pkts_per_sec = bwd_cnt / duration if duration > 0 else 0.0

        # Construct unified feature dictionary
        features = {
            # CICIDS2017 features
            'ACK Flag Count': ack_cnt,
            'Active Max': 0.0,
            'Active Mean': 0.0,
            'Active Min': 0.0,
            'Active Std': 0.0,
            'Average Packet Size': pkt_len_mean,
            'Avg Bwd Segment Size': bwd_len_mean,
            'Avg Fwd Segment Size': fwd_len_mean,
            'Bwd Header Length': raw["bwd_header_len"],
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
            'CWE Flag Count': cwe_cnt,
            'Destination Port': float(raw["dst_port"]),
            'Down/Up Ratio': (bwd_cnt / fwd_cnt) if fwd_cnt > 0 else 0.0,
            'ECE Flag Count': ece_cnt,
            'FIN Flag Count': fin_cnt,
            'Flow Bytes/s': flow_bytes_per_sec,
            'Flow Duration': dur_micro,
            'Flow IAT Max': float(max(flow_iats)) * 1000000.0,
            'Flow IAT Mean': float(np.mean(flow_iats)) * 1000000.0,
            'Flow IAT Min': float(min(flow_iats)) * 1000000.0,
            'Flow IAT Std': float(np.std(flow_iats)) * 1000000.0 if len(flow_iats) > 1 else 0.0,
            'Flow Packets/s': flow_pkts_per_sec,
            'Fwd Header Length': raw["fwd_header_len"],
            'Fwd Header Length.1': raw["fwd_header_len"],
            'Fwd IAT Max': float(max(fwd_iats)) * 1000000.0,
            'Fwd IAT Mean': float(np.mean(fwd_iats)) * 1000000.0,
            'Fwd IAT Min': float(min(fwd_iats)) * 1000000.0,
            'Fwd IAT Std': float(np.std(fwd_iats)) * 1000000.0 if len(fwd_iats) > 1 else 0.0,
            'Fwd IAT Total': float(sum(fwd_iats)) * 1000000.0,
            'Fwd PSH Flags': psh_cnt if fwd_cnt > 0 else 0,
            'Fwd Packet Length Max': fwd_len_max,
            'Fwd Packet Length Mean': fwd_len_mean,
            'Fwd Packet Length Min': fwd_len_min,
            'Fwd Packet Length Std': fwd_len_std,
            'Fwd Packets/s': fwd_pkts_per_sec,
            'Fwd URG Flags': urg_cnt if fwd_cnt > 0 else 0,
            'Idle Max': 0.0,
            'Idle Mean': 0.0,
            'Idle Min': 0.0,
            'Idle Std': 0.0,
            'Init_Win_bytes_backward': float(raw["bwd_win"]),
            'Init_Win_bytes_forward': float(raw["fwd_win"]),
            'Max Packet Length': pkt_len_max,
            'Min Packet Length': pkt_len_min,
            'PSH Flag Count': psh_cnt,
            'Packet Length Mean': pkt_len_mean,
            'Packet Length Std': pkt_len_std,
            'Packet Length Variance': pkt_len_var,
            'RST Flag Count': rst_cnt,
            'SYN Flag Count': syn_cnt,
            'Subflow Bwd Bytes': float(bwd_bytes),
            'Subflow Bwd Packets': float(bwd_cnt),
            'Subflow Fwd Bytes': float(fwd_bytes),
            'Subflow Fwd Packets': float(fwd_cnt),
            'Total Backward Packets': float(bwd_cnt),
            'Total Fwd Packets': float(fwd_cnt),
            'Total Length of Bwd Packets': float(bwd_bytes),
            'Total Length of Fwd Packets': float(fwd_bytes),
            'URG Flag Count': urg_cnt,
            'act_data_pkt_fwd': float(fwd_cnt),
            'min_seg_size_forward': 20.0 if raw["protocol"] == "TCP" else 8.0,

            # UNSW-NB15 features
            'dur': duration,
            'proto': 6.0 if raw["protocol"] == "TCP" else (17.0 if raw["protocol"] == "UDP" else 1.0),
            'service': 0.0,
            'state': 2.0 if syn_cnt > 0 and ack_cnt > 0 else 1.0,
            'spkts': float(fwd_cnt),
            'dpkts': float(bwd_cnt),
            'sbytes': float(fwd_bytes),
            'dbytes': float(bwd_bytes),
            'rate': float(tot_cnt / duration) if duration > 0 else 0.0,
            'sttl': 64.0,
            'dttl': 64.0,
            'sload': float((fwd_bytes * 8) / duration) if duration > 0 else 0.0,
            'dload': float((bwd_bytes * 8) / duration) if duration > 0 else 0.0,
            'sloss': 0.0,
            'dloss': 0.0,
            'sinpkt': float(np.mean(fwd_iats) * 1000.0) if fwd_iats else 0.0,
            'dinpkt': float(np.mean(bwd_iats) * 1000.0) if bwd_iats else 0.0,
            'sjit': float(np.std(fwd_iats) * 1000.0) if len(fwd_iats) > 1 else 0.0,
            'djit': float(np.std(bwd_iats) * 1000.0) if len(bwd_iats) > 1 else 0.0,
            'swin': float(raw["fwd_win"]),
            'stcpb': 0.0,
            'dtcpb': 0.0,
            'dwin': float(raw["bwd_win"]),
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
            'is_sm_ips_ports': 1.0 if raw["src_ip"] == raw["dst_ip"] and raw["src_port"] == raw["dst_port"] else 0.0
        }

        # Timestamp representation
        ts = datetime.fromtimestamp(raw["start_time"], tz=timezone.utc) if raw["start_time"] > 0 else datetime.now(timezone.utc)

        return {
            "flow_id": f"flow-{uuid.uuid4().hex[:12]}",
            "timestamp": ts,
            "src_ip": raw["src_ip"],
            "dst_ip": raw["dst_ip"],
            "src_port": raw["src_port"],
            "dst_port": raw["dst_port"],
            "protocol": raw["protocol"],
            "duration": round(duration, 4),
            "packet_count": tot_cnt,
            "byte_count": tot_bytes,
            "features": features
        }
