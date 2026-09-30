import os
import time
import uuid
import logging
from typing import List, Dict, Any
from app.services.flow_aggregator import CanonicalFlowAggregator

logger = logging.getLogger(__name__)

class TrafficParserService:
    """
    Parses PCAP and PCAPNG files into canonical bidirectional network flows.
    Extracts statistical features using CanonicalFlowAggregator.
    """

    @staticmethod
    def parse_pcap_to_flows(pcap_path: str, max_packets: int = 10000) -> List[Dict[str, Any]]:
        try:
            from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
        except ImportError:
            raise RuntimeError("Scapy is required for PCAP parsing. Please install scapy.")

        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        aggregator = CanonicalFlowAggregator(flow_timeout_seconds=30.0, max_active_flows=10000)
        completed_flows: List[Dict[str, Any]] = []

        packet_count = 0
        try:
            with PcapReader(pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1
                    if packet_count > max_packets:
                        logger.warning(f"Reached maximum packet parse limit ({max_packets}) in {pcap_path}")
                        break

                    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                        continue

                    ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto_name = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else ("ICMP" if pkt.haslayer(ICMP) else "OTHER"))

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

                    flow_feat, is_term = aggregator.ingest_packet(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto_name,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        tcp_flags=tcp_flags,
                        win_size=win_size,
                        header_len=header_len
                    )

                    if is_term and flow_feat:
                        completed_flows.append(flow_feat)

        except Exception as e:
            logger.error(f"Error reading PCAP {pcap_path}: {e}")

        # Drain any remaining active flows at the end of capture
        drained_flows = aggregator.drain_all_flows()
        completed_flows.extend(drained_flows)

        logger.info(f"Extracted {len(completed_flows)} canonical flows from {packet_count} packets in {pcap_path}")
        return completed_flows
