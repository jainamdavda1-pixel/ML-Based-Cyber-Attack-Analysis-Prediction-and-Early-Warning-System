import io
import math
import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set
import numpy as np
import pandas as pd

from app.ml.registry_metadata import CICIDS_70_FEATURES, UNSW_42_FEATURES, GENERALIZED_10_FEATURES, MODEL_REGISTRY_METADATA

logger = logging.getLogger(__name__)

class CompatibilityStatus:
    EXACT_MATCH = "EXACT_MATCH"
    TRANSFORMABLE = "TRANSFORMABLE"
    TRANSFORMED_COMPATIBLE = "TRANSFORMED_COMPATIBLE"
    NEEDS_FEATURE_EXTRACTION = "NEEDS_FEATURE_EXTRACTION"
    UNSUPPORTED = "UNSUPPORTED"
    INVALID_INPUT = "INVALID_INPUT"
    LOW_RELIABILITY = "LOW_RELIABILITY"

# Label columns to exclude to prevent target leakage
TARGET_LABEL_COLUMNS = {
    "label", "attack_cat", "class", "target", "is_attack", "binary_label",
    "Label", "Class", "Target", "Label.1", "attack", "category", "attack_category",
    "attack_type", "attack_class", "threat_type"
}

def normalize_token(s: str) -> str:
    """
    Normalizes feature names by lowercasing, stripping,
    and replacing underscores, dots, hyphens, and slashes with spaces.
    """
    if not s:
        return ""
    cleaned = re.sub(r'[\._\-/]+', ' ', str(s).strip().lower())
    return re.sub(r'\s+', ' ', cleaned).strip()

# Verified Domain 1-to-1 Column Aliases
CICIDS_COLUMN_ALIASES = {
    # Destination Port
    "destination_port": "Destination Port",
    "dst_port": "Destination Port",
    "dport": "Destination Port",
    "dest_port": "Destination Port",
    "destination.port": "Destination Port",
    "dstport": "Destination Port",
    "target_port": "Destination Port",
    "dst_port_num": "Destination Port",
    "port_dst": "Destination Port",
    "d_port": "Destination Port",

    # Flow Duration
    "flow_duration": "Flow Duration",
    "flow_duration_us": "Flow Duration",
    "flow_duration_usec": "Flow Duration",
    "flow_duration_microseconds": "Flow Duration",
    "duration": "Flow Duration",
    "duration_us": "Flow Duration",
    "duration_usec": "Flow Duration",
    "dur_us": "Flow Duration",
    "flow_dur": "Flow Duration",
    "flow_dur_us": "Flow Duration",
    "flow_duration_s": "Flow Duration",
    "flow_duration_sec": "Flow Duration",
    "duration_sec": "Flow Duration",
    "dur_s": "Flow Duration",

    # Total Fwd Packets
    "tot_fwd_pkts": "Total Fwd Packets",
    "total_fwd_packets": "Total Fwd Packets",
    "total_fwd_pkts": "Total Fwd Packets",
    "fwd_pkts": "Total Fwd Packets",
    "fwd_packets": "Total Fwd Packets",
    "total_forward_packets": "Total Fwd Packets",
    "tot_fwd_pkt": "Total Fwd Packets",
    "fwd_pkt_count": "Total Fwd Packets",
    "fwd_packets_total": "Total Fwd Packets",
    "fwd_pkts_tot": "Total Fwd Packets",
    "tot_fwd_p": "Total Fwd Packets",

    # Total Backward Packets
    "tot_bwd_pkts": "Total Backward Packets",
    "total_bwd_packets": "Total Backward Packets",
    "total_bwd_pkts": "Total Backward Packets",
    "bwd_pkts": "Total Backward Packets",
    "bwd_packets": "Total Backward Packets",
    "total_backward_packets": "Total Backward Packets",
    "tot_bwd_pkt": "Total Backward Packets",
    "bwd_pkt_count": "Total Backward Packets",
    "bwd_packets_total": "Total Backward Packets",
    "bwd_pkts_tot": "Total Backward Packets",
    "tot_bwd_p": "Total Backward Packets",

    # Total Length of Fwd Packets
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packets",
    "total_length_fwd_packets": "Total Length of Fwd Packets",
    "total_len_fwd_pkts": "Total Length of Fwd Packets",
    "tot_len_fwd_pkts": "Total Length of Fwd Packets",
    "total_fwd_bytes": "Total Length of Fwd Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "tot_fwd_bytes": "Total Length of Fwd Packets",
    "fwd_len_tot": "Total Length of Fwd Packets",
    "fwd_bytes_total": "Total Length of Fwd Packets",
    "fwd_tot_len": "Total Length of Fwd Packets",
    "tot_fwd_len": "Total Length of Fwd Packets",

    # Total Length of Bwd Packets
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "total_length_of_bwd_packets": "Total Length of Bwd Packets",
    "total_length_bwd_packets": "Total Length of Bwd Packets",
    "total_len_bwd_pkts": "Total Length of Bwd Packets",
    "tot_len_bwd_pkts": "Total Length of Bwd Packets",
    "total_bwd_bytes": "Total Length of Bwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
    "tot_bwd_bytes": "Total Length of Bwd Packets",
    "bwd_len_tot": "Total Length of Bwd Packets",
    "bwd_bytes_total": "Total Length of Bwd Packets",
    "bwd_tot_len": "Total Length of Bwd Packets",
    "tot_bwd_len": "Total Length of Bwd Packets",

    # Fwd Packet Length Max/Min/Mean/Std
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_packet_length_max": "Fwd Packet Length Max",
    "fwd_pkt_max": "Fwd Packet Length Max",
    "max_fwd_pkt_len": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_packet_length_min": "Fwd Packet Length Min",
    "fwd_pkt_min": "Fwd Packet Length Min",
    "min_fwd_pkt_len": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_packet_length_mean": "Fwd Packet Length Mean",
    "fwd_pkt_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_avg": "Fwd Packet Length Mean",
    "mean_fwd_pkt_len": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "fwd_packet_length_std": "Fwd Packet Length Std",
    "fwd_pkt_std": "Fwd Packet Length Std",
    "std_fwd_pkt_len": "Fwd Packet Length Std",

    # Bwd Packet Length Max/Min/Mean/Std
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_packet_length_max": "Bwd Packet Length Max",
    "bwd_pkt_max": "Bwd Packet Length Max",
    "max_bwd_pkt_len": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_packet_length_min": "Bwd Packet Length Min",
    "bwd_pkt_min": "Bwd Packet Length Min",
    "min_bwd_pkt_len": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_packet_length_mean": "Bwd Packet Length Mean",
    "bwd_pkt_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_avg": "Bwd Packet Length Mean",
    "mean_bwd_pkt_len": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "bwd_packet_length_std": "Bwd Packet Length Std",
    "bwd_pkt_std": "Bwd Packet Length Std",
    "std_bwd_pkt_len": "Bwd Packet Length Std",

    # Flow Bytes/s & Flow Packets/s
    "flow_byts_s": "Flow Bytes/s",
    "flow_bytes_s": "Flow Bytes/s",
    "flow_bytes_sec": "Flow Bytes/s",
    "flow_byte_rate": "Flow Bytes/s",
    "flow_bytes_per_sec": "Flow Bytes/s",
    "bytes_per_sec": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_packets_s": "Flow Packets/s",
    "flow_packets_sec": "Flow Packets/s",
    "flow_packet_rate": "Flow Packets/s",
    "flow_packets_per_sec": "Flow Packets/s",
    "pkts_per_sec": "Flow Packets/s",

    # Flow IAT
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_avg": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",

    # Fwd IAT
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_total": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_avg": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",

    # Bwd IAT
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_total": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_avg": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",

    # Header Length
    "fwd_header_len": "Fwd Header Length",
    "fwd_header_length": "Fwd Header Length",
    "fwd_hdr_len": "Fwd Header Length",
    "fwd_hdr_length": "Fwd Header Length",
    "fwd_header_bytes": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "bwd_header_length": "Bwd Header Length",
    "bwd_hdr_len": "Bwd Header Length",
    "bwd_hdr_length": "Bwd Header Length",
    "bwd_header_bytes": "Bwd Header Length",

    # Packet rates
    "fwd_pkts_s": "Fwd Packets/s",
    "fwd_packets_s": "Fwd Packets/s",
    "fwd_packets_sec": "Fwd Packets/s",
    "fwd_packet_rate": "Fwd Packets/s",
    "fwd_pkts_per_sec": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "bwd_packets_s": "Bwd Packets/s",
    "bwd_packets_sec": "Bwd Packets/s",
    "bwd_packet_rate": "Bwd Packets/s",
    "bwd_pkts_per_sec": "Bwd Packets/s",

    # Packet Length stats
    "pkt_len_min": "Min Packet Length",
    "min_packet_length": "Min Packet Length",
    "min_pkt_len": "Min Packet Length",
    "packet_length_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "max_packet_length": "Max Packet Length",
    "max_pkt_len": "Max Packet Length",
    "packet_length_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "packet_length_mean": "Packet Length Mean",
    "mean_packet_length": "Packet Length Mean",
    "avg_packet_length": "Packet Length Mean",
    "packet_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "packet_length_std": "Packet Length Std",
    "std_packet_length": "Packet Length Std",
    "packet_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "packet_length_variance": "Packet Length Variance",
    "var_packet_length": "Packet Length Variance",
    "packet_len_var": "Packet Length Variance",
    "packet_length_var": "Packet Length Variance",

    # Flags
    "fin_flag_cnt": "FIN Flag Count",
    "fin_flag_count": "FIN Flag Count",
    "fin_flags": "FIN Flag Count",
    "fin_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "syn_flag_count": "SYN Flag Count",
    "syn_flags": "SYN Flag Count",
    "syn_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "rst_flag_count": "RST Flag Count",
    "rst_flags": "RST Flag Count",
    "rst_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "psh_flag_count": "PSH Flag Count",
    "psh_flags": "PSH Flag Count",
    "psh_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "ack_flag_count": "ACK Flag Count",
    "ack_flags": "ACK Flag Count",
    "ack_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "urg_flag_count": "URG Flag Count",
    "urg_flags": "URG Flag Count",
    "urg_cnt": "URG Flag Count",
    "cwe_flag_cnt": "CWE Flag Count",
    "cwe_flag_count": "CWE Flag Count",
    "cwe_flags": "CWE Flag Count",
    "cwe_cnt": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "ece_flag_count": "ECE Flag Count",
    "ece_flags": "ECE Flag Count",
    "ece_cnt": "ECE Flag Count",

    # Derived or other metrics
    "down_up_ratio": "Down/Up Ratio",
    "down_up_rat": "Down/Up Ratio",
    "download_upload_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "average_packet_size": "Average Packet Size",
    "avg_pkt_size": "Average Packet Size",
    "avg_packet_size": "Average Packet Size",
    "packet_size_avg": "Average Packet Size",
    "avg_fwd_segment_size": "Avg Fwd Segment Size",
    "avg_fwd_seg_size": "Avg Fwd Segment Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "avg_bwd_segment_size": "Avg Bwd Segment Size",
    "avg_bwd_seg_size": "Avg Bwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",

    # Subflows
    "subflow_fwd_packets": "Subflow Fwd Packets",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "sfwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_bytes": "Subflow Fwd Bytes",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "sfwd_bytes": "Subflow Fwd Bytes",
    "subflow_bwd_packets": "Subflow Bwd Packets",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "sbwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_bytes": "Subflow Bwd Bytes",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "sbwd_bytes": "Subflow Bwd Bytes",

    # Window sizes & active data
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_win_bytes_forward": "Init_Win_bytes_forward",
    "init_win_bytes_fwd": "Init_Win_bytes_forward",
    "init_win_fwd": "Init_Win_bytes_forward",
    "fwd_init_win_bytes": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "init_win_bytes_backward": "Init_Win_bytes_backward",
    "init_win_bytes_bwd": "Init_Win_bytes_backward",
    "init_win_bwd": "Init_Win_bytes_backward",
    "bwd_init_win_bytes": "Init_Win_bytes_backward",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "act_data_pkts_fwd": "act_data_pkt_fwd",
    "act_data_pkt_forward": "act_data_pkt_fwd",
    "active_data_pkt_fwd": "act_data_pkt_fwd",
    "min_seg_size_forward": "min_seg_size_forward",
    "min_seg_size_fwd": "min_seg_size_forward",
    "min_segment_size_forward": "min_seg_size_forward",

    # Active / Idle
    "active_mean": "Active Mean",
    "active_avg": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_avg": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min"
}

UNSW_COLUMN_ALIASES = {
    # Duration
    "duration": "dur",
    "flow_duration": "dur",
    "flow_dur": "dur",
    "time_duration": "dur",

    # Protocol & Service & State
    "protocol": "proto",
    "service_type": "service",
    "conn_state": "state",
    "connection_state": "state",

    # Packets & Bytes
    "src_bytes": "sbytes",
    "source_bytes": "sbytes",
    "tot_src_bytes": "sbytes",
    "dst_bytes": "dbytes",
    "destination_bytes": "dbytes",
    "tot_dst_bytes": "dbytes",
    "src_pkts": "spkts",
    "source_pkts": "spkts",
    "source_packets": "spkts",
    "tot_src_pkts": "spkts",
    "dst_pkts": "dpkts",
    "destination_pkts": "dpkts",
    "destination_packets": "dpkts",
    "tot_dst_pkts": "dpkts",

    # TTL & Load & Loss
    "src_ttl": "sttl",
    "source_ttl": "sttl",
    "dst_ttl": "dttl",
    "destination_ttl": "dttl",
    "src_load": "sload",
    "source_load": "sload",
    "dst_load": "dload",
    "destination_load": "dload",
    "src_loss": "sloss",
    "source_loss": "sloss",
    "dst_loss": "dloss",
    "destination_loss": "dloss",

    # Inter-packet time & Jitter & Windows
    "src_inter_pkt": "sinpkt",
    "src_inter_packet": "sinpkt",
    "dst_inter_pkt": "dinpkt",
    "dst_inter_packet": "dinpkt",
    "src_jitter": "sjit",
    "dst_jitter": "djit",
    "src_win": "swin",
    "src_window": "swin",
    "dst_win": "dwin",
    "dst_window": "dwin",
    "src_mean": "smean",
    "src_pkt_mean": "smean",
    "dst_mean": "dmean",
    "dst_pkt_mean": "dmean",

    # TCP sequence & RTT
    "src_tcp_base": "stcpb",
    "dst_tcp_base": "dtcpb",
    "tcp_rtt": "tcprtt",
    "syn_ack_time": "synack",
    "ack_data_time": "ackdat",
    "syn_ack": "synack",
    "ack_dat": "ackdat"
}

# Verified Domain 1-to-1 Column Aliases for Generalized 10 Features
GENERALIZED_COLUMN_ALIASES = {
    # duration_seconds
    "dur": "duration_seconds",
    "duration": "duration_seconds",
    "flow_duration": "duration_seconds",
    "flow_duration_s": "duration_seconds",
    "flow_duration_sec": "duration_seconds",
    "flow_duration_seconds": "duration_seconds",
    "duration_s": "duration_seconds",
    "duration_sec": "duration_seconds",
    "flow_dur": "duration_seconds",
    "flow_dur_s": "duration_seconds",
    "flow duration": "duration_seconds",
    "Flow Duration": "duration_seconds",

    # forward_packets
    "spkts": "forward_packets",
    "fwd_pkts": "forward_packets",
    "fwd_packets": "forward_packets",
    "total_fwd_packets": "forward_packets",
    "total_fwd_pkts": "forward_packets",
    "tot_fwd_pkts": "forward_packets",
    "total_forward_packets": "forward_packets",
    "Total Fwd Packets": "forward_packets",
    "total fwd packets": "forward_packets",
    "fwd_pkt_count": "forward_packets",
    "fwd_packets_total": "forward_packets",
    "fwd_pkts_tot": "forward_packets",

    # backward_packets
    "dpkts": "backward_packets",
    "bwd_pkts": "backward_packets",
    "bwd_packets": "backward_packets",
    "total_bwd_packets": "backward_packets",
    "total_bwd_pkts": "backward_packets",
    "tot_bwd_pkts": "backward_packets",
    "total_backward_packets": "backward_packets",
    "Total Backward Packets": "backward_packets",
    "total backward packets": "backward_packets",
    "bwd_pkt_count": "backward_packets",
    "bwd_packets_total": "backward_packets",
    "bwd_pkts_tot": "backward_packets",

    # forward_bytes
    "sbytes": "forward_bytes",
    "fwd_bytes": "forward_bytes",
    "tot_fwd_bytes": "forward_bytes",
    "total_fwd_bytes": "forward_bytes",
    "Total Length of Fwd Packets": "forward_bytes",
    "total length of fwd packets": "forward_bytes",
    "totlen_fwd_pkts": "forward_bytes",
    "total_length_of_fwd_packets": "forward_bytes",
    "total_length_fwd_packets": "forward_bytes",
    "total_len_fwd_pkts": "forward_bytes",
    "tot_len_fwd_pkts": "forward_bytes",
    "fwd_len_tot": "forward_bytes",
    "fwd_tot_len": "forward_bytes",

    # backward_bytes
    "dbytes": "backward_bytes",
    "bwd_bytes": "backward_bytes",
    "tot_bwd_bytes": "backward_bytes",
    "total_bwd_bytes": "backward_bytes",
    "Total Length of Bwd Packets": "backward_bytes",
    "total length of bwd packets": "backward_bytes",
    "totlen_bwd_pkts": "backward_bytes",
    "total_length_of_bwd_packets": "backward_bytes",
    "total_length_bwd_packets": "backward_bytes",
    "total_len_bwd_pkts": "backward_bytes",
    "tot_len_bwd_pkts": "backward_bytes",
    "bwd_len_tot": "backward_bytes",
    "bwd_tot_len": "backward_bytes",

    # total_packets
    "tot_pkts": "total_packets",
    "total_pkts": "total_packets",
    "tot_packets": "total_packets",
    "total_packets": "total_packets",
    "packet_count": "total_packets",
    "pkts": "total_packets",
    "total_flow_packets": "total_packets",

    # total_bytes
    "tot_bytes": "total_bytes",
    "total_bytes": "total_bytes",
    "byte_count": "total_bytes",
    "bytes": "total_bytes",
    "total_flow_bytes": "total_bytes",
    "tot_len": "total_bytes",

    # packets_per_second
    "rate": "packets_per_second",
    "flow_pkts_per_sec": "packets_per_second",
    "Flow Packets/s": "packets_per_second",
    "flow packets/s": "packets_per_second",
    "flow_packets_s": "packets_per_second",
    "pkts_per_sec": "packets_per_second",
    "packet_rate": "packets_per_second",
    "packets_s": "packets_per_second",

    # bytes_per_second
    "flow_bytes_per_sec": "bytes_per_second",
    "Flow Bytes/s": "bytes_per_second",
    "flow bytes/s": "bytes_per_second",
    "flow_bytes_s": "bytes_per_second",
    "bytes_per_sec": "bytes_per_second",
    "byte_rate": "bytes_per_second",
    "bytes_s": "bytes_per_second",

    # average_packet_size
    "avg_packet_size": "average_packet_size",
    "Average Packet Size": "average_packet_size",
    "average packet size": "average_packet_size",
    "avg_pkt_size": "average_packet_size",
    "mean_packet_size": "average_packet_size",
    "packet_size_mean": "average_packet_size",
    "pkt_len_mean": "average_packet_size"
}

class CompatibilityEngine:
    """
    Multi-Stage Input Profiler, Schema Verification, and Feature Adaptation Engine.
    Executes legitimate alias resolution, unit conversion, and mathematical derivations.
    Guarantees that inference is permitted only when a model's exact input specification is fully met.
    """

    @classmethod
    def profile_csv(cls, file_bytes: bytes, requested_dataset: Optional[str] = None) -> Dict[str, Any]:
        if not file_bytes or len(file_bytes) == 0:
            return {
                "status": CompatibilityStatus.INVALID_INPUT,
                "detected_schema": "empty_file",
                "compatible_models": [],
                "models_evaluation": {},
                "mapping_report": [],
                "missing_features": [],
                "extra_features": [],
                "validation_errors": ["Uploaded file is empty (0 bytes)."],
                "warnings": [],
                "recommended_action": "Upload a non-empty CSV file containing valid network flow features.",
                "explanation": "Cannot process an empty input file."
            }

        try:
            df = pd.read_csv(io.BytesIO(file_bytes), nrows=500)
        except Exception as e:
            return {
                "status": CompatibilityStatus.INVALID_INPUT,
                "detected_schema": "unparseable_csv",
                "compatible_models": [],
                "models_evaluation": {},
                "mapping_report": [],
                "missing_features": [],
                "extra_features": [],
                "validation_errors": [f"Failed to parse CSV format: {str(e)}"],
                "warnings": [],
                "recommended_action": "Ensure the uploaded file is a valid standard CSV.",
                "explanation": "Malformed CSV structure could not be parsed."
            }

        if df.empty or len(df.columns) == 0:
            return {
                "status": CompatibilityStatus.INVALID_INPUT,
                "detected_schema": "no_columns",
                "compatible_models": [],
                "models_evaluation": {},
                "mapping_report": [],
                "missing_features": [],
                "extra_features": [],
                "validation_errors": ["CSV file contains no readable columns or rows."],
                "warnings": [],
                "recommended_action": "Check the CSV headers and data rows.",
                "explanation": "CSV structure contains no header row or records."
            }

        raw_columns = list(df.columns)
        cleaned_columns = [str(c).strip() for c in raw_columns]

        # Isolate ground truth labels to prevent target leakage
        feature_columns = [c for c in cleaned_columns if c.lower() not in [tl.lower() for tl in TARGET_LABEL_COLUMNS]]
        detected_labels = [c for c in cleaned_columns if c.lower() in [tl.lower() for tl in TARGET_LABEL_COLUMNS]]

        # Evaluate against CICIDS2017, UNSW-NB15, and Generalized models independently
        cicids_eval = cls._evaluate_model_compatibility(df, feature_columns, "cicids2017")
        unsw_eval = cls._evaluate_model_compatibility(df, feature_columns, "unsw-nb15")
        gen_eval = cls._evaluate_model_compatibility(df, feature_columns, "generalized")

        models_eval = {
            "cicids2017": cicids_eval,
            "unsw_nb15": unsw_eval,
            "generalized": gen_eval
        }

        # Model Selection Decision
        compatible_models = []
        selected_schema = "Unrecognized / Custom Network Schema"
        overall_status = CompatibilityStatus.UNSUPPORTED
        mapping_report = []
        applied_transforms = []
        warnings = []

        if detected_labels:
            warnings.append(f"Ground-truth label column(s) {detected_labels} were detected and isolated from model input features.")

        # Priority 1: Check if requested dataset matches
        req_norm = requested_dataset.lower().strip() if requested_dataset else None

        if req_norm:
            if "gen" in req_norm or "isolation" in req_norm or "iforest" in req_norm:
                if gen_eval["is_inferable"]:
                    overall_status = gen_eval["status"]
                    selected_schema = "Generalized 10-Feature Schema" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted Generalized Schema"
                    compatible_models = ["generalized-xgboost-binary", "isolation-forest-baseline"]
                    mapping_report = gen_eval["mapping_report"]
                    applied_transforms = gen_eval["transformations_summary"]
                else:
                    overall_status = CompatibilityStatus.UNSUPPORTED
                    selected_schema = f"Custom / Incompatible with Generalized Models (Missing {gen_eval['missing_count']} features)"
                    compatible_models = []
                    mapping_report = gen_eval["mapping_report"]
            elif "cicids" in req_norm:
                if cicids_eval["is_inferable"]:
                    overall_status = cicids_eval["status"]
                    selected_schema = "CICIDS2017" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted CICIDS2017"
                    compatible_models = ["cicids2017-xgboost-multiclass"]
                    mapping_report = cicids_eval["mapping_report"]
                    applied_transforms = cicids_eval["transformations_summary"]
                else:
                    overall_status = CompatibilityStatus.UNSUPPORTED
                    selected_schema = f"Custom / Incompatible with CICIDS2017 (Missing {cicids_eval['missing_count']} features)"
                    compatible_models = []
                    mapping_report = cicids_eval["mapping_report"]
            elif "unsw" in req_norm:
                if unsw_eval["is_inferable"]:
                    overall_status = unsw_eval["status"]
                    selected_schema = "UNSW-NB15" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted UNSW-NB15"
                    compatible_models = ["unsw-nb15-xgboost-binary", "unsw-nb15-xgboost-multiclass"]
                    mapping_report = unsw_eval["mapping_report"]
                    applied_transforms = unsw_eval["transformations_summary"]
                else:
                    overall_status = CompatibilityStatus.UNSUPPORTED
                    selected_schema = f"Custom / Incompatible with UNSW-NB15 (Missing {unsw_eval['missing_count']} features)"
                    compatible_models = []
                    mapping_report = unsw_eval["mapping_report"]
            else:
                overall_status = CompatibilityStatus.UNSUPPORTED
                selected_schema = f"Custom / Unknown dataset request '{requested_dataset}'"
                compatible_models = []
                mapping_report = gen_eval["mapping_report"]
        else:
            # Automatic schema discovery across all models
            if cicids_eval["is_inferable"]:
                overall_status = cicids_eval["status"]
                selected_schema = "CICIDS2017" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted CICIDS2017"
                compatible_models = ["cicids2017-xgboost-multiclass"]
                mapping_report = cicids_eval["mapping_report"]
                applied_transforms = cicids_eval["transformations_summary"]
            elif unsw_eval["is_inferable"]:
                overall_status = unsw_eval["status"]
                selected_schema = "UNSW-NB15" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted UNSW-NB15"
                compatible_models = ["unsw-nb15-xgboost-binary", "unsw-nb15-xgboost-multiclass"]
                mapping_report = unsw_eval["mapping_report"]
                applied_transforms = unsw_eval["transformations_summary"]
            elif gen_eval["is_inferable"]:
                overall_status = gen_eval["status"]
                selected_schema = "Generalized 10-Feature Schema" if overall_status == CompatibilityStatus.EXACT_MATCH else "Adapted Generalized Schema"
                compatible_models = ["generalized-xgboost-binary", "isolation-forest-baseline"]
                mapping_report = gen_eval["mapping_report"]
                applied_transforms = gen_eval["transformations_summary"]
            else:
                # Neither model is 100% inferable -> UNSUPPORTED
                overall_status = CompatibilityStatus.UNSUPPORTED
                selected_schema = f"Partial / Custom Schema ({len(feature_columns)} features detected)"
                compatible_models = []
                best_match = max([cicids_eval, unsw_eval, gen_eval], key=lambda x: x["match_percentage"])
                mapping_report = best_match["mapping_report"]

        # Build Explanation and Recommendations
        if overall_status == CompatibilityStatus.EXACT_MATCH:
            explanation = f"Input schema is directly 100% compatible with {selected_schema} model."
            rec = "Proceed with standard inference."
        elif overall_status in [CompatibilityStatus.TRANSFORMABLE, CompatibilityStatus.TRANSFORMED_COMPATIBLE]:
            explanation = f"Dataset successfully adapted to 100% {selected_schema} compliance via legitimate aliases and mathematical derivations."
            rec = f"Apply validated transformations ({len(applied_transforms)} transforms) and run inference."
        else:
            missing_c = cicids_eval["missing_count"]
            missing_u = unsw_eval["missing_count"]
            missing_g = gen_eval["missing_count"]
            explanation = f"Dataset cannot be safely adapted: missing {missing_c} features for CICIDS2017, {missing_u} features for UNSW-NB15, and {missing_g} features for Generalized models. Missing features cannot be filled with arbitrary zeros or fabricated values."
            rec = "Route to Evaluation-Only Mode for statistical exploratory data analysis without model inference."

        return {
            "status": overall_status,
            "detected_schema": selected_schema,
            "compatible_models": compatible_models,
            "total_rows_sampled": len(df),
            "total_columns": len(raw_columns),
            "feature_columns_count": len(feature_columns),
            "models_evaluation": models_eval,
            "mapping_report": mapping_report,
            "applied_transformations": applied_transforms,
            "missing_features": (
                cicids_eval["missing_features"] if "cicids" in selected_schema.lower()
                else (unsw_eval["missing_features"] if "unsw" in selected_schema.lower()
                else gen_eval["missing_features"])
            ),
            "extra_features": [c for c in feature_columns if c not in [m["source_feature"] for m in mapping_report if m["status"] == "mapped"]][:20],
            "cicids_match_percentage": cicids_eval["match_percentage"],
            "unsw_match_percentage": unsw_eval["match_percentage"],
            "generalized_match_percentage": gen_eval["match_percentage"],
            "validation_errors": [],
            "warnings": warnings,
            "recommended_action": rec,
            "explanation": explanation
        }

    @classmethod
    def _evaluate_model_compatibility(cls, df: pd.DataFrame, feature_columns: List[str], target_model_name: str) -> Dict[str, Any]:
        """
        Evaluates a specific model's required features against available columns, aliases, and derivable formulas.
        """
        is_gen = ("gen" in target_model_name.lower() or "isolation" in target_model_name.lower() or "iforest" in target_model_name.lower())
        is_cicids = ("cicids" in target_model_name.lower()) and not is_gen

        if is_gen:
            required_features = GENERALIZED_10_FEATURES
            alias_dict = GENERALIZED_COLUMN_ALIASES
            model_type = "generalized"
        elif is_cicids:
            required_features = CICIDS_70_FEATURES
            alias_dict = CICIDS_COLUMN_ALIASES
            model_type = "cicids"
        else:
            required_features = UNSW_42_FEATURES
            alias_dict = UNSW_COLUMN_ALIASES
            model_type = "unsw"

        input_cols_set = set(feature_columns)
        input_cols_lower = {c.lower(): c for c in feature_columns}
        input_cols_norm = {normalize_token(c): c for c in feature_columns}

        mapping_report = []
        transformations_summary = []
        matched_count = 0
        transformed_count = 0
        derived_count = 0
        missing_features = []

        # Stage 1-4: Direct and Alias Resolution
        resolved_features: Dict[str, Tuple[str, str, str]] = {}

        for target_feat in required_features:
            norm_target = normalize_token(target_feat)
            
            # 1. Exact Match
            if target_feat in input_cols_set:
                matched_count += 1
                resolved_features[target_feat] = (target_feat, "EXACT_MATCH", "Direct feature match with identical schema name.")
            # 2. Case-Insensitive Match
            elif target_feat.lower() in input_cols_lower:
                matched_count += 1
                src_col = input_cols_lower[target_feat.lower()]
                resolved_features[target_feat] = (src_col, "CASE_NORMALIZED", "Case-insensitive exact match.")
            # 3. Canonical Token Normalization Match (e.g. total_fwd_packets -> Total Fwd Packets)
            elif norm_target in input_cols_norm:
                transformed_count += 1
                src_col = input_cols_norm[norm_target]
                transformations_summary.append(f"Normalized '{src_col}' -> '{target_feat}'")
                resolved_features[target_feat] = (src_col, "ALIAS_MAPPED", f"Canonical token normalization ({src_col} -> {target_feat}).")
            else:
                # 4. Explicit Alias Lookup
                matched_alias_src = None
                for alias_key, mapped_feat in alias_dict.items():
                    if mapped_feat == target_feat:
                        if alias_key in input_cols_set:
                            matched_alias_src = alias_key
                            break
                        elif alias_key.lower() in input_cols_lower:
                            matched_alias_src = input_cols_lower[alias_key.lower()]
                            break
                        elif normalize_token(alias_key) in input_cols_norm:
                            matched_alias_src = input_cols_norm[normalize_token(alias_key)]
                            break

                if matched_alias_src:
                    transformed_count += 1
                    assumptions = f"Verified network flow alias mapping for {target_feat}."
                    if is_cicids and target_feat == "Flow Duration":
                        if "us" in matched_alias_src.lower():
                            assumptions = "Verified Flow Duration alias in microseconds (no scaling needed)."
                        elif matched_alias_src.lower() in ["dur", "duration_sec", "flow_duration_s"]:
                            assumptions = "Verified Flow Duration alias in seconds (scaled to microseconds)."
                    elif is_gen and target_feat == "duration_seconds":
                        if "us" in matched_alias_src.lower() or matched_alias_src.lower() == "flow duration":
                            assumptions = "Verified Duration alias in microseconds (scaled to seconds)."
                        else:
                            assumptions = "Verified Duration alias in seconds."
                    transformations_summary.append(f"Mapped alias '{matched_alias_src}' -> '{target_feat}'")
                    resolved_features[target_feat] = (matched_alias_src, "ALIAS_MAPPED", assumptions)

        # Stage 5: Mathematical Derivability for Unresolved Features
        for target_feat in required_features:
            if target_feat in resolved_features:
                src_col, t_type, assumptions = resolved_features[target_feat]
                mapping_report.append({
                    "target_feature": target_feat,
                    "source_feature": src_col,
                    "transform_type": t_type,
                    "assumptions": assumptions,
                    "status": "mapped"
                })
            else:
                # Check Derivability using already resolved base features
                derivable, derivation_rule, used_cols = cls._can_derive_feature(
                    target_feat, model_type, resolved_features, input_cols_norm
                )
                if derivable:
                    derived_count += 1
                    transformations_summary.append(f"Derived '{target_feat}' via formula: {derivation_rule}")
                    mapping_report.append({
                        "target_feature": target_feat,
                        "source_feature": ", ".join(used_cols),
                        "transform_type": "DERIVED_CALCULATION",
                        "assumptions": f"Calculated using formula: {derivation_rule}",
                        "status": "mapped"
                    })
                else:
                    missing_features.append(target_feat)
                    mapping_report.append({
                        "target_feature": target_feat,
                        "source_feature": None,
                        "transform_type": "MISSING",
                        "assumptions": "Feature is unavailable and cannot be legitimately derived.",
                        "status": "missing"
                    })

        total_req = len(required_features)
        total_mapped = matched_count + transformed_count + derived_count
        match_pct = round((total_mapped / total_req) * 100.0, 1)
        is_inferable = (total_mapped == total_req)

        if matched_count == total_req:
            status = CompatibilityStatus.EXACT_MATCH
        elif is_inferable:
            status = CompatibilityStatus.TRANSFORMABLE
        else:
            status = CompatibilityStatus.UNSUPPORTED

        return {
            "model_name": target_model_name,
            "status": status,
            "is_inferable": is_inferable,
            "total_required": total_req,
            "matched_count": matched_count,
            "transformed_count": transformed_count,
            "derived_count": derived_count,
            "missing_count": len(missing_features),
            "match_percentage": match_pct,
            "missing_features": missing_features,
            "mapping_report": mapping_report,
            "transformations_summary": transformations_summary
        }

    @classmethod
    def _can_derive_feature(
        cls,
        feat: str,
        model_type: str,
        resolved: Dict[str, Tuple[str, str, str]],
        input_cols_norm: Dict[str, str]
    ) -> Tuple[bool, str, List[str]]:
        """
        Determines if a missing feature can be mathematically derived from resolved base features.
        """
        if model_type == "generalized":
            has_fwd_pkts = "forward_packets" in resolved
            has_bwd_pkts = "backward_packets" in resolved
            has_fwd_bytes = "forward_bytes" in resolved
            has_bwd_bytes = "backward_bytes" in resolved
            has_tot_pkts = "total_packets" in resolved
            has_tot_bytes = "total_bytes" in resolved
            has_dur = "duration_seconds" in resolved

            if feat == "total_packets" and (has_fwd_pkts and has_bwd_pkts):
                return True, "forward_packets + backward_packets", ["forward_packets", "backward_packets"]
            elif feat == "total_bytes" and (has_fwd_bytes and has_bwd_bytes):
                return True, "forward_bytes + backward_bytes", ["forward_bytes", "backward_bytes"]
            elif feat == "packets_per_second" and ((has_tot_pkts or (has_fwd_pkts and has_bwd_pkts)) and has_dur):
                return True, "total_packets / duration_seconds", ["total_packets", "duration_seconds"]
            elif feat == "bytes_per_second" and ((has_tot_bytes or (has_fwd_bytes and has_bwd_bytes)) and has_dur):
                return True, "total_bytes / duration_seconds", ["total_bytes", "duration_seconds"]
            elif feat == "average_packet_size" and ((has_tot_bytes or (has_fwd_bytes and has_bwd_bytes)) and (has_tot_pkts or (has_fwd_pkts and has_bwd_pkts))):
                return True, "total_bytes / total_packets", ["total_bytes", "total_packets"]

        elif model_type == "cicids":
            has_fwd_len = "Total Length of Fwd Packets" in resolved
            has_bwd_len = "Total Length of Bwd Packets" in resolved
            has_fwd_pkts = "Total Fwd Packets" in resolved
            has_bwd_pkts = "Total Backward Packets" in resolved
            has_dur = "Flow Duration" in resolved
            has_fwd_hdr = "Fwd Header Length" in resolved

            if feat == "Fwd Header Length.1" and has_fwd_hdr:
                return True, "Identity(Fwd Header Length)", ["Fwd Header Length"]
            elif feat == "Average Packet Size" and (has_fwd_len and has_bwd_len and has_fwd_pkts and has_bwd_pkts):
                return True, "(Total Length of Fwd Packets + Total Length of Bwd Packets) / (Total Fwd Packets + Total Backward Packets)", ["Total Length of Fwd Packets", "Total Length of Bwd Packets", "Total Fwd Packets", "Total Backward Packets"]
            elif feat == "Avg Fwd Segment Size" and (has_fwd_len and has_fwd_pkts):
                return True, "Total Length of Fwd Packets / Total Fwd Packets", ["Total Length of Fwd Packets", "Total Fwd Packets"]
            elif feat == "Avg Bwd Segment Size" and (has_bwd_len and has_bwd_pkts):
                return True, "Total Length of Bwd Packets / Total Backward Packets", ["Total Length of Bwd Packets", "Total Backward Packets"]
            elif feat == "Down/Up Ratio" and (has_fwd_pkts and has_bwd_pkts):
                return True, "Total Backward Packets / Total Fwd Packets", ["Total Backward Packets", "Total Fwd Packets"]
            elif feat == "Subflow Fwd Packets" and has_fwd_pkts:
                return True, "Identity(Total Fwd Packets)", ["Total Fwd Packets"]
            elif feat == "Subflow Fwd Bytes" and has_fwd_len:
                return True, "Identity(Total Length of Fwd Packets)", ["Total Length of Fwd Packets"]
            elif feat == "Subflow Bwd Packets" and has_bwd_pkts:
                return True, "Identity(Total Backward Packets)", ["Total Backward Packets"]
            elif feat == "Subflow Bwd Bytes" and has_bwd_len:
                return True, "Identity(Total Length of Bwd Packets)", ["Total Length of Bwd Packets"]
            elif feat == "Flow Bytes/s" and (has_fwd_len and has_bwd_len and has_dur):
                return True, "(Total Length of Fwd Packets + Total Length of Bwd Packets) / (Flow Duration in sec)", ["Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Duration"]
            elif feat == "Flow Packets/s" and (has_fwd_pkts and has_bwd_pkts and has_dur):
                return True, "(Total Fwd Packets + Total Backward Packets) / (Flow Duration in sec)", ["Total Fwd Packets", "Total Backward Packets", "Flow Duration"]
            elif feat == "Fwd Packets/s" and (has_fwd_pkts and has_dur):
                return True, "Total Fwd Packets / (Flow Duration in sec)", ["Total Fwd Packets", "Flow Duration"]
            elif feat == "Bwd Packets/s" and (has_bwd_pkts and has_dur):
                return True, "Total Backward Packets / (Flow Duration in sec)", ["Total Backward Packets", "Flow Duration"]
        else: # unsw
            has_fwd_len = "sbytes" in resolved
            has_bwd_len = "dbytes" in resolved
            has_fwd_pkts = "spkts" in resolved
            has_bwd_pkts = "dpkts" in resolved
            has_dur = "dur" in resolved

            if feat == "smean" and (has_fwd_len and has_fwd_pkts):
                return True, "sbytes / spkts", ["sbytes", "spkts"]
            elif feat == "dmean" and (has_bwd_len and has_bwd_pkts):
                return True, "dbytes / dpkts", ["dbytes", "dpkts"]
            elif feat == "rate" and (has_fwd_pkts and has_bwd_pkts and has_dur):
                return True, "(spkts + dpkts) / dur", ["spkts", "dpkts", "dur"]
            elif feat == "sload" and (has_fwd_len and has_dur):
                return True, "(sbytes * 8) / dur", ["sbytes", "dur"]
            elif feat == "dload" and (has_bwd_len and has_dur):
                return True, "(dbytes * 8) / dur", ["dbytes", "dur"]

        return False, "", []

    @classmethod
    def transform_dataframe(cls, df: pd.DataFrame, target_dataset: str) -> pd.DataFrame:
        """
        Executes multi-stage feature adaptation, alias mapping, unit conversions,
        and mathematical feature derivations to produce an exact model-compliant feature matrix.
        """
        target = target_dataset.lower().strip()
        is_gen = ("gen" in target or "isolation" in target or "iforest" in target)
        is_cicids = ("cicids" in target) and not is_gen

        if is_gen:
            required_features = GENERALIZED_10_FEATURES
            alias_dict = GENERALIZED_COLUMN_ALIASES
        elif is_cicids:
            required_features = CICIDS_70_FEATURES
            alias_dict = CICIDS_COLUMN_ALIASES
        else:
            required_features = UNSW_42_FEATURES
            alias_dict = UNSW_COLUMN_ALIASES

        input_cols_set = set(df.columns)
        input_cols_lower = {str(c).strip().lower(): str(c) for c in df.columns}
        input_cols_norm = {normalize_token(c): str(c) for c in df.columns}

        out_df = pd.DataFrame(index=df.index)

        # 1. Base Feature Resolution & Unit Normalization
        for feat in required_features:
            norm_feat = normalize_token(feat)
            src_col = None

            if feat in input_cols_set:
                src_col = feat
            elif feat.lower() in input_cols_lower:
                src_col = input_cols_lower[feat.lower()]
            elif norm_feat in input_cols_norm:
                src_col = input_cols_norm[norm_feat]
            else:
                for alias_key, mapped_feat in alias_dict.items():
                    if mapped_feat == feat:
                        if alias_key in input_cols_set:
                            src_col = alias_key
                            break
                        elif alias_key.lower() in input_cols_lower:
                            src_col = input_cols_lower[alias_key.lower()]
                            break
                        elif normalize_token(alias_key) in input_cols_norm:
                            src_col = input_cols_norm[normalize_token(alias_key)]
                            break

            if src_col is not None and src_col in df.columns:
                val_series = pd.to_numeric(df[src_col], errors='coerce').fillna(0.0)

                # Unit conversion check for Flow Duration:
                if is_cicids and feat == "Flow Duration":
                    s_name = str(src_col).lower()
                    if "us" in s_name or "micro" in s_name:
                        pass
                    elif "sec" in s_name or s_name.endswith("_s") or s_name == "dur":
                        val_series = val_series * 1000000.0
                    else:
                        s_max = val_series.max()
                        if s_max > 0 and s_max < 500.0:
                            val_series = val_series * 1000000.0
                elif is_gen and feat == "duration_seconds":
                    s_name = str(src_col).lower()
                    if "us" in s_name or "micro" in s_name or s_name in ["flow duration", "flow_duration"]:
                        val_series = val_series / 1000000.0
                    else:
                        s_max = val_series.max()
                        if s_max > 50000.0: # clearly microseconds
                            val_series = val_series / 1000000.0

                val_series = val_series.replace([np.inf, -np.inf], np.nan).fillna(0.0)
                out_df[feat] = val_series

        # 2. Derive missing features mathematically
        if is_gen:
            has_fwd_pkts = "forward_packets" in out_df
            has_bwd_pkts = "backward_packets" in out_df
            has_fwd_bytes = "forward_bytes" in out_df
            has_bwd_bytes = "backward_bytes" in out_df

            if "total_packets" not in out_df and has_fwd_pkts and has_bwd_pkts:
                out_df["total_packets"] = out_df["forward_packets"] + out_df["backward_packets"]

            if "total_bytes" not in out_df and has_fwd_bytes and has_bwd_bytes:
                out_df["total_bytes"] = out_df["forward_bytes"] + out_df["backward_bytes"]

            if "packets_per_second" not in out_df and "total_packets" in out_df and "duration_seconds" in out_df:
                dur_s = out_df["duration_seconds"].replace(0, 0.000001)
                out_df["packets_per_second"] = out_df["total_packets"] / dur_s

            if "bytes_per_second" not in out_df and "total_bytes" in out_df and "duration_seconds" in out_df:
                dur_s = out_df["duration_seconds"].replace(0, 0.000001)
                out_df["bytes_per_second"] = out_df["total_bytes"] / dur_s

            if "average_packet_size" not in out_df and "total_bytes" in out_df and "total_packets" in out_df:
                out_df["average_packet_size"] = out_df["total_bytes"] / out_df["total_packets"].replace(0, 1.0)

        elif is_cicids:
            has_fwd_len = "Total Length of Fwd Packets" in out_df
            has_bwd_len = "Total Length of Bwd Packets" in out_df
            has_fwd_pkts = "Total Fwd Packets" in out_df
            has_bwd_pkts = "Total Backward Packets" in out_df
            has_dur = "Flow Duration" in out_df
            has_fwd_hdr = "Fwd Header Length" in out_df

            if "Fwd Header Length.1" not in out_df and has_fwd_hdr:
                out_df["Fwd Header Length.1"] = out_df["Fwd Header Length"]

            if "Average Packet Size" not in out_df and has_fwd_len and has_bwd_len and has_fwd_pkts and has_bwd_pkts:
                tot_pkts = (out_df["Total Fwd Packets"] + out_df["Total Backward Packets"]).replace(0, 1.0)
                out_df["Average Packet Size"] = (out_df["Total Length of Fwd Packets"] + out_df["Total Length of Bwd Packets"]) / tot_pkts

            if "Avg Fwd Segment Size" not in out_df and has_fwd_len and has_fwd_pkts:
                out_df["Avg Fwd Segment Size"] = out_df["Total Length of Fwd Packets"] / out_df["Total Fwd Packets"].replace(0, 1.0)

            if "Avg Bwd Segment Size" not in out_df and has_bwd_len and has_bwd_pkts:
                out_df["Avg Bwd Segment Size"] = out_df["Total Length of Bwd Packets"] / out_df["Total Backward Packets"].replace(0, 1.0)

            if "Down/Up Ratio" not in out_df and has_fwd_pkts and has_bwd_pkts:
                out_df["Down/Up Ratio"] = out_df["Total Backward Packets"] / out_df["Total Fwd Packets"].replace(0, 1.0)

            if "Subflow Fwd Packets" not in out_df and has_fwd_pkts:
                out_df["Subflow Fwd Packets"] = out_df["Total Fwd Packets"]

            if "Subflow Fwd Bytes" not in out_df and has_fwd_len:
                out_df["Subflow Fwd Bytes"] = out_df["Total Length of Fwd Packets"]

            if "Subflow Bwd Packets" not in out_df and has_bwd_pkts:
                out_df["Subflow Bwd Packets"] = out_df["Total Backward Packets"]

            if "Subflow Bwd Bytes" not in out_df and has_bwd_len:
                out_df["Subflow Bwd Bytes"] = out_df["Total Length of Bwd Packets"]

            if "Flow Bytes/s" not in out_df and has_fwd_len and has_bwd_len and has_dur:
                dur_in_sec = (out_df["Flow Duration"] / 1000000.0).replace(0, 0.000001)
                out_df["Flow Bytes/s"] = (out_df["Total Length of Fwd Packets"] + out_df["Total Length of Bwd Packets"]) / dur_in_sec

            if "Flow Packets/s" not in out_df and has_fwd_pkts and has_bwd_pkts and has_dur:
                dur_in_sec = (out_df["Flow Duration"] / 1000000.0).replace(0, 0.000001)
                out_df["Flow Packets/s"] = (out_df["Total Fwd Packets"] + out_df["Total Backward Packets"]) / dur_in_sec

            if "Fwd Packets/s" not in out_df and has_fwd_pkts and has_dur:
                dur_in_sec = (out_df["Flow Duration"] / 1000000.0).replace(0, 0.000001)
                out_df["Fwd Packets/s"] = out_df["Total Fwd Packets"] / dur_in_sec

            if "Bwd Packets/s" not in out_df and has_bwd_pkts and has_dur:
                dur_in_sec = (out_df["Flow Duration"] / 1000000.0).replace(0, 0.000001)
                out_df["Bwd Packets/s"] = out_df["Total Backward Packets"] / dur_in_sec
        else: # unsw
            has_fwd_len = "sbytes" in out_df
            has_bwd_len = "dbytes" in out_df
            has_fwd_pkts = "spkts" in out_df
            has_bwd_pkts = "dpkts" in out_df
            has_dur = "dur" in out_df

            if "smean" not in out_df and has_fwd_len and has_fwd_pkts:
                out_df["smean"] = out_df["sbytes"] / out_df["spkts"].replace(0, 1.0)

            if "dmean" not in out_df and has_bwd_len and has_bwd_pkts:
                out_df["dmean"] = out_df["dbytes"] / out_df["dpkts"].replace(0, 1.0)

            if "rate" not in out_df and has_fwd_pkts and has_bwd_pkts and has_dur:
                out_df["rate"] = (out_df["spkts"] + out_df["dpkts"]) / out_df["dur"].replace(0, 0.000001)

            if "sload" not in out_df and has_fwd_len and has_dur:
                out_df["sload"] = (out_df["sbytes"] * 8.0) / out_df["dur"].replace(0, 0.000001)

            if "dload" not in out_df and has_bwd_len and has_dur:
                out_df["dload"] = (out_df["dbytes"] * 8.0) / out_df["dur"].replace(0, 0.000001)

        # 3. Final Verification: ensure all required columns exist and are strictly ordered
        missing_final = [f for f in required_features if f not in out_df.columns]
        if missing_final:
            raise ValueError(f"Cannot perform inference: dataset is missing {len(missing_final)} essential features ({missing_final[:5]}...) that cannot be derived.")

        # Clean non-finite values
        clean_matrix = out_df[required_features].apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return clean_matrix
