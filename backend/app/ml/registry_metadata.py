"""
Centralized Model Metadata, Provenance, Feature Schemas, and Verified Benchmarks.
Authoritative source for Model Registry and Compatibility Engine.
Derived directly from verified evaluation artifacts in results/.
"""
from typing import Dict, Any, List

CICIDS_70_FEATURES: List[str] = [
    'ACK Flag Count', 'Active Max', 'Active Mean', 'Active Min', 'Active Std',
    'Average Packet Size', 'Avg Bwd Segment Size', 'Avg Fwd Segment Size',
    'Bwd Header Length', 'Bwd IAT Max', 'Bwd IAT Mean', 'Bwd IAT Min',
    'Bwd IAT Std', 'Bwd IAT Total', 'Bwd Packet Length Max',
    'Bwd Packet Length Mean', 'Bwd Packet Length Min', 'Bwd Packet Length Std',
    'Bwd Packets/s', 'CWE Flag Count', 'Destination Port', 'Down/Up Ratio',
    'ECE Flag Count', 'FIN Flag Count', 'Flow Bytes/s', 'Flow Duration',
    'Flow IAT Max', 'Flow IAT Mean', 'Flow IAT Min', 'Flow IAT Std',
    'Flow Packets/s', 'Fwd Header Length', 'Fwd Header Length.1',
    'Fwd IAT Max', 'Fwd IAT Mean', 'Fwd IAT Min', 'Fwd IAT Std',
    'Fwd IAT Total', 'Fwd PSH Flags', 'Fwd Packet Length Max',
    'Fwd Packet Length Mean', 'Fwd Packet Length Min', 'Fwd Packet Length Std',
    'Fwd Packets/s', 'Fwd URG Flags', 'Idle Max', 'Idle Mean', 'Idle Min',
    'Idle Std', 'Init_Win_bytes_backward', 'Init_Win_bytes_forward',
    'Max Packet Length', 'Min Packet Length', 'PSH Flag Count',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'RST Flag Count', 'SYN Flag Count', 'Subflow Bwd Bytes',
    'Subflow Bwd Packets', 'Subflow Fwd Bytes', 'Subflow Fwd Packets',
    'Total Backward Packets', 'Total Fwd Packets',
    'Total Length of Bwd Packets', 'Total Length of Fwd Packets',
    'URG Flag Count', 'act_data_pkt_fwd', 'min_seg_size_forward'
]

CICIDS_CLASSES: List[str] = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
    'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
    'SSH-Patator', 'Web Attack - Brute Force', 'Web Attack - SQL Injection',
    'Web Attack - XSS'
]

UNSW_42_FEATURES: List[str] = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt',
    'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt',
    'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

UNSW_ATTACK_CLASSES: List[str] = [
    'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers',
    'Generic', 'Normal', 'Reconnaissance', 'Shellcode', 'Worms'
]

GENERALIZED_10_FEATURES: List[str] = [
    "duration_seconds",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size"
]

GENERALIZED_CLASSES: List[str] = [
    "Normal",
    "Attack"
]

MODEL_REGISTRY_METADATA: Dict[str, Dict[str, Any]] = {
    "cicids2017-xgboost-multiclass": {
        "model_id": "cicids2017-xgboost-multiclass",
        "name": "CICIDS2017 Multiclass XGBoost Classifier",
        "dataset": "CICIDS2017",
        "task": "multiclass_classification",
        "model_architecture": "Gradient Boosted Decision Trees (XGBoost JSON)",
        "features": CICIDS_70_FEATURES,
        "feature_count": len(CICIDS_70_FEATURES),
        "classes": CICIDS_CLASSES,
        "class_count": len(CICIDS_CLASSES),
        "decision_threshold": 0.94,
        "decision_threshold_notes": "Tuned to freeze false positive rate <= 0.05% on 383,203 evaluation test flows (results/cicids2017/Risk_Analysis/CICIDS_Final_Early_Warning_Metrics.json).",
        "supported_input_sources": ["CSV (CICFlowMeter schema)", "PCAP / PCAPNG (Derived Flow Features)", "Live Capture (Canonical Flow Adapter)"],
        "evaluation_metrics": {
            "test_samples": 383203,
            "accuracy": 0.998659,
            "macro_precision": 0.921818,
            "macro_recall": 0.920359,
            "macro_f1": 0.914891,
            "weighted_precision": 0.998810,
            "weighted_recall": 0.998659,
            "weighted_f1": 0.998701,
            "evaluation_split": "Holdout test set (unseen flows during training)",
            "source_report": "results/cicids2017/Metrics/CICIDS_Test_Evaluation_Summary.txt"
        },
        "known_limitations": [
            "Requires exact 70-feature representation with microsecond duration scaling.",
            "Web Attack - XSS and Infiltration classes have lower support in training data.",
            "Requires bidirectional flow statistics (both forward and backward packets)."
        ]
    },
    "unsw-nb15-xgboost-binary": {
        "model_id": "unsw-nb15-xgboost-binary",
        "name": "UNSW-NB15 Binary XGBoost Detector",
        "dataset": "UNSW-NB15",
        "task": "binary_classification",
        "model_architecture": "Gradient Boosted Decision Trees (Joblib serialized)",
        "features": UNSW_42_FEATURES,
        "feature_count": len(UNSW_42_FEATURES),
        "classes": ["Normal", "Attack"],
        "class_count": 2,
        "decision_threshold": 0.50,
        "supported_input_sources": ["CSV (UNSW-NB15 schema)", "PCAP / PCAPNG (Derived Flow Features)", "Live Capture (Canonical Flow Adapter)"],
        "evaluation_metrics": {
            "test_samples": 82332,
            "accuracy": 0.873585,
            "precision": 0.822070,
            "recall": 0.983213,
            "f1_score": 0.895450,
            "roc_auc": 0.983548,
            "evaluation_split": "Official UNSW-NB15 Test Partition",
            "source_report": "results/UNSW-NB15/Metrics/binary_baseline_vs_optimized_metrics.csv"
        },
        "known_limitations": [
            "Requires 42 features including historical connection window counters (ct_srv_src, ct_dst_ltm).",
            "Fuzzers and Exploits have overlapping feature distributions with Generic attacks.",
            "Connection tracking features require stateful multi-connection history."
        ]
    },
    "unsw-nb15-xgboost-multiclass": {
        "model_id": "unsw-nb15-xgboost-multiclass",
        "name": "UNSW-NB15 10-Class Threat Categorizer",
        "dataset": "UNSW-NB15",
        "task": "multiclass_classification",
        "model_architecture": "Gradient Boosted Decision Trees (Joblib serialized)",
        "features": UNSW_42_FEATURES,
        "feature_count": len(UNSW_42_FEATURES),
        "classes": UNSW_ATTACK_CLASSES,
        "class_count": len(UNSW_ATTACK_CLASSES),
        "decision_threshold": 0.50,
        "supported_input_sources": ["CSV (UNSW-NB15 schema)", "PCAP / PCAPNG (Derived Flow Features)", "Live Capture (Canonical Flow Adapter)"],
        "evaluation_metrics": {
            "test_samples": 82332,
            "per_class_f1": {
                "Generic": 0.98,
                "Normal": 0.85,
                "Reconnaissance": 0.87,
                "Exploits": 0.71,
                "Fuzzers": 0.40,
                "DoS": 0.18,
                "Shellcode": 0.51,
                "Worms": 0.53,
                "Analysis": 0.09,
                "Backdoor": 0.07
            },
            "evaluation_split": "Official UNSW-NB15 Test Partition",
            "source_report": "results/UNSW-NB15/Metrics/multiclass_classification_report.csv"
        },
        "known_limitations": [
            "Minority classes (Worms, Analysis, Backdoor) have limited samples in the benchmark partition."
        ]
    },
    "generalized-xgboost-binary": {
        "model_id": "generalized-xgboost-binary",
        "name": "Generalized Cross-Dataset Binary XGBoost Classifier",
        "dataset": "Generalized",
        "task": "binary_classification",
        "model_architecture": "Gradient Boosted Decision Trees with Median SimpleImputer Pipeline",
        "features": GENERALIZED_10_FEATURES,
        "feature_count": len(GENERALIZED_10_FEATURES),
        "classes": GENERALIZED_CLASSES,
        "class_count": len(GENERALIZED_CLASSES),
        "decision_threshold": 0.1743,
        "decision_threshold_notes": "Calibrated on validation set targeting 1% benign false positive rate (threshold = 0.1743).",
        "supported_input_sources": ["CSV (Standardized 10-feature schema or canonical flow telemetry)", "PCAP / PCAPNG (Derived Flow Features)", "Live Capture (Canonical Flow Adapter)"],
        "evaluation_metrics": {
            "validation_target": "1% benign FPR validation target",
            "threshold": 0.1743,
            "feature_representation": "Standard 10 bidirectional duration, packet, byte, rate, and size features."
        },
        "known_limitations": [
            "Evaluates binary normal vs. attack behavior across 10 aggregate flow features; does not classify granular sub-attack families.",
            "Requires non-negative flow duration and packet/byte counters."
        ]
    },
    "isolation-forest-baseline": {
        "model_id": "isolation-forest-baseline",
        "name": "Baseline Unsupervised Isolation Forest Anomaly Detector",
        "dataset": "Generalized",
        "task": "anomaly_detection",
        "model_architecture": "Isolation Forest (300 estimators with SimpleImputer pipeline)",
        "features": GENERALIZED_10_FEATURES,
        "feature_count": len(GENERALIZED_10_FEATURES),
        "classes": ["Inlier / Normal", "Outlier / Anomaly"],
        "class_count": 2,
        "decision_threshold": 0.02341647450041217,
        "decision_threshold_notes": "Decision function threshold calibrated on benign-only quantile targeting 10% benign FPR. Anomaly rule: decision_function_score < threshold.",
        "supported_input_sources": ["CSV (Standardized 10-feature schema or canonical flow telemetry)", "PCAP / PCAPNG (Derived Flow Features)", "Live Capture (Canonical Flow Adapter)"],
        "evaluation_metrics": {
            "validation_rows": 788876,
            "target_benign_fpr": 0.10,
            "validation_benign_fpr": 0.100002,
            "validation_attack_recall": 0.497416,
            "validation_attack_precision": 0.860164,
            "validation_accuracy": 0.677408,
            "status": "experimental_not_production_approved"
        },
        "known_limitations": [
            "Experimental baseline anomaly detector; lower recall on sophisticated low-volume evasion traffic.",
            "High variance on extreme volumetric outliers compared to supervised gradient boosted trees."
        ]
    }
}
