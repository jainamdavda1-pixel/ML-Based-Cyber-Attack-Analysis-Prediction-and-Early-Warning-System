import math
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

TARGET_LABEL_NAMES = {
    "label", "attack_cat", "class", "target", "is_attack", "binary_label",
    "Label", "Class", "Target", "Label.1", "attack", "category", "attack_category",
    "attack_type", "attack_class", "threat_type"
}

PROTOCOL_COLUMN_NAMES = {"protocol", "proto", "Protocol", "Proto", "prot"}
TIMESTAMP_COLUMN_NAMES = {"timestamp", "time", "Timestamp", "Time", "start_time", "st_time"}

def normalize_col(s: str) -> str:
    cleaned = re.sub(r'[\._\-/]+', ' ', str(s).strip().lower())
    return re.sub(r'\s+', ' ', cleaned).strip()

class DatasetEvaluatorService:
    """
    Evaluation-Only Analysis & Potential Threat Analysis Service for Incompatible / Uncalibrated Datasets.
    
    Provides:
    1. Comprehensive exploratory data profiling (summary stats, missingness, duplicates, protocols).
    2. Ground-truth label isolation & class-imbalance analysis (clearly marked as pre-existing annotations).
    3. Explainable rule-based suspicious behavioral indicators (DoS-like rates, port scans, asymmetric flows, high volume).
    4. Unsupervised anomaly detection (Isolation Forest) with explicit limitations.
    5. Record-level evidence compilation for auditing and export.
    """

    @classmethod
    def evaluate_dataset(cls, df: pd.DataFrame, dataset_name: str = "Uploaded Dataset") -> Dict[str, Any]:
        total_records = len(df)
        total_columns = len(df.columns)

        if total_records == 0 or total_columns == 0:
            return {
                "evaluation_status": "EMPTY_DATASET",
                "dataset_name": dataset_name,
                "total_records": 0,
                "total_columns": 0,
                "summary": "Dataset contains no records or columns."
            }

        # 1. Column analysis and data types
        col_types = {str(col): str(dtype) for col, dtype in df.dtypes.items()}
        numeric_cols = list(df.select_dtypes(include=[np.number]).columns)
        categorical_cols = list(df.select_dtypes(exclude=[np.number]).columns)

        # 2. Missing & Infinite Value Checks
        missing_counts = df.isna().sum().to_dict()
        total_missing_cells = sum(missing_counts.values())
        missing_pct = round((total_missing_cells / (total_records * total_columns)) * 100.0, 2)

        # Infinite value check in numeric columns
        inf_counts = {}
        total_inf_cells = 0
        if numeric_cols:
            numeric_vals = df[numeric_cols].to_numpy()
            is_inf_mask = np.isinf(numeric_vals)
            total_inf_cells = int(is_inf_mask.sum())
            for col in numeric_cols:
                cnt = int(np.isinf(df[col].to_numpy()).sum())
                if cnt > 0:
                    inf_counts[str(col)] = cnt

        # 3. Duplicate Records
        duplicate_count = int(df.duplicated().sum())
        duplicate_pct = round((duplicate_count / total_records) * 100.0, 2)

        # 4. Numeric Summary Statistics
        numeric_summary = {}
        if numeric_cols:
            sample_df = df[numeric_cols].head(5000)
            desc = sample_df.describe().to_dict()
            for col, stats in desc.items():
                numeric_summary[str(col)] = {
                    "mean": round(float(stats.get("mean", 0.0)), 4),
                    "std": round(float(stats.get("std", 0.0)), 4) if not math.isnan(stats.get("std", 0.0)) else 0.0,
                    "min": round(float(stats.get("min", 0.0)), 4),
                    "p25": round(float(stats.get("25%", 0.0)), 4),
                    "median": round(float(stats.get("50%", 0.0)), 4),
                    "p75": round(float(stats.get("75%", 0.0)), 4),
                    "max": round(float(stats.get("max", 0.0)), 4),
                }

        # 5. Protocol Distribution
        protocol_dist = {}
        proto_col = next((c for c in df.columns if str(c).strip().lower() in PROTOCOL_COLUMN_NAMES), None)
        if proto_col:
            raw_proto_counts = df[proto_col].astype(str).value_counts().head(10).to_dict()
            protocol_dist = {str(k): int(v) for k, v in raw_proto_counts.items()}

        # 6. Timestamp Span
        timestamp_info = {}
        ts_col = next((c for c in df.columns if str(c).strip().lower() in TIMESTAMP_COLUMN_NAMES), None)
        if ts_col:
            try:
                ts_series = pd.to_datetime(df[ts_col], errors='coerce').dropna()
                if not ts_series.empty:
                    timestamp_info = {
                        "column": str(ts_col),
                        "earliest": ts_series.min().isoformat(),
                        "latest": ts_series.max().isoformat(),
                        "valid_timestamps_count": len(ts_series)
                    }
            except Exception:
                pass

        # 7. Ground-Truth Label Distribution (Explicitly labeled as pre-existing annotations)
        has_ground_truth = False
        label_distribution = {}
        label_col = next((c for c in df.columns if str(c).strip().lower() in TARGET_LABEL_NAMES), None)
        class_imbalance_ratio = None
        
        if label_col:
            has_ground_truth = True
            raw_label_counts = df[label_col].astype(str).value_counts().to_dict()
            label_distribution = {str(k): int(v) for k, v in raw_label_counts.items()}
            counts = list(label_distribution.values())
            if len(counts) >= 2 and min(counts) > 0:
                class_imbalance_ratio = round(max(counts) / min(counts), 2)

        # 8. Potential Threat Analysis & Record-Level Evidence
        threat_analysis = cls._analyze_potential_threats(df, numeric_cols, label_col)

        # 9. Data Quality Warnings
        data_quality_warnings = []
        if missing_pct > 5.0:
            data_quality_warnings.append(f"High missingness: {missing_pct}% of dataset cells contain NaN/null values.")
        if total_inf_cells > 0:
            data_quality_warnings.append(f"Dataset contains {total_inf_cells} infinite values across numeric features.")
        if duplicate_pct > 10.0:
            data_quality_warnings.append(f"High duplicate rate: {duplicate_pct}% of rows are exact duplicates.")
        if class_imbalance_ratio and class_imbalance_ratio > 20.0:
            data_quality_warnings.append(f"Severe class imbalance detected: Majority class is {class_imbalance_ratio}x larger than minority class.")

        return {
            "evaluation_status": "COMPLETED",
            "evaluation_mode": "DATASET_EVALUATION_ONLY",
            "inference_performed": False,
            "inference_skipped_reason": "Dataset feature representation is incompatible with registered XGBoost classifiers. Performed statistical profiling and rule-based anomaly analysis without executing model inference.",
            "dataset_name": dataset_name,
            "total_records": total_records,
            "total_columns": total_columns,
            "numeric_columns_count": len(numeric_cols),
            "categorical_columns_count": len(categorical_cols),
            "missing_cells_total": total_missing_cells,
            "missing_percentage": missing_pct,
            "infinite_cells_total": total_inf_cells,
            "infinite_columns": inf_counts,
            "duplicate_records_count": duplicate_count,
            "duplicate_percentage": duplicate_pct,
            "protocol_distribution": protocol_dist,
            "timestamp_coverage": timestamp_info,
            "has_ground_truth_labels": has_ground_truth,
            "detected_label_column": str(label_col) if label_col else None,
            "label_distribution": label_distribution,
            "class_imbalance_ratio": class_imbalance_ratio,
            "ground_truth_disclaimer": "These values represent pre-existing dataset annotations and were NOT generated by machine learning model inference.",
            "potential_threat_analysis": threat_analysis,
            "data_quality_warnings": data_quality_warnings,
            "sample_feature_statistics": dict(list(numeric_summary.items())[:15])
        }

    @classmethod
    def _analyze_potential_threats(cls, df: pd.DataFrame, numeric_cols: List[str], label_col: Optional[str]) -> Dict[str, Any]:
        """
        Executes explainable rule-based suspicious behavior detection and unsupervised anomaly analysis.
        Does not fabricate probabilities, risk scores, or confirmed attack classifications.
        """
        n_rows = len(df)
        cols_norm = {normalize_col(c): c for c in df.columns}
        
        indicators: List[Dict[str, Any]] = []
        record_flags: Dict[int, List[str]] = {i: [] for i in range(min(n_rows, 1000))}
        record_details: Dict[int, List[str]] = {i: [] for i in range(min(n_rows, 1000))}

        # Helper to fetch Series as numeric
        def get_col(candidates: List[str]) -> Optional[pd.Series]:
            for cand in candidates:
                if cand in df.columns:
                    return pd.to_numeric(df[cand], errors='coerce').fillna(0.0)
                norm_c = normalize_col(cand)
                if norm_c in cols_norm:
                    return pd.to_numeric(df[cols_norm[norm_c]], errors='coerce').fillna(0.0)
            return None

        # Helper to fetch Series as string
        def get_raw_col(candidates: List[str]) -> Optional[pd.Series]:
            for cand in candidates:
                if cand in df.columns:
                    return df[cand].astype(str)
                norm_c = normalize_col(cand)
                if norm_c in cols_norm:
                    return df[cols_norm[norm_c]].astype(str)
            return None

        # -------------------------------------------------------------------
        # Rule 1: High-Rate / DoS-like Volumetric Traffic Indicator
        # -------------------------------------------------------------------
        pkt_rate = get_col(["flow_pkts_s", "flow_packets_s", "fwd_pkts_s", "rate", "packets_per_sec", "pkt_rate"])
        byte_rate = get_col(["flow_byts_s", "flow_bytes_s", "sload", "dload", "bytes_per_sec", "byte_rate"])
        tot_pkts = get_col(["tot_fwd_pkts", "total_fwd_packets", "spkts", "fwd_pkts", "network_packets", "packets"])
        dur = get_col(["flow_duration", "duration", "dur", "flow_dur"])

        rate_series = pkt_rate
        if rate_series is None and tot_pkts is not None and dur is not None:
            # Calculate packets/sec: if dur in us (> 1000), convert to sec
            dur_in_sec = dur.apply(lambda d: d / 1e6 if d > 500.0 else max(d, 0.000001))
            rate_series = tot_pkts / dur_in_sec

        if rate_series is not None and not rate_series.empty:
            # Flag rate > 5,000 pkts/s or 4x IQR above 75th percentile
            p75 = rate_series.quantile(0.75)
            p25 = rate_series.quantile(0.25)
            iqr = p75 - p25
            thresh = max(5000.0, p75 + 3.0 * iqr) if iqr > 0 else 5000.0
            
            mask = rate_series > thresh
            matched_indices = df.index[mask].tolist()
            count = len(matched_indices)
            
            if count > 0:
                max_rate = round(float(rate_series.max()), 2)
                indicators.append({
                    "indicator_id": "IND-DOS-VOLUMETRIC",
                    "name": "High-Rate / DoS-like Traffic Burst",
                    "category": "Volumetric Anomaly",
                    "severity": "HIGH",
                    "detected": True,
                    "affected_records_count": count,
                    "affected_percentage": round((count / n_rows) * 100.0, 2),
                    "relevant_features": ["Packet Rate", "Duration", "Total Packets"],
                    "evidence_summary": f"Observed peak rate of {max_rate:,.1f} pkts/s exceeding threshold of {thresh:,.1f} pkts/s.",
                    "detection_method": "Statistical upper-bound & volumetric rate thresholding (> 5,000 pkts/s or > Q3 + 3*IQR).",
                    "limitations": "High packet rates can occur during legitimate network stress tests, large file transfers, or benchmark workloads; does not confirm malicious denial of service."
                })
                for idx in matched_indices[:1000]:
                    record_flags[idx].append("High-Rate DoS-like Burst")
                    record_details[idx].append(f"Packet Rate: {rate_series.loc[idx]:,.1f} pkts/s")
        else:
            indicators.append({
                "indicator_id": "IND-DOS-VOLUMETRIC",
                "name": "High-Rate / DoS-like Traffic Burst",
                "category": "Volumetric Anomaly",
                "severity": "HIGH",
                "detected": False,
                "affected_records_count": 0,
                "affected_percentage": 0.0,
                "relevant_features": ["Packet Rate", "Duration"],
                "evidence_summary": "Insufficient rate or duration features to evaluate volumetric burst patterns.",
                "detection_method": "Volumetric rate thresholding",
                "limitations": "Requires packet count and flow duration."
            })

        # -------------------------------------------------------------------
        # Rule 2: Port Scanning / Reconnaissance Pattern
        # -------------------------------------------------------------------
        dst_port = get_col(["dst_port", "destination_port", "dport", "port", "Destination Port"])
        src_ip = get_raw_col(["src_ip", "ip_src", "source_ip", "src_addr", "srcip"])
        bwd_pkts = get_col(["tot_bwd_pkts", "total_bwd_packets", "dpkts", "bwd_pkts", "Total Backward Packets"])

        scan_flagged = []
        if dst_port is not None and not dst_port.empty:
            # Case A: If Source IP is present, detect multi-port probing per host
            if src_ip is not None and not src_ip.empty:
                port_counts_per_src = df.groupby(src_ip)[dst_port.name if dst_port.name in df.columns else dst_port].nunique()
                probing_sources = set(port_counts_per_src[port_counts_per_src >= 15].index)
                if probing_sources:
                    scan_mask = src_ip.isin(probing_sources)
                    scan_flagged = df.index[scan_mask].tolist()
            # Case B: If Source IP absent, check for single-packet probes with 0 backward packets
            elif bwd_pkts is not None:
                probe_mask = (bwd_pkts == 0) & (dst_port > 0)
                if probe_mask.sum() > 5:
                    scan_flagged = df.index[probe_mask].tolist()

            count = len(scan_flagged)
            if count > 0:
                indicators.append({
                    "indicator_id": "IND-RECON-PORTSCAN",
                    "name": "Port Scanning / Sequential Reconnaissance",
                    "category": "Reconnaissance Pattern",
                    "severity": "MEDIUM",
                    "detected": True,
                    "affected_records_count": count,
                    "affected_percentage": round((count / n_rows) * 100.0, 2),
                    "relevant_features": ["Destination Port", "Source IP", "Backward Packets"],
                    "evidence_summary": f"Detected {count} connection probes matching horizontal/vertical scanning profiles (fan-out across multiple distinct ports).",
                    "detection_method": "Source host fan-out entropy and unidirectional probe heuristics (>= 15 distinct ports per source or unresponsive single-packet probes).",
                    "limitations": "May flag administrative network discovery, vulnerability scanners, or P2P/gaming traffic."
                })
                for idx in scan_flagged[:1000]:
                    record_flags[idx].append("Port Scanning / Probe")
                    record_details[idx].append(f"Dst Port: {dst_port.loc[idx]}")
        else:
            indicators.append({
                "indicator_id": "IND-RECON-PORTSCAN",
                "name": "Port Scanning / Sequential Reconnaissance",
                "category": "Reconnaissance Pattern",
                "severity": "MEDIUM",
                "detected": False,
                "affected_records_count": 0,
                "affected_percentage": 0.0,
                "relevant_features": ["Destination Port"],
                "evidence_summary": "Port columns unavailable in dataset.",
                "detection_method": "Fan-out entropy heuristics",
                "limitations": "Requires transport port attributes."
            })

        # -------------------------------------------------------------------
        # Rule 3: Asymmetric Connection / Unresponsive Flow Indicator
        # -------------------------------------------------------------------
        fwd_pkts = get_col(["tot_fwd_pkts", "total_fwd_packets", "spkts", "fwd_pkts", "Total Fwd Packets"])
        if fwd_pkts is not None and bwd_pkts is not None:
            asym_mask = (fwd_pkts >= 20) & (bwd_pkts == 0)
            asym_indices = df.index[asym_mask].tolist()
            count = len(asym_indices)
            if count > 0:
                indicators.append({
                    "indicator_id": "IND-ASYM-UNRESPONSIVE",
                    "name": "Asymmetric / Unresponsive Flow Pattern",
                    "category": "Connection Asymmetry",
                    "severity": "LOW",
                    "detected": True,
                    "affected_records_count": count,
                    "affected_percentage": round((count / n_rows) * 100.0, 2),
                    "relevant_features": ["Forward Packets", "Backward Packets"],
                    "evidence_summary": f"Found {count} flows with persistent forward packet bursts (>= 20 packets) receiving zero backward responses.",
                    "detection_method": "Bidirectional packet symmetry evaluation.",
                    "limitations": "Unidirectional UDP telemetry, log streaming, or network blackholes can produce zero backward packets."
                })
                for idx in asym_indices[:1000]:
                    record_flags[idx].append("Asymmetric Unresponsive Flow")
                    record_details[idx].append(f"Fwd Pkts: {fwd_pkts.loc[idx]}, Bwd Pkts: 0")

        # -------------------------------------------------------------------
        # Rule 4: Data Exfiltration / Unusual Payload Transfer Volume
        # -------------------------------------------------------------------
        fwd_bytes = get_col(["totlen_fwd_pkts", "total_length_of_fwd_packets", "sbytes", "fwd_bytes", "bytes_transmitted", "bytes"])
        if fwd_bytes is not None and not fwd_bytes.empty:
            # Outlier bytes (> 10MB or > Q3 + 5*IQR)
            b75 = fwd_bytes.quantile(0.75)
            b25 = fwd_bytes.quantile(0.25)
            b_iqr = b75 - b25
            byte_thresh = max(10_000_000.0, b75 + 4.0 * b_iqr) if b_iqr > 0 else 10_000_000.0
            
            exfil_mask = fwd_bytes > byte_thresh
            exfil_indices = df.index[exfil_mask].tolist()
            count = len(exfil_indices)
            if count > 0:
                max_bytes_mb = round(float(fwd_bytes.max()) / (1024 * 1024), 2)
                indicators.append({
                    "indicator_id": "IND-DATA-EXFIL",
                    "name": "Unusual Outbound Data Volume / Exfiltration Signature",
                    "category": "Volume Anomaly",
                    "severity": "MEDIUM",
                    "detected": True,
                    "affected_records_count": count,
                    "affected_percentage": round((count / n_rows) * 100.0, 2),
                    "relevant_features": ["Forward Bytes", "Payload Volume"],
                    "evidence_summary": f"Detected {count} flows transferring extreme payload volumes (peak: {max_bytes_mb} MB).",
                    "detection_method": "Robust statistical upper dispersion thresholding (> Q3 + 4*IQR or > 10 MB).",
                    "limitations": "Legitimate ISO downloads, database replication, or media streams also generate large byte volumes."
                })
                for idx in exfil_indices[:1000]:
                    record_flags[idx].append("Extreme Data Volume")
                    record_details[idx].append(f"Payload Bytes: {fwd_bytes.loc[idx]:,.0f}")

        # -------------------------------------------------------------------
        # Unsupervised Outlier Analysis (Isolation Forest)
        # -------------------------------------------------------------------
        anomaly_results = {
            "method": "Unsupervised Isolation Forest Outlier Analysis",
            "status": "SKIPPED",
            "total_anomalies_detected": 0,
            "anomaly_percentage": 0.0,
            "features_used": [],
            "limitations": "Unsupervised statistical anomaly score measures feature space distance; statistical outliers do not indicate confirmed attacks."
        }
        
        anomaly_scores: Dict[int, float] = {}

        if len(numeric_cols) >= 2 and n_rows >= 10:
            try:
                # Sample up to 2000 rows for model fitting
                sample_n = min(n_rows, 2000)
                sub_df = df[numeric_cols].head(sample_n).fillna(0.0).replace([np.inf, -np.inf], 0.0)
                
                # Filter zero-variance columns
                std_series = sub_df.std()
                valid_num_cols = std_series[std_series > 0].index.tolist()[:10]
                
                if len(valid_num_cols) >= 2:
                    X = sub_df[valid_num_cols].to_numpy()
                    # Fit Isolation Forest
                    iso = IsolationForest(random_state=42, n_estimators=50)
                    iso.fit(X)
                    raw_scores = iso.score_samples(X)  # Negative anomaly score (lower is more anomalous)
                    
                    # Normalize scores between 0 (normal) and 100 (extreme outlier)
                    min_s, max_s = raw_scores.min(), raw_scores.max()
                    norm_scores = ((max_s - raw_scores) / (max_s - min_s + 1e-9)) * 100.0
                    
                    # Identify statistical outliers (top 15% dispersion or score >= 70)
                    anom_mask = (norm_scores >= 70.0) | (raw_scores <= np.percentile(raw_scores, 15))
                    anom_indices = np.where(anom_mask)[0]
                    
                    anomaly_results["status"] = "COMPLETED"
                    anomaly_results["total_anomalies_detected"] = len(anom_indices)
                    anomaly_results["anomaly_percentage"] = round((len(anom_indices) / sample_n) * 100.0, 2)
                    anomaly_results["features_used"] = valid_num_cols
                    
                    for idx_i in range(sample_n):
                        s_val = round(float(norm_scores[idx_i]), 2)
                        anomaly_scores[idx_i] = s_val
                        if idx_i in anom_indices:
                            record_flags[idx_i].append("Statistical Multidimensional Outlier")
                            record_details[idx_i].append(f"Outlier Index: {s_val}/100")
            except Exception as e:
                logger.warning(f"Isolation Forest execution failed: {e}")
                anomaly_results["status"] = f"ERROR: {str(e)}"

        # -------------------------------------------------------------------
        # Compile Record-Level Evidence Table (Top flagged rows)
        # -------------------------------------------------------------------
        evidence_records: List[Dict[str, Any]] = []
        flagged_row_indices = [idx for idx, flags in record_flags.items() if len(flags) > 0]
        
        # Sort rows by number of flags and anomaly score
        flagged_row_indices.sort(key=lambda idx: (len(record_flags[idx]), anomaly_scores.get(idx, 0.0)), reverse=True)
        
        sample_limit = min(50, len(flagged_row_indices)) if flagged_row_indices else min(10, n_rows)
        selected_indices = flagged_row_indices[:sample_limit] if flagged_row_indices else list(range(sample_limit))

        for idx in selected_indices:
            row_data = df.iloc[idx]
            actual_lbl = str(row_data[label_col]) if label_col and label_col in df.columns else None
            
            # Key feature snippet
            feat_snippet = {}
            for col in numeric_cols[:5]:
                val = row_data[col]
                try:
                    feat_snippet[str(col)] = round(float(val), 2) if not pd.isna(val) else None
                except Exception:
                    feat_snippet[str(col)] = str(val)

            flags = record_flags.get(idx, [])
            details = record_details.get(idx, [])
            evidence_str = "; ".join(details) if details else "No heuristic indicators triggered."

            evidence_records.append({
                "row_index": idx,
                "actual_label": actual_lbl,
                "potential_indicators": flags if flags else ["Baseline / Unflagged"],
                "statistical_outlier_score": anomaly_scores.get(idx, 0.0),
                "evidence_details": evidence_str,
                "key_features": feat_snippet
            })

        return {
            "threat_analysis_performed": True,
            "threat_analysis_status": "COMPLETED",
            "active_indicators_count": sum(1 for ind in indicators if ind["detected"]),
            "indicators": indicators,
            "anomaly_detector": anomaly_results,
            "record_level_evidence": evidence_records,
            "disclaimer": "Potential threat indicators are derived from rule-based thresholds and unsupervised statistical dispersion. They identify suspicious behavioral anomalies and do not constitute confirmed machine learning predictions."
        }
