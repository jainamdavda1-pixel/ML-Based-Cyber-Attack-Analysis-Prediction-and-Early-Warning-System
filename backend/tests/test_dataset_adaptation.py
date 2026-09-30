import pytest
import io
import pandas as pd
import numpy as np
from app.services.compatibility_engine import CompatibilityEngine, CompatibilityStatus
from app.services.dataset_evaluator import DatasetEvaluatorService
from app.services.prediction_service import PredictionService
from app.services.job_service import JobService
from app.database.connection import SessionLocal
from app.ml.registry_metadata import CICIDS_70_FEATURES, UNSW_42_FEATURES

# ---------------------------------------------------------------------------
# Scenario 1: Original CICIDS2017-format data
# ---------------------------------------------------------------------------
def test_scenario_1_original_cicids2017_data():
    sample_values = [
        80.0, 1500.0, 10.0, 8.0, 500.0, 1200.0, 150.0, 40.0, 50.0, 20.0,
        300.0, 40.0, 150.0, 50.0, 1133.3, 12.0, 150.0, 25.0, 300.0, 10.0,
        1000.0, 100.0, 15.0, 200.0, 5.0, 800.0, 100.0, 12.0, 150.0, 5.0,
        0.0, 0.0, 0.0, 0.0, 40.0, 40.0, 6.0, 5.0, 40.0, 300.0,
        94.4, 60.0, 3600.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0,
        0.0, 0.8, 94.4, 50.0, 150.0, 40.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 10.0, 500.0, 8.0, 1200.0, 8192.0, 255.0, 5.0, 32.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ]
    # Keep first 70 values to match CICIDS_70_FEATURES
    row_data = {feat: [val] for feat, val in zip(CICIDS_70_FEATURES, sample_values[:len(CICIDS_70_FEATURES)])}
    row_data["Label"] = ["BENIGN"]
    df = pd.DataFrame(row_data)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.EXACT_MATCH
    assert profile["detected_schema"] == "CICIDS2017"
    assert "cicids2017-xgboost-multiclass" in profile["compatible_models"]
    assert profile["cicids_match_percentage"] == 100.0

    # Ensure transformation isolates label and returns 70 columns
    clean_df = CompatibilityEngine.transform_dataframe(df, "cicids2017")
    assert clean_df.shape == (1, 70)
    assert list(clean_df.columns) == CICIDS_70_FEATURES
    assert "Label" not in clean_df.columns


# ---------------------------------------------------------------------------
# Scenario 2: Original UNSW-NB15-format data
# ---------------------------------------------------------------------------
def test_scenario_2_original_unsw_nb15_data():
    sample_values = [0.12] * len(UNSW_42_FEATURES)
    row_data = {feat: [val] for feat, val in zip(UNSW_42_FEATURES, sample_values)}
    row_data["attack_cat"] = ["Normal"]
    row_data["label"] = [0]
    df = pd.DataFrame(row_data)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="unsw-nb15")
    assert profile["status"] == CompatibilityStatus.EXACT_MATCH
    assert profile["detected_schema"] == "UNSW-NB15"
    assert "unsw-nb15-xgboost-binary" in profile["compatible_models"]
    assert profile["unsw_match_percentage"] == 100.0

    clean_df = CompatibilityEngine.transform_dataframe(df, "unsw-nb15")
    assert clean_df.shape == (1, 42)
    assert list(clean_df.columns) == UNSW_42_FEATURES
    assert "attack_cat" not in clean_df.columns
    assert "label" not in clean_df.columns


# ---------------------------------------------------------------------------
# Scenario 3: Compatible dataset with renamed columns (safe aliases)
# ---------------------------------------------------------------------------
def test_scenario_3_safe_aliases_allow_inference():
    # Construct dataframe using lowercase aliases for CICIDS2017
    data = {}
    for feat in CICIDS_70_FEATURES:
        data[feat] = [10.0]
    # Rename some standard features to common flow aliases
    data["dst_port"] = data.pop("Destination Port")
    data["flow_duration"] = data.pop("Flow Duration")
    data["tot_fwd_pkts"] = data.pop("Total Fwd Packets")
    data["tot_bwd_pkts"] = data.pop("Total Backward Packets")
    data["totlen_fwd_pkts"] = data.pop("Total Length of Fwd Packets")
    data["totlen_bwd_pkts"] = data.pop("Total Length of Bwd Packets")
    data["flow_byts_s"] = data.pop("Flow Bytes/s")
    data["flow_pkts_s"] = data.pop("Flow Packets/s")
    data["fin_flag_cnt"] = data.pop("FIN Flag Count")
    data["syn_flag_cnt"] = data.pop("SYN Flag Count")
    data["rst_flag_cnt"] = data.pop("RST Flag Count")
    data["psh_flag_cnt"] = data.pop("PSH Flag Count")
    data["ack_flag_cnt"] = data.pop("ACK Flag Count")

    df = pd.DataFrame(data)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] in [CompatibilityStatus.TRANSFORMABLE, CompatibilityStatus.TRANSFORMED_COMPATIBLE]
    assert len(profile["applied_transformations"]) >= 10
    assert "cicids2017-xgboost-multiclass" in profile["compatible_models"]

    clean_df = CompatibilityEngine.transform_dataframe(df, "cicids2017")
    assert clean_df.shape == (1, 70)
    assert "Destination Port" in clean_df.columns
    assert "Flow Duration" in clean_df.columns


# ---------------------------------------------------------------------------
# Scenario 4: Compatible dataset with verified unit differences
# ---------------------------------------------------------------------------
def test_scenario_4_unit_conversion():
    # Duration provided in seconds (0.0015s = 1500 microseconds)
    data = {}
    for feat in CICIDS_70_FEATURES:
        data[feat] = [50.0]
    data["Flow Duration"] = [0.0015]  # In seconds (< 500s threshold)

    df = pd.DataFrame(data)
    clean_df = CompatibilityEngine.transform_dataframe(df, "cicids2017")
    # Should convert 0.0015 seconds to 1500.0 microseconds
    assert np.isclose(clean_df["Flow Duration"].iloc[0], 1500.0)


# ---------------------------------------------------------------------------
# Scenario 5: Dataset with genuinely derivable features
# ---------------------------------------------------------------------------
def test_scenario_5_mathematical_feature_derivations():
    # Build a dataset where derived metrics (Average Packet Size, Down/Up Ratio, Subflow metrics)
    # are absent, but their base components (fwd/bwd bytes, fwd/bwd pkts) are provided
    data = {}
    for feat in CICIDS_70_FEATURES:
        data[feat] = [10.0]

    # Set explicit base metrics
    data["Total Fwd Packets"] = [20.0]
    data["Total Backward Packets"] = [5.0]
    data["Total Length of Fwd Packets"] = [1000.0]
    data["Total Length of Bwd Packets"] = [500.0]
    data["Fwd Header Length"] = [64.0]

    # Remove derivable features from the input dataframe
    del data["Average Packet Size"]
    del data["Avg Fwd Segment Size"]
    del data["Avg Bwd Segment Size"]
    del data["Down/Up Ratio"]
    del data["Subflow Fwd Packets"]
    del data["Subflow Fwd Bytes"]
    del data["Subflow Bwd Packets"]
    del data["Subflow Bwd Bytes"]
    del data["Fwd Header Length.1"]

    df = pd.DataFrame(data)
    assert "Average Packet Size" not in df.columns

    clean_df = CompatibilityEngine.transform_dataframe(df, "cicids2017")
    assert clean_df.shape == (1, 70)

    # Expected: (1000 + 500) / (20 + 5) = 1500 / 25 = 60.0
    assert np.isclose(clean_df["Average Packet Size"].iloc[0], 60.0)
    # Expected Avg Fwd Segment Size: 1000 / 20 = 50.0
    assert np.isclose(clean_df["Avg Fwd Segment Size"].iloc[0], 50.0)
    # Expected Avg Bwd Segment Size: 500 / 5 = 100.0
    assert np.isclose(clean_df["Avg Bwd Segment Size"].iloc[0], 100.0)
    # Expected Down/Up Ratio: 5 / 20 = 0.25
    assert np.isclose(clean_df["Down/Up Ratio"].iloc[0], 0.25)
    # Subflow identities
    assert np.isclose(clean_df["Subflow Fwd Packets"].iloc[0], 20.0)
    assert np.isclose(clean_df["Subflow Fwd Bytes"].iloc[0], 1000.0)
    assert np.isclose(clean_df["Subflow Bwd Packets"].iloc[0], 5.0)
    assert np.isclose(clean_df["Subflow Bwd Bytes"].iloc[0], 500.0)
    assert np.isclose(clean_df["Fwd Header Length.1"].iloc[0], 64.0)


# ---------------------------------------------------------------------------
# Scenario 6: Dataset missing essential model features (e.g. 14-col summary)
# ---------------------------------------------------------------------------
def test_scenario_6_missing_essential_features_rejected():
    # 14-column basic netflow summary (missing IAT variance, window sizes, stateful metrics)
    basic_14_cols = {
        "src_ip": ["192.168.1.10", "10.0.0.5"],
        "dst_ip": ["192.168.1.1", "172.16.0.1"],
        "src_port": [54321, 49152],
        "dst_port": [80, 443],
        "protocol": [6, 6],
        "timestamp": ["2026-03-15 10:00:00", "2026-03-15 10:00:01"],
        "duration": [1.5, 0.8],
        "fwd_pkts": [10, 5],
        "bwd_pkts": [8, 4],
        "fwd_bytes": [500, 250],
        "bwd_bytes": [1200, 600],
        "flags": ["AP/S", "S"],
        "state": ["CON", "FIN"],
        "label": ["Benign", "Attack"]
    }
    df = pd.DataFrame(basic_14_cols)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.UNSUPPORTED
    assert len(profile["compatible_models"]) == 0
    assert "missing" in profile["explanation"].lower()
    assert "cannot be filled with arbitrary zeros" in profile["explanation"]

    # In batch predict, this must route to DATASET_EVALUATION_ONLY mode without fabricated predictions
    db = SessionLocal()
    try:
        batch_res = PredictionService.predict_batch_csv(db, "cicids2017", csv_bytes)
        assert batch_res["evaluation_mode"] == "DATASET_EVALUATION_ONLY"
        assert batch_res["total_records"] == 2
        assert len(batch_res["sample_predictions"]) == 0
        assert batch_res["attack_count"] == 0
        assert batch_res["average_risk_score"] == 0.0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scenario 7: Dataset with misleading column names but different feature definitions
# ---------------------------------------------------------------------------
def test_scenario_7_misleading_column_names_rejected():
    # Misleading names like "host_score", "connection_confidence", "model_prediction"
    misleading_data = {
        "host_score": [0.95, 0.88],
        "connection_confidence": [0.99, 0.92],
        "model_prediction": ["DDoS", "PortScan"],
        "cpu_load": [45.2, 88.1],
        "memory_free_pct": [30.5, 12.0]
    }
    df = pd.DataFrame(misleading_data)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.UNSUPPORTED
    assert len(profile["compatible_models"]) == 0

    with pytest.raises(ValueError) as excinfo:
        CompatibilityEngine.transform_dataframe(df, "cicids2017")
    assert "missing" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Scenario 8: Dataset with labels from an unfamiliar taxonomy
# ---------------------------------------------------------------------------
def test_scenario_8_unfamiliar_label_taxonomy_evaluation_only():
    unfamiliar_data = {
        "flow_id": [101, 102, 103, 104, 105],
        "device_type": ["PLC", "RTU", "HMI", "PLC", "Gateway"],
        "bytes_transmitted": [400, 85000, 620, 92000, 500],
        "attack_category": ["CryptoMiner", "Mirai_Botnet", "Normal", "C2_Beacon", "Normal"]
    }
    df = pd.DataFrame(unfamiliar_data)
    eval_report = DatasetEvaluatorService.evaluate_dataset(df, dataset_name="SCADA Network Telemetry")

    assert eval_report["evaluation_status"] == "COMPLETED"
    assert eval_report["evaluation_mode"] == "DATASET_EVALUATION_ONLY"
    assert eval_report["inference_performed"] is False
    assert eval_report["has_ground_truth_labels"] is True
    assert eval_report["detected_label_column"] == "attack_category"
    assert "CryptoMiner" in eval_report["label_distribution"]
    assert "Mirai_Botnet" in eval_report["label_distribution"]
    assert "C2_Beacon" in eval_report["label_distribution"]
    assert eval_report["label_distribution"]["Normal"] == 2


# ---------------------------------------------------------------------------
# Prediction Equivalence: Original vs Safely Transformed Records
# ---------------------------------------------------------------------------
def test_prediction_equivalence_original_vs_transformed():
    db = SessionLocal()
    try:
        # Original canonical row
        base_features = {feat: 10.0 for feat in CICIDS_70_FEATURES}
        base_features["Destination Port"] = 443.0
        base_features["Flow Duration"] = 1500.0
        base_features["Total Fwd Packets"] = 20.0
        base_features["Total Backward Packets"] = 10.0
        base_features["Total Length of Fwd Packets"] = 1000.0
        base_features["Total Length of Bwd Packets"] = 2000.0
        base_features["Average Packet Size"] = 100.0
        base_features["Avg Fwd Segment Size"] = 50.0
        base_features["Avg Bwd Segment Size"] = 200.0
        base_features["Down/Up Ratio"] = 0.5
        base_features["Subflow Fwd Packets"] = 20.0
        base_features["Subflow Fwd Bytes"] = 1000.0
        base_features["Subflow Bwd Packets"] = 10.0
        base_features["Subflow Bwd Bytes"] = 2000.0
        base_features["Fwd Header Length.1"] = 10.0

        orig_pred = PredictionService.predict_single(db, "cicids2017", base_features)

        # Transformed row (using aliases and omitting derivable metrics so they are computed dynamically)
        transformed_raw = dict(base_features)
        # Convert Duration to seconds (0.0015s = 1500us)
        transformed_raw["flow_duration"] = 0.0015
        del transformed_raw["Flow Duration"]

        # Rename to aliases
        transformed_raw["dst_port"] = transformed_raw.pop("Destination Port")
        transformed_raw["tot_fwd_pkts"] = transformed_raw.pop("Total Fwd Packets")
        transformed_raw["tot_bwd_pkts"] = transformed_raw.pop("Total Backward Packets")
        transformed_raw["totlen_fwd_pkts"] = transformed_raw.pop("Total Length of Fwd Packets")
        transformed_raw["totlen_bwd_pkts"] = transformed_raw.pop("Total Length of Bwd Packets")

        # Delete derivable fields
        del transformed_raw["Average Packet Size"]
        del transformed_raw["Avg Fwd Segment Size"]
        del transformed_raw["Avg Bwd Segment Size"]
        del transformed_raw["Down/Up Ratio"]
        del transformed_raw["Subflow Fwd Packets"]
        del transformed_raw["Subflow Fwd Bytes"]
        del transformed_raw["Subflow Bwd Packets"]
        del transformed_raw["Subflow Bwd Bytes"]
        del transformed_raw["Fwd Header Length.1"]

        # Add an unrelated extra column to ensure it is cleanly filtered
        transformed_raw["unrelated_metadata_id"] = 9999

        # Run transformation pipeline
        df_trans = pd.DataFrame([transformed_raw])
        clean_df = CompatibilityEngine.transform_dataframe(df_trans, "cicids2017")
        adapted_dict = clean_df.iloc[0].to_dict()

        adapted_pred = PredictionService.predict_single(db, "cicids2017", adapted_dict)

        # Assert predictions and risk calculations are identical
        assert orig_pred["prediction"] == adapted_pred["prediction"]
        assert np.isclose(orig_pred["attack_probability"], adapted_pred["attack_probability"], atol=1e-3)
        assert np.isclose(orig_pred["confidence"], adapted_pred["confidence"], atol=1e-3)
        assert orig_pred["risk_level"] == adapted_pred["risk_level"]
        assert np.isclose(orig_pred["risk_score"], adapted_pred["risk_score"], atol=1e-1)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CICIDS2017 10-Renamed Features Compatibility & Row-by-Row Equivalence Test
# ---------------------------------------------------------------------------
def test_cicids2017_renamed_features_compatibility_upload():
    """
    Directly tests the scenario where a CICIDS2017 sample CSV has 10 traffic features renamed,
    contains 68 flow columns and 2 label columns (Label, binary_label),
    and validates that automatic adaptation achieves 100% compatibility and row-by-row prediction equivalence.
    """
    db = SessionLocal()
    try:
        np.random.seed(42)
        n_rows = 50

        # Construct original canonical dataset
        orig_data = {}
        for feat in CICIDS_70_FEATURES:
            if "Port" in feat:
                orig_data[feat] = np.random.choice([80.0, 443.0, 8080.0, 22.0], size=n_rows)
            elif "Duration" in feat:
                orig_data[feat] = np.random.uniform(5000.0, 5000000.0, size=n_rows)
            elif "Flag" in feat:
                orig_data[feat] = np.random.choice([0.0, 1.0], size=n_rows)
            else:
                orig_data[feat] = np.random.uniform(1.0, 1500.0, size=n_rows)

        # Ensure consistent base values for derived features
        orig_data["Total Fwd Packets"] = np.random.uniform(5.0, 100.0, size=n_rows)
        orig_data["Total Backward Packets"] = np.random.uniform(5.0, 100.0, size=n_rows)
        orig_data["Total Length of Fwd Packets"] = orig_data["Total Fwd Packets"] * np.random.uniform(40.0, 500.0, size=n_rows)
        orig_data["Total Length of Bwd Packets"] = orig_data["Total Backward Packets"] * np.random.uniform(40.0, 500.0, size=n_rows)
        orig_data["Fwd Header Length"] = orig_data["Total Fwd Packets"] * 20.0
        orig_data["Fwd Header Length.1"] = orig_data["Fwd Header Length"]
        orig_data["Average Packet Size"] = (orig_data["Total Length of Fwd Packets"] + orig_data["Total Length of Bwd Packets"]) / (orig_data["Total Fwd Packets"] + orig_data["Total Backward Packets"])
        orig_data["Avg Fwd Segment Size"] = orig_data["Total Length of Fwd Packets"] / orig_data["Total Fwd Packets"]
        orig_data["Avg Bwd Segment Size"] = orig_data["Total Length of Bwd Packets"] / orig_data["Total Backward Packets"]
        orig_data["Down/Up Ratio"] = orig_data["Total Backward Packets"] / orig_data["Total Fwd Packets"]
        orig_data["Subflow Fwd Packets"] = orig_data["Total Fwd Packets"]
        orig_data["Subflow Fwd Bytes"] = orig_data["Total Length of Fwd Packets"]
        orig_data["Subflow Bwd Packets"] = orig_data["Total Backward Packets"]
        orig_data["Subflow Bwd Bytes"] = orig_data["Total Length of Bwd Packets"]

        orig_df = pd.DataFrame(orig_data)
        orig_df["Label"] = ["BENIGN"] * n_rows
        orig_df["binary_label"] = [0] * n_rows

        # Construct renamed dataset (10 renamed traffic features)
        # Note: 68 flow columns in CSV (duplicate Fwd Header Length.1 is absent, and 10 features renamed)
        renamed_df = orig_df.copy()
        
        # 10 renamed traffic feature mappings
        renamed_df = renamed_df.rename(columns={
            "Destination Port": "destination_port",
            "Flow Duration": "flow_duration_us",
            "Total Fwd Packets": "tot_fwd_pkts",
            "Total Backward Packets": "tot_bwd_pkts",
            "Total Length of Fwd Packets": "totlen_fwd_pkts",
            "Total Length of Bwd Packets": "totlen_bwd_pkts",
            "Fwd Header Length": "fwd_header_length",
            "Bwd Header Length": "bwd_header_length",
            "Avg Fwd Segment Size": "avg_fwd_segment_size",
            "Avg Bwd Segment Size": "avg_bwd_segment_size"
        })

        # Remove 2 derivable columns (Fwd Header Length.1 and Average Packet Size) so total flow columns = 68
        if "Fwd Header Length.1" in renamed_df.columns:
            renamed_df = renamed_df.drop(columns=["Fwd Header Length.1"])
        if "Average Packet Size" in renamed_df.columns:
            renamed_df = renamed_df.drop(columns=["Average Packet Size"])

        # Check column counts: 58 exact matches + 10 renamed features = 68 flow columns
        flow_cols = [c for c in renamed_df.columns if c not in ["Label", "binary_label"]]
        assert len(flow_cols) == 68

        renamed_csv_bytes = renamed_df.to_csv(index=False).encode("utf-8")

        # 1. Profile CSV
        profile = CompatibilityEngine.profile_csv(renamed_csv_bytes, requested_dataset="cicids2017")
        assert profile["status"] in [CompatibilityStatus.TRANSFORMABLE, CompatibilityStatus.TRANSFORMED_COMPATIBLE]
        assert profile["cicids_match_percentage"] == 100.0
        assert "cicids2017-xgboost-multiclass" in profile["compatible_models"]
        assert len(profile["missing_features"]) == 0

        # 2. Batch Predict on Original and Renamed CSVs
        orig_csv_bytes = orig_df.to_csv(index=False).encode("utf-8")
        orig_batch = PredictionService.predict_batch_csv(db, "cicids2017", orig_csv_bytes)
        renamed_batch = PredictionService.predict_batch_csv(db, "cicids2017", renamed_csv_bytes)

        assert orig_batch["evaluation_mode"] == "MODEL_INFERENCE"
        assert renamed_batch["evaluation_mode"] == "MODEL_INFERENCE"
        assert orig_batch["total_records"] == n_rows
        assert renamed_batch["total_records"] == n_rows

        # 3. Row-by-row prediction comparison
        for i in range(min(len(orig_batch["sample_predictions"]), len(renamed_batch["sample_predictions"]))):
            p_orig = orig_batch["sample_predictions"][i]
            p_renamed = renamed_batch["sample_predictions"][i]
            assert p_orig["prediction"] == p_renamed["prediction"]
            assert p_orig["risk_level"] == p_renamed["risk_level"]
            assert np.isclose(p_orig["risk_score"], p_renamed["risk_score"], atol=1e-1)
            assert np.isclose(p_orig["confidence"], p_renamed["confidence"], atol=1e-3)
            assert np.isclose(p_orig["attack_probability"], p_renamed["attack_probability"], atol=1e-3)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Potential Threat Analysis: Unlabeled Unfamiliar Network Dataset
# ---------------------------------------------------------------------------
def test_threat_analysis_unlabeled_unfamiliar_traffic():
    # Construct an unfamiliar custom dataset containing volumetric burst flows and port scanning probes
    rows = []
    # 20 normal flows
    for i in range(20):
        rows.append({
            "src_ip": f"10.0.0.{i % 5 + 1}",
            "dst_ip": "172.16.0.100",
            "dst_port": 80,
            "packets": 15,
            "bytes": 2400,
            "duration": 2.5
        })
    # 5 DoS-like high rate flows (e.g. 50,000 pkts in 0.5s = 100,000 pkts/s)
    for i in range(5):
        rows.append({
            "src_ip": "192.168.100.50",
            "dst_ip": "172.16.0.100",
            "dst_port": 80,
            "packets": 50000,
            "bytes": 32000000,
            "duration": 0.5
        })
    # 15 port scanning probe flows from a single source across distinct ports
    for i in range(15):
        rows.append({
            "src_ip": "192.168.200.99",
            "dst_ip": "172.16.0.100",
            "dst_port": 1000 + i,
            "packets": 1,
            "bytes": 40,
            "duration": 0.001
        })

    df = pd.DataFrame(rows)
    eval_res = DatasetEvaluatorService.evaluate_dataset(df, dataset_name="Unlabeled Telemetry")

    assert eval_res["evaluation_status"] == "COMPLETED"
    assert eval_res["inference_performed"] is False
    assert eval_res["has_ground_truth_labels"] is False

    threat_analysis = eval_res["potential_threat_analysis"]
    assert threat_analysis["threat_analysis_performed"] is True
    assert threat_analysis["active_indicators_count"] >= 2

    # Verify DoS indicator triggered
    dos_ind = next(ind for ind in threat_analysis["indicators"] if ind["indicator_id"] == "IND-DOS-VOLUMETRIC")
    assert dos_ind["detected"] is True
    assert dos_ind["affected_records_count"] >= 5
    assert "limitations" in dos_ind

    # Verify Port Scan indicator triggered
    scan_ind = next(ind for ind in threat_analysis["indicators"] if ind["indicator_id"] == "IND-RECON-PORTSCAN")
    assert scan_ind["detected"] is True
    assert scan_ind["affected_records_count"] >= 15

    # Verify Isolation Forest ran on numeric columns
    anom_det = threat_analysis["anomaly_detector"]
    assert anom_det["status"] == "COMPLETED"
    assert anom_det["total_anomalies_detected"] > 0

    # Verify Record-Level Evidence Table
    evidence = threat_analysis["record_level_evidence"]
    assert len(evidence) > 0
    assert "row_index" in evidence[0]
    assert "potential_indicators" in evidence[0]
    assert "evidence_details" in evidence[0]


# ---------------------------------------------------------------------------
# Potential Threat Analysis: Missing Specific Features
# ---------------------------------------------------------------------------
def test_threat_analysis_missing_features_graceful_handling():
    # Dataset missing port columns and packet rate columns
    data = {
        "sensor_id": [f"sensor-{i}" for i in range(30)],
        "temperature": np.random.uniform(20.0, 25.0, size=30),
        "humidity": np.random.uniform(40.0, 60.0, size=30)
    }
    df = pd.DataFrame(data)
    eval_res = DatasetEvaluatorService.evaluate_dataset(df, dataset_name="IoT Environmental Data")

    threat_analysis = eval_res["potential_threat_analysis"]
    assert threat_analysis["threat_analysis_performed"] is True
    # Port scan indicator should report not detected due to unavailable port column
    scan_ind = next(ind for ind in threat_analysis["indicators"] if ind["indicator_id"] == "IND-RECON-PORTSCAN")
    assert scan_ind["detected"] is False
    assert "unavailable" in scan_ind["evidence_summary"].lower()


# ---------------------------------------------------------------------------
# Potential Threat Analysis: Evaluation-Only Export as CSV and JSON
# ---------------------------------------------------------------------------
def test_threat_analysis_export_csv_and_json():
    db = SessionLocal()
    try:
        csv_content = (
            "src_ip,dst_ip,dst_port,packets,bytes,duration,is_attack\n"
            "10.0.0.1,10.0.0.2,80,10,500,1.0,Normal\n"
            "10.0.0.1,10.0.0.2,80,60000,45000000,0.2,Anomaly\n"
            "192.168.1.5,10.0.0.2,22,1,40,0.001,Scan\n"
            "192.168.1.5,10.0.0.2,23,1,40,0.001,Scan\n"
            "192.168.1.5,10.0.0.2,24,1,40,0.001,Scan\n"
        ).encode("utf-8")

        job_res = JobService.create_and_run_csv_job(
            db=db,
            filename="threat_audit_sample.csv",
            content_bytes=csv_content,
            dataset="cicids2017"
        )

        job_id = job_res["job_id"]
        assert job_res["evaluation_mode"] == "DATASET_EVALUATION_ONLY"

        # 1. Export as JSON
        json_str, media_type = JobService.export_job_results(db, job_id, format_type="json")
        assert media_type == "application/json"
        assert "potential_threat_analysis" in json_str
        assert "IND-DOS-VOLUMETRIC" in json_str

        # 2. Export as CSV
        csv_str, media_type = JobService.export_job_results(db, job_id, format_type="csv")
        assert media_type == "text/csv"
        assert "actual_dataset_label" in csv_str
        assert "potential_threat_indicators" in csv_str
        assert "evidence_details" in csv_str
    finally:
        db.close()


