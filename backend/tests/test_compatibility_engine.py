import pytest
from app.services.compatibility_engine import CompatibilityEngine, CompatibilityStatus
from app.ml.registry_metadata import CICIDS_70_FEATURES, UNSW_42_FEATURES

def test_compatibility_exact_match_cicids():
    # Header with exact 70 features + label
    header = ",".join(CICIDS_70_FEATURES) + ",Label\n"
    sample_row = ",".join(["10.0"] * len(CICIDS_70_FEATURES)) + ",BENIGN\n"
    csv_bytes = (header + sample_row).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.EXACT_MATCH
    assert profile["detected_schema"] == "CICIDS2017"
    assert profile["cicids_match_percentage"] == 100.0
    assert "cicids2017-xgboost-multiclass" in profile["compatible_models"]
    assert len(profile["warnings"]) > 0  # Warns that ground truth Label column is safely excluded

def test_compatibility_unsupported_partial_features():
    # 35 features present out of 70 (50% match - partial schema)
    partial_features = CICIDS_70_FEATURES[:35]
    partial_header = ",".join(partial_features) + "\n"
    partial_row = ",".join(["10.0"] * len(partial_features)) + "\n"
    csv_bytes = (partial_header + partial_row).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.UNSUPPORTED
    assert len(profile["compatible_models"]) == 0
    assert "cannot be filled with arbitrary zeros" in profile["explanation"]

def test_compatibility_unsupported_custom_schema():
    custom_header = "ip_src,ip_dst,port,bytes,packets\n"
    custom_row = "1.1.1.1,2.2.2.2,80,100,5\n"
    csv_bytes = (custom_header + custom_row).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.UNSUPPORTED
    assert "Custom" in profile["detected_schema"] or "Unrecognized" in profile["detected_schema"]
    assert len(profile["compatible_models"]) == 0

def test_compatibility_empty_invalid_file():
    profile = CompatibilityEngine.profile_csv(b"", requested_dataset="cicids2017")
    assert profile["status"] == CompatibilityStatus.INVALID_INPUT
    assert len(profile["validation_errors"]) > 0

def test_compatibility_unsw_match():
    header = ",".join(UNSW_42_FEATURES) + ",attack_cat\n"
    sample_row = ",".join(["1.0"] * len(UNSW_42_FEATURES)) + ",Normal\n"
    csv_bytes = (header + sample_row).encode("utf-8")

    profile = CompatibilityEngine.profile_csv(csv_bytes, requested_dataset="unsw-nb15")
    assert profile["status"] == CompatibilityStatus.EXACT_MATCH
    assert profile["detected_schema"] == "UNSW-NB15"
    assert profile["unsw_match_percentage"] == 100.0
    assert "unsw-nb15-xgboost-binary" in profile["compatible_models"]
