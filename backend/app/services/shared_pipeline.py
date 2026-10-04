import uuid
import logging
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.core.config import settings
from app.ml.registry_metadata import (
    CICIDS_70_FEATURES, CICIDS_CLASSES,
    UNSW_42_FEATURES, UNSW_ATTACK_CLASSES,
    GENERALIZED_10_FEATURES, GENERALIZED_CLASSES
)
from app.models.cicids_xgboost import cicids_model_wrapper
from app.models.unsw_xgboost import unsw_model_wrapper
from app.models.generalized_xgboost import generalized_xgb_wrapper
from app.models.isolation_forest import isolation_forest_wrapper
from app.services.risk_service import RiskService
from app.database.repositories import FlowRepository, IncidentRepository

logger = logging.getLogger(__name__)

class SharedPipelineService:
    """
    Unified traffic processing pipeline supporting CSV, PCAP, and Live Captures.
    Standardizes feature validation, inference, risk estimation, incident correlation,
    and database persistence across data sources.
    """

    @staticmethod
    def process_flow_batch(
        db: Session,
        flows: List[Dict[str, Any]],
        dataset: str = "cicids2017",
        job_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_type: str = "csv",
        persist: bool = True
    ) -> List[Dict[str, Any]]:
        if not flows:
            return []

        dataset_raw = str(dataset).lower().strip()
        if "isolation" in dataset_raw or "iforest" in dataset_raw:
            dataset_norm = "isolation_forest"
            feature_keys = GENERALIZED_10_FEATURES
            model_wrapper = isolation_forest_wrapper
            classes = ["Normal", "Anomaly"]
        elif "gen" in dataset_raw:
            dataset_norm = "generalized"
            feature_keys = GENERALIZED_10_FEATURES
            model_wrapper = generalized_xgb_wrapper
            classes = GENERALIZED_CLASSES
        elif "unsw" in dataset_raw:
            dataset_norm = "unsw-nb15"
            feature_keys = UNSW_42_FEATURES
            model_wrapper = unsw_model_wrapper
            classes = UNSW_ATTACK_CLASSES
        else:
            dataset_norm = "cicids2017"
            feature_keys = CICIDS_70_FEATURES
            model_wrapper = cicids_model_wrapper
            classes = CICIDS_CLASSES

        if not model_wrapper.is_loaded():
            raise RuntimeError(f"Model artifact for {dataset_norm.upper()} is not loaded or configured.")

        results = []
        # Build feature rows with strict feature extraction
        matrix_rows = []
        valid_flows = []
        rejected_flows = []

        for f in flows:
            feat_map = f.get("features", f)
            
            # Check for case-insensitive feature match
            feat_map_lower = {str(k).strip().lower(): v for k, v in feat_map.items()}
            
            row = []
            missing_for_flow = []
            for k in feature_keys:
                if k in feat_map:
                    val = feat_map[k]
                elif k.lower() in feat_map_lower:
                    val = feat_map_lower[k.lower()]
                else:
                    missing_for_flow.append(k)
                    val = 0.0
                
                try:
                    num_val = float(val)
                    if np.isinf(num_val) or np.isnan(num_val):
                        num_val = 0.0
                except (ValueError, TypeError):
                    num_val = 0.0
                row.append(num_val)

            # If more than 20% of required features are missing from a flow, mark as rejected
            if len(missing_for_flow) > 0.2 * len(feature_keys):
                rejected_flows.append(f)
                continue

            matrix_rows.append(row)
            valid_flows.append(f)

        if not valid_flows:
            if rejected_flows:
                raise ValueError(f"All {len(rejected_flows)} input records lack required {dataset_norm.upper()} features and were rejected to prevent inaccurate predictions.")
            return []

        X = np.array(matrix_rows, dtype=np.float32)

        # Run inference
        if dataset_norm == "cicids2017":
            all_probs = model_wrapper.predict_features(X)
        elif dataset_norm == "unsw-nb15":
            all_probs = model_wrapper.predict_multi_probs(X)
        elif dataset_norm == "generalized":
            all_probs = model_wrapper.predict_proba(X)
        else: # isolation_forest
            all_scores = model_wrapper.decision_function(X)

        processed_flow_objects = []

        for i, f in enumerate(valid_flows):
            if dataset_norm == "cicids2017":
                probs = all_probs[i]
                top_idx = int(np.argmax(probs))
                predicted_class = classes[top_idx] if top_idx < len(classes) else str(top_idx)
                sorted_p = np.sort(probs)[::-1]
                confidence = float(sorted_p[0])
                margin = float(sorted_p[0] - sorted_p[1]) if len(sorted_p) > 1 else confidence
                benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
                benign_prob = float(probs[benign_idx])
                attack_prob = 1.0 - benign_prob
                is_attack = predicted_class != "BENIGN"
            elif dataset_norm == "unsw-nb15":
                probs = all_probs[i]
                top_idx = int(np.argmax(probs))
                predicted_class = classes[top_idx] if top_idx < len(classes) else str(top_idx)
                sorted_p = np.sort(probs)[::-1]
                confidence = float(sorted_p[0])
                margin = float(sorted_p[0] - sorted_p[1]) if len(sorted_p) > 1 else confidence
                norm_idx = classes.index("Normal") if "Normal" in classes else 6
                normal_prob = float(probs[norm_idx])
                attack_prob = 1.0 - normal_prob
                is_attack = predicted_class != "Normal"
            elif dataset_norm == "generalized":
                probs = all_probs[i]
                attack_prob = float(probs[1])
                is_attack = attack_prob >= model_wrapper.threshold
                predicted_class = "Attack" if is_attack else "Normal"
                confidence = float(max(probs[0], probs[1]))
                margin = float(abs(probs[1] - probs[0]))
            else: # isolation_forest
                score = float(all_scores[i])
                is_attack = score < model_wrapper.threshold
                predicted_class = "Anomaly" if is_attack else "Normal"
                attack_prob = round(float(min(1.0, max(0.0, (model_wrapper.threshold - score) * 2.0 + 0.5))) if is_attack else float(max(0.01, min(0.49, 0.5 - (score - model_wrapper.threshold) * 2.0))), 4)
                confidence = round(float(min(1.0, abs(score - model_wrapper.threshold) * 5.0 + 0.5)), 4)
                margin = round(abs(confidence - 0.5), 4)

            risk_score = round(attack_prob * 100.0, 2)
            risk_level = RiskService.get_risk_level(risk_score)

            dataset_display = (
                "CICIDS2017" if dataset_norm == "cicids2017"
                else ("UNSW-NB15" if dataset_norm == "unsw-nb15"
                else ("Generalized-XGB" if dataset_norm == "generalized" else "Isolation-Forest"))
            )

            flow_res = {
                "flow_id": f.get("flow_id", f"flow-{uuid.uuid4().hex[:12]}"),
                "job_id": job_id,
                "session_id": session_id,
                "source_type": source_type,
                "timestamp": f.get("timestamp"),
                "src_ip": f.get("src_ip", "127.0.0.1"),
                "dst_ip": f.get("dst_ip", "127.0.0.1"),
                "src_port": int(f.get("src_port", 0)),
                "dst_port": int(f.get("dst_port", 0)),
                "protocol": f.get("protocol", "TCP"),
                "duration": float(f.get("duration", 0.0)),
                "packet_count": int(f.get("packet_count", 1)),
                "byte_count": int(f.get("byte_count", 0)),
                "dataset": dataset_display,
                "prediction": predicted_class,
                "is_attack": is_attack,
                "confidence": round(confidence, 4),
                "attack_probability": round(attack_prob, 4),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "prediction_margin": round(margin, 4),
                "features": f.get("features", {})
            }

            processed_flow_objects.append(flow_res)
            results.append(flow_res)

            # Auto-correlate into incident if attack detected
            if is_attack and persist:
                severity = "Critical" if risk_level == "Critical" else ("High" if risk_level == "High" else "Medium")
                title = f"Potential {predicted_class} attack from {flow_res['src_ip']}"
                IncidentRepository.create_or_update_incident(
                    db=db,
                    title=title,
                    src_ip=flow_res["src_ip"],
                    dst_ip=flow_res["dst_ip"],
                    attack_category=predicted_class,
                    severity=severity,
                    risk_score=risk_score,
                    notes=f"Correlated from {source_type} flow analysis ({dataset_display})."
                )

        if persist and processed_flow_objects:
            FlowRepository.bulk_create_flows(db, processed_flow_objects)

        return results
