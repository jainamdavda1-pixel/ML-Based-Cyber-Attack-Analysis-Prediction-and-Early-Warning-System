import uuid
import logging
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cicids_xgboost import cicids_model_wrapper, CICIDS_70_FEATURES, CICIDS_CLASSES
from app.models.unsw_xgboost import unsw_model_wrapper, UNSW_42_FEATURES, UNSW_ATTACK_CLASSES
from app.services.risk_service import RiskService
from app.database.repositories import FlowRepository, IncidentRepository, PredictionRepository

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

        dataset_norm = "unsw-nb15" if "unsw" in dataset.lower() else "cicids2017"
        results = []

        # Prepare feature matrices
        if dataset_norm == "cicids2017":
            feature_keys = CICIDS_70_FEATURES
            model_wrapper = cicids_model_wrapper
            classes = CICIDS_CLASSES
        else:
            feature_keys = UNSW_42_FEATURES
            model_wrapper = unsw_model_wrapper
            classes = UNSW_ATTACK_CLASSES

        # Build feature rows
        matrix_rows = []
        for f in flows:
            feat_map = f.get("features", f)
            row = [float(feat_map.get(k, 0.0)) for k in feature_keys]
            matrix_rows.append(row)

        X = np.array(matrix_rows, dtype=np.float32)

        # Run inference
        if dataset_norm == "cicids2017":
            if not model_wrapper.is_loaded():
                raise RuntimeError("CICIDS2017 model artifact is not loaded or configured.")
            all_probs = model_wrapper.predict_features(X)
        else:
            if not model_wrapper.is_loaded():
                raise RuntimeError("UNSW-NB15 model artifact is not loaded or configured.")
            all_probs = model_wrapper.predict_multi_probs(X)

        processed_flow_objects = []

        for i, f in enumerate(flows):
            probs = all_probs[i]
            top_idx = int(np.argmax(probs))
            predicted_class = classes[top_idx] if top_idx < len(classes) else str(top_idx)

            sorted_p = np.sort(probs)[::-1]
            confidence = float(sorted_p[0])
            margin = float(sorted_p[0] - sorted_p[1]) if len(sorted_p) > 1 else confidence

            if dataset_norm == "cicids2017":
                benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
                benign_prob = float(probs[benign_idx])
                attack_prob = 1.0 - benign_prob
                is_attack = predicted_class != "BENIGN"
            else:
                norm_idx = classes.index("Normal") if "Normal" in classes else 6
                normal_prob = float(probs[norm_idx])
                attack_prob = 1.0 - normal_prob
                is_attack = predicted_class != "Normal"

            risk_score = round(attack_prob * 100.0, 2)
            risk_level = RiskService.get_risk_level(risk_score)

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
                "dataset": "CICIDS2017" if dataset_norm == "cicids2017" else "UNSW-NB15",
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
                    notes=f"Correlated from {source_type} flow analysis."
                )

        if persist and processed_flow_objects:
            FlowRepository.bulk_create_flows(db, processed_flow_objects)

        return results
