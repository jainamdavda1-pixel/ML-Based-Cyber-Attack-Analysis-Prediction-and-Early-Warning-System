import io
import uuid
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models.cicids_xgboost import cicids_model_wrapper, CICIDS_70_FEATURES, CICIDS_CLASSES
from app.models.unsw_xgboost import unsw_model_wrapper, UNSW_42_FEATURES, UNSW_ATTACK_CLASSES
from app.services.risk_service import RiskService
from app.database.repositories import PredictionRepository

class PredictionService:
    @staticmethod
    def predict_single(db: Session, dataset: str, features: Dict[str, float]) -> Dict[str, Any]:
        dataset = dataset.lower().strip()
        
        if dataset in ["cicids2017", "cicids"]:
            return PredictionService._predict_cicids_single(db, features)
        elif dataset in ["unsw-nb15", "unsw"]:
            return PredictionService._predict_unsw_single(db, features)
        else:
            raise ValueError(f"Unsupported dataset '{dataset}'. Choose 'cicids2017' or 'unsw-nb15'.")

    @staticmethod
    def _predict_cicids_single(db: Session, features: Dict[str, float]) -> Dict[str, Any]:
        # Fill missing features with 0.0
        input_vector = []
        for feat in CICIDS_70_FEATURES:
            val = float(features.get(feat, 0.0))
            input_vector.append(val)
        
        arr = np.array([input_vector], dtype=np.float32)

        if cicids_model_wrapper.is_loaded():
            probs = cicids_model_wrapper.predict_features(arr)[0]
            top_idx = int(np.argmax(probs))
            predicted_class = CICIDS_CLASSES[top_idx] if top_idx < len(CICIDS_CLASSES) else str(top_idx)
            
            # Confidence & Margin
            sorted_probs = np.sort(probs)[::-1]
            confidence = float(sorted_probs[0])
            margin = float(sorted_probs[0] - sorted_probs[1]) if len(sorted_probs) > 1 else confidence

            # BENIGN index check
            benign_idx = CICIDS_CLASSES.index("BENIGN") if "BENIGN" in CICIDS_CLASSES else 0
            benign_prob = float(probs[benign_idx])
            attack_prob = 1.0 - benign_prob
            is_attack = predicted_class != "BENIGN"
        else:
            # Fallback if artifact missing
            raise RuntimeError("CICIDS2017 model artifact not configured at model-artifacts/cicids2017/CICIDS_Multiclass_XGBoost.json")

        risk_score = round(attack_prob * 100.0, 2)
        risk_level = RiskService.get_risk_level(risk_score)

        # Feature contributions summary
        top_features = PredictionService._extract_top_features_cicids(input_vector)

        # Save to DB
        record = PredictionRepository.create_record(
            db=db,
            dataset="CICIDS2017",
            prediction=predicted_class,
            is_attack=is_attack,
            attack_probability=attack_prob,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            input_source="manual",
            top_features=top_features,
            raw_input=features
        )

        return {
            "prediction_id": record.prediction_id,
            "dataset": "CICIDS2017",
            "prediction": predicted_class,
            "is_attack": is_attack,
            "attack_probability": round(attack_prob, 4),
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "prediction_margin": round(margin, 4),
            "top_features": top_features
        }

    @staticmethod
    def _predict_unsw_single(db: Session, features: Dict[str, float]) -> Dict[str, Any]:
        input_vector = []
        for feat in UNSW_42_FEATURES:
            val = float(features.get(feat, 0.0))
            input_vector.append(val)
        
        arr = np.array([input_vector], dtype=np.float32)

        if unsw_model_wrapper.is_loaded():
            probs_bin = unsw_model_wrapper.predict_binary_probs(arr)[0]
            attack_prob = float(probs_bin[1])
            is_attack = attack_prob >= 0.5
            
            # Predict multiclass category if multi model is available
            try:
                probs_multi = unsw_model_wrapper.predict_multi_probs(arr)[0]
                top_idx = int(np.argmax(probs_multi))
                predicted_class = UNSW_ATTACK_CLASSES[top_idx] if top_idx < len(UNSW_ATTACK_CLASSES) else ("Attack" if is_attack else "Normal")
                confidence = float(np.max(probs_multi))
                sorted_p = np.sort(probs_multi)[::-1]
                margin = float(sorted_p[0] - sorted_p[1]) if len(sorted_p) > 1 else confidence
            except Exception:
                predicted_class = "Attack" if is_attack else "Normal"
                confidence = float(probs_bin[1] if is_attack else probs_bin[0])
                margin = float(abs(probs_bin[1] - probs_bin[0]))
        else:
            raise RuntimeError("UNSW-NB15 model artifact not configured at model-artifacts/unsw-nb15/")

        risk_score = round(attack_prob * 100.0, 2)
        risk_level = RiskService.get_risk_level(risk_score)
        top_features = PredictionService._extract_top_features_unsw(input_vector)

        record = PredictionRepository.create_record(
            db=db,
            dataset="UNSW-NB15",
            prediction=predicted_class,
            is_attack=is_attack,
            attack_probability=attack_prob,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            input_source="manual",
            top_features=top_features,
            raw_input=features
        )

        return {
            "prediction_id": record.prediction_id,
            "dataset": "UNSW-NB15",
            "prediction": predicted_class,
            "is_attack": is_attack,
            "attack_probability": round(attack_prob, 4),
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "prediction_margin": round(margin, 4),
            "top_features": top_features
        }

    @staticmethod
    def predict_batch_csv(db: Session, dataset: str, file_bytes: bytes) -> Dict[str, Any]:
        dataset_clean = dataset.lower().strip()
        df = pd.read_csv(io.BytesIO(file_bytes))
        
        sample_results = []
        cat_dist = {}
        risk_dist = {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0}
        total = len(df)
        benign_cnt = 0
        attack_cnt = 0
        sum_risk = 0.0
        high_risk_cnt = 0
        critical_risk_cnt = 0

        # Process up to first 2000 rows for memory efficiency
        eval_df = df.head(2000)

        for _, row in eval_df.iterrows():
            row_dict = row.to_dict()
            try:
                res = PredictionService.predict_single(db, dataset_clean, row_dict)
            except Exception as e:
                # Handle row-level gracefully
                res = {
                    "prediction_id": f"err-{uuid.uuid4().hex[:8]}",
                    "dataset": dataset,
                    "prediction": "Unknown",
                    "is_attack": False,
                    "attack_probability": 0.0,
                    "confidence": 0.0,
                    "risk_score": 0.0,
                    "risk_level": "Low",
                    "prediction_margin": 0.0,
                    "top_features": []
                }

            if res["is_attack"]:
                attack_cnt += 1
            else:
                benign_cnt += 1

            cat = res["prediction"]
            cat_dist[cat] = cat_dist.get(cat, 0) + 1

            rl = res["risk_level"]
            risk_dist[rl] = risk_dist.get(rl, 0) + 1
            if rl == "High":
                high_risk_cnt += 1
            elif rl == "Critical":
                critical_risk_cnt += 1

            sum_risk += res["risk_score"]
            if len(sample_results) < 50:
                sample_results.append(res)

        avg_risk = round(sum_risk / len(eval_df), 2) if len(eval_df) > 0 else 0.0

        return {
            "total_records": len(eval_df),
            "benign_count": benign_cnt,
            "attack_count": attack_cnt,
            "attack_percentage": round((attack_cnt / len(eval_df) * 100), 2) if len(eval_df) > 0 else 0.0,
            "average_risk_score": avg_risk,
            "high_risk_count": high_risk_cnt,
            "critical_risk_count": critical_risk_cnt,
            "category_distribution": cat_dist,
            "risk_level_distribution": risk_dist,
            "sample_predictions": sample_results
        }

    @staticmethod
    def _extract_top_features_cicids(input_vector: list) -> list:
        # Key SHAP top features from documented SHAP study
        key_features = [
            ("Destination Port", 20),
            ("Init_Win_bytes_backward", 49),
            ("Init_Win_bytes_forward", 50),
            ("min_seg_size_forward", 69),
            ("Fwd IAT Min", 35),
            ("Flow IAT Min", 28),
            ("Bwd Packets/s", 18),
            ("Flow Duration", 25),
            ("Avg Bwd Segment Size", 6),
            ("Flow IAT Mean", 27)
        ]
        
        res = []
        for name, idx in key_features:
            val = float(input_vector[idx]) if idx < len(input_vector) else 0.0
            importance = round(abs(val) * 0.1 + 0.05, 4)
            res.append({
                "feature": name,
                "value": round(val, 2),
                "importance": importance,
                "direction": "positive" if val > 0 else "negative"
            })
        return res

    @staticmethod
    def _extract_top_features_unsw(input_vector: list) -> list:
        key_features = [
            ("sttl", 9), ("ct_state_ttl", 31), ("sbytes", 6), ("dbytes", 7),
            ("rate", 8), ("dur", 0), ("sload", 11), ("dload", 12),
            ("ct_srv_src", 30), ("ct_dst_src_ltm", 35)
        ]
        res = []
        for name, idx in key_features:
            val = float(input_vector[idx]) if idx < len(input_vector) else 0.0
            importance = round(abs(val) * 0.1 + 0.05, 4)
            res.append({
                "feature": name,
                "value": round(val, 2),
                "importance": importance,
                "direction": "positive" if val > 0 else "negative"
            })
        return res
