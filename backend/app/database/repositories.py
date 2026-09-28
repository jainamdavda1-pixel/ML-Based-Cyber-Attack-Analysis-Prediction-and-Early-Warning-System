import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database.models import PredictionRecord

class PredictionRepository:
    @staticmethod
    def create_record(
        db: Session,
        dataset: str,
        prediction: str,
        is_attack: bool,
        attack_probability: float,
        confidence: float,
        risk_score: float,
        risk_level: str,
        input_source: str = "manual",
        top_features: list = None,
        raw_input: dict = None
    ) -> PredictionRecord:
        record = PredictionRecord(
            prediction_id=f"pred-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            dataset=dataset,
            prediction=prediction,
            is_attack=is_attack,
            attack_probability=round(float(attack_probability), 4),
            confidence=round(float(confidence), 4),
            risk_score=round(float(risk_score), 2),
            risk_level=risk_level,
            input_source=input_source,
            top_features_json=json.dumps(top_features) if top_features else None,
            raw_input_json=json.dumps(raw_input) if raw_input else None,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_history(db: Session, limit: int = 100, dataset: str = None, risk_level: str = None):
        query = db.query(PredictionRecord)
        if dataset:
            query = query.filter(PredictionRecord.dataset == dataset)
        if risk_level:
            query = query.filter(PredictionRecord.risk_level == risk_level)
        return query.order_by(PredictionRecord.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_dashboard_summary(db: Session):
        total = db.query(PredictionRecord).count()
        attacks = db.query(PredictionRecord).filter(PredictionRecord.is_attack == True).count()
        high_risk = db.query(PredictionRecord).filter(PredictionRecord.risk_level == "High").count()
        critical_risk = db.query(PredictionRecord).filter(PredictionRecord.risk_level == "Critical").count()
        
        avg_risk = 0.0
        if total > 0:
            records = db.query(PredictionRecord.risk_score).all()
            avg_risk = sum(r[0] for r in records if r[0] is not None) / total

        recent_alerts = db.query(PredictionRecord).order_by(PredictionRecord.timestamp.desc()).limit(10).all()

        return {
            "total_analyzed": total,
            "attacks_detected": attacks,
            "attack_percentage": round((attacks / total * 100), 2) if total > 0 else 0.0,
            "average_risk_score": round(avg_risk, 2),
            "high_risk_count": high_risk,
            "critical_risk_count": critical_risk,
            "recent_alerts": [
                {
                    "prediction_id": r.prediction_id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                    "dataset": r.dataset,
                    "prediction": r.prediction,
                    "is_attack": r.is_attack,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "confidence": r.confidence,
                    "input_source": r.input_source
                }
                for r in recent_alerts
            ]
        }
