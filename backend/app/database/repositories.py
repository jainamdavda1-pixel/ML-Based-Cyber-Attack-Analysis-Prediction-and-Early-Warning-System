import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database.models import (
    PredictionRecord, AnalysisJobRecord, FlowRecord, IncidentRecord, MonitoringSessionRecord
)

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
    def get_dashboard_summary(db: Session, dataset: str = None):
        base_query = db.query(PredictionRecord)
        if dataset:
            ds = "UNSW-NB15" if "unsw" in dataset.lower() else "CICIDS2017"
            base_query = base_query.filter(PredictionRecord.dataset == ds)

        total = base_query.count()
        attacks = base_query.filter(PredictionRecord.is_attack == True).count()
        high_risk = base_query.filter(PredictionRecord.risk_level == "High").count()
        critical_risk = base_query.filter(PredictionRecord.risk_level == "Critical").count()
        
        avg_risk = 0.0
        if total > 0:
            records = base_query.with_entities(PredictionRecord.risk_score).all()
            avg_risk = sum(r[0] for r in records if r[0] is not None) / total

        recent_alerts = base_query.order_by(PredictionRecord.timestamp.desc()).limit(10).all()

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

class JobRepository:
    @staticmethod
    def create_job(db: Session, filename: str, file_type: str, dataset: str = "cicids2017") -> AnalysisJobRecord:
        job = AnalysisJobRecord(
            job_id=f"job-{uuid.uuid4().hex[:12]}",
            filename=filename,
            file_type=file_type,
            dataset=dataset,
            status="processing",
            created_at=datetime.now(timezone.utc)
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def get_job(db: Session, job_id: str) -> AnalysisJobRecord:
        return db.query(AnalysisJobRecord).filter(AnalysisJobRecord.job_id == job_id).first()

    @staticmethod
    def list_jobs(db: Session, limit: int = 50) -> list[AnalysisJobRecord]:
        return db.query(AnalysisJobRecord).order_by(AnalysisJobRecord.created_at.desc()).limit(limit).all()

    @staticmethod
    def update_job_status(db: Session, job_id: str, status: str, total: int = 0, analyzed: int = 0, summary: dict = None, error: str = None):
        job = db.query(AnalysisJobRecord).filter(AnalysisJobRecord.job_id == job_id).first()
        if job:
            job.status = status
            job.total_records = total
            job.analyzed_records = analyzed
            if summary:
                job.summary_json = json.dumps(summary)
            if error:
                job.error_message = error
            if status in ["completed", "failed"]:
                job.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(job)
        return job

class FlowRepository:
    @staticmethod
    def bulk_create_flows(db: Session, flows: list[dict]):
        flow_objs = []
        for f in flows:
            obj = FlowRecord(
                flow_id=f.get("flow_id", f"flow-{uuid.uuid4().hex[:12]}"),
                job_id=f.get("job_id"),
                session_id=f.get("session_id"),
                source_type=f.get("source_type", "csv"),
                timestamp=f.get("timestamp", datetime.now(timezone.utc)),
                src_ip=f.get("src_ip", "127.0.0.1"),
                dst_ip=f.get("dst_ip", "127.0.0.1"),
                src_port=int(f.get("src_port", 0)),
                dst_port=int(f.get("dst_port", 0)),
                protocol=f.get("protocol", "TCP"),
                duration=float(f.get("duration", 0.0)),
                packet_count=int(f.get("packet_count", 0)),
                byte_count=int(f.get("byte_count", 0)),
                dataset=f.get("dataset", "CICIDS2017"),
                prediction=f.get("prediction", "BENIGN"),
                is_attack=bool(f.get("is_attack", False)),
                confidence=float(f.get("confidence", 0.0)),
                attack_probability=float(f.get("attack_probability", 0.0)),
                risk_score=float(f.get("risk_score", 0.0)),
                risk_level=f.get("risk_level", "Low"),
                features_json=json.dumps(f.get("features", {}))
            )
            flow_objs.append(obj)
        db.bulk_save_objects(flow_objs)
        db.commit()
        return len(flow_objs)

    @staticmethod
    def get_flows_by_job(db: Session, job_id: str, limit: int = 200) -> list[FlowRecord]:
        return db.query(FlowRecord).filter(FlowRecord.job_id == job_id).order_by(FlowRecord.id.asc()).limit(limit).all()

    @staticmethod
    def get_recent_flows(db: Session, limit: int = 100, source_type: str = None) -> list[FlowRecord]:
        query = db.query(FlowRecord)
        if source_type:
            query = query.filter(FlowRecord.source_type == source_type)
        return query.order_by(FlowRecord.timestamp.desc()).limit(limit).all()

class IncidentRepository:
    @staticmethod
    def create_or_update_incident(
        db: Session,
        title: str,
        src_ip: str,
        dst_ip: str,
        attack_category: str,
        severity: str,
        risk_score: float,
        notes: str = ""
    ) -> IncidentRecord:
        # Check if active incident already exists for same src_ip + attack_category
        incident = db.query(IncidentRecord).filter(
            IncidentRecord.src_ip == src_ip,
            IncidentRecord.attack_category == attack_category,
            IncidentRecord.status.in_(["New", "Investigating", "Acknowledged"])
        ).first()

        now = datetime.now(timezone.utc)
        if incident:
            incident.flow_count += 1
            incident.last_seen = now
            if risk_score > incident.risk_score:
                incident.risk_score = risk_score
                incident.severity = severity
            db.commit()
            db.refresh(incident)
            return incident
        else:
            incident = IncidentRecord(
                incident_id=f"inc-{uuid.uuid4().hex[:10]}",
                title=title,
                status="New",
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_category=attack_category,
                flow_count=1,
                risk_score=risk_score,
                first_seen=now,
                last_seen=now,
                notes=notes
            )
            db.add(incident)
            db.commit()
            db.refresh(incident)
            return incident

    @staticmethod
    def list_incidents(db: Session, status: str = None, severity: str = None, limit: int = 50) -> list[IncidentRecord]:
        query = db.query(IncidentRecord)
        if status:
            query = query.filter(IncidentRecord.status == status)
        if severity:
            query = query.filter(IncidentRecord.severity == severity)
        return query.order_by(IncidentRecord.last_seen.desc()).limit(limit).all()

    @staticmethod
    def get_incident(db: Session, incident_id: str) -> IncidentRecord:
        return db.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).first()

    @staticmethod
    def update_incident(db: Session, incident_id: str, status: str = None, notes: str = None, analyst: str = None) -> IncidentRecord:
        inc = db.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id).first()
        if inc:
            if status:
                inc.status = status
            if notes is not None:
                inc.notes = notes
            if analyst:
                inc.analyst = analyst
            db.commit()
            db.refresh(inc)
        return inc

class MonitoringRepository:
    @staticmethod
    def start_session(db: Session, interface: str) -> MonitoringSessionRecord:
        # Mark existing running sessions stopped
        running = db.query(MonitoringSessionRecord).filter(MonitoringSessionRecord.status == "Running").all()
        for r in running:
            r.status = "Stopped"
            r.stopped_at = datetime.now(timezone.utc)
        
        session = MonitoringSessionRecord(
            session_id=f"mon-{uuid.uuid4().hex[:10]}",
            interface=interface,
            status="Running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    @staticmethod
    def stop_session(db: Session, session_id: str, packet_count: int = 0, flow_count: int = 0, alert_count: int = 0) -> MonitoringSessionRecord:
        session = db.query(MonitoringSessionRecord).filter(MonitoringSessionRecord.session_id == session_id).first()
        if session:
            session.status = "Stopped"
            session.stopped_at = datetime.now(timezone.utc)
            session.packet_count = packet_count
            session.flow_count = flow_count
            session.alert_count = alert_count
            db.commit()
            db.refresh(session)
        return session

    @staticmethod
    def get_active_session(db: Session) -> MonitoringSessionRecord:
        return db.query(MonitoringSessionRecord).filter(MonitoringSessionRecord.status == "Running").order_by(MonitoringSessionRecord.started_at.desc()).first()

    @staticmethod
    def get_session_history(db: Session, limit: int = 20) -> list[MonitoringSessionRecord]:
        return db.query(MonitoringSessionRecord).order_by(MonitoringSessionRecord.started_at.desc()).limit(limit).all()

