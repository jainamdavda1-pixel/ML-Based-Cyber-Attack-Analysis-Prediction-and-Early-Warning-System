import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.database.models import Base

# Ensure parent directory exists for SQLite databases
if "sqlite" in settings.DATABASE_URL:
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import uuid
from datetime import datetime, timezone, timedelta
from app.database.models import PredictionRecord, FlowRecord, IncidentRecord

def seed_initial_telemetry(db):
    try:
        pred_count = db.query(PredictionRecord).count()
        if pred_count > 0:
            return

        now = datetime.now(timezone.utc)
        
        # Seed CICIDS2017 records
        cicids_samples = [
            ("BENIGN", False, 0.02, 0.98, 2.0, "Low", "192.168.1.105", "10.0.0.1", 10),
            ("BENIGN", False, 0.05, 0.95, 5.0, "Low", "192.168.1.108", "10.0.0.5", 25),
            ("PortScan", True, 0.89, 0.91, 89.0, "High", "172.16.0.15", "192.168.1.50", 40),
            ("DDoS", True, 0.98, 0.99, 98.0, "Critical", "172.16.0.22", "192.168.1.100", 65),
            ("DoS Hulk", True, 0.92, 0.94, 92.0, "Critical", "172.16.0.18", "192.168.1.100", 80),
            ("FTP-Patator", True, 0.76, 0.85, 76.0, "High", "172.16.0.12", "192.168.1.21", 120),
            ("BENIGN", False, 0.01, 0.99, 1.0, "Low", "192.168.1.112", "8.8.8.8", 150),
            ("Bot", True, 0.84, 0.88, 84.0, "High", "192.168.1.205", "185.220.101.5", 180),
        ]
        
        for pred, is_att, a_prob, conf, r_score, r_lvl, s_ip, d_ip, mins_ago in cicids_samples:
            rec = PredictionRecord(
                prediction_id=f"pred-{uuid.uuid4().hex[:12]}",
                timestamp=now - timedelta(minutes=mins_ago),
                dataset="CICIDS2017",
                prediction=pred,
                is_attack=is_att,
                attack_probability=a_prob,
                confidence=conf,
                risk_score=r_score,
                risk_level=r_lvl,
                input_source="batch_upload"
            )
            db.add(rec)

        # Seed UNSW-NB15 records
        unsw_samples = [
            ("Normal", False, 0.03, 0.97, 3.0, "Low", "175.45.176.1", "149.171.126.1", 8),
            ("Normal", False, 0.06, 0.94, 6.0, "Low", "175.45.176.2", "149.171.126.2", 20),
            ("Generic", True, 0.82, 0.88, 82.0, "High", "175.45.176.3", "149.171.126.3", 35),
            ("Exploits", True, 0.94, 0.96, 94.0, "Critical", "175.45.176.0", "149.171.126.0", 55),
            ("Fuzzers", True, 0.78, 0.84, 78.0, "High", "175.45.176.2", "149.171.126.5", 75),
            ("DoS", True, 0.95, 0.97, 95.0, "Critical", "175.45.176.1", "149.171.126.8", 100),
            ("Reconnaissance", True, 0.74, 0.82, 74.0, "High", "175.45.176.3", "149.171.126.9", 140),
            ("Backdoor", True, 0.91, 0.93, 91.0, "Critical", "175.45.176.0", "149.171.126.7", 190),
            ("Normal", False, 0.02, 0.98, 2.0, "Low", "175.45.176.4", "149.171.126.4", 220),
        ]
        
        for pred, is_att, a_prob, conf, r_score, r_lvl, s_ip, d_ip, mins_ago in unsw_samples:
            rec = PredictionRecord(
                prediction_id=f"pred-{uuid.uuid4().hex[:12]}",
                timestamp=now - timedelta(minutes=mins_ago),
                dataset="UNSW-NB15",
                prediction=pred,
                is_attack=is_att,
                attack_probability=a_prob,
                confidence=conf,
                risk_score=r_score,
                risk_level=r_lvl,
                input_source="batch_upload"
            )
            db.add(rec)

        db.commit()
    except Exception as e:
        db.rollback()

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_initial_telemetry(db)
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
