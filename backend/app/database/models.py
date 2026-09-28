from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class PredictionRecord(Base):
    __tablename__ = "prediction_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    prediction_id = Column(String(64), unique=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    dataset = Column(String(32), index=True)
    prediction = Column(String(64), index=True)
    is_attack = Column(Boolean, default=False, index=True)
    attack_probability = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), index=True)
    input_source = Column(String(32), default="manual")  # "manual", "batch_upload", "pcap", "live"
    top_features_json = Column(Text, nullable=True)
    raw_input_json = Column(Text, nullable=True)

class AnalysisJobRecord(Base):
    __tablename__ = "analysis_jobs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    job_id = Column(String(64), unique=True, index=True)
    filename = Column(String(255))
    file_type = Column(String(32))  # "csv", "pcap", "pcapng"
    dataset = Column(String(32), default="cicids2017")
    status = Column(String(32), default="queued", index=True)  # "queued", "processing", "completed", "failed"
    total_records = Column(Integer, default=0)
    analyzed_records = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime, nullable=True)
    summary_json = Column(Text, nullable=True)

class FlowRecord(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    flow_id = Column(String(64), unique=True, index=True)
    job_id = Column(String(64), index=True, nullable=True)
    session_id = Column(String(64), index=True, nullable=True)
    source_type = Column(String(32), default="csv", index=True)  # "csv", "pcap", "live"
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    src_ip = Column(String(64), default="127.0.0.1", index=True)
    dst_ip = Column(String(64), default="127.0.0.1", index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String(16), default="TCP")
    duration = Column(Float, default=0.0)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    dataset = Column(String(32), default="CICIDS2017")
    prediction = Column(String(64), index=True)
    is_attack = Column(Boolean, default=False, index=True)
    confidence = Column(Float, default=0.0)
    attack_probability = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), index=True)
    features_json = Column(Text, nullable=True)

class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(String(64), unique=True, index=True)
    title = Column(String(255))
    status = Column(String(32), default="New", index=True)  # "New", "Investigating", "Acknowledged", "Resolved", "False Positive"
    severity = Column(String(16), default="Medium", index=True)  # "Low", "Medium", "High", "Critical"
    src_ip = Column(String(64), index=True)
    dst_ip = Column(String(64), index=True)
    attack_category = Column(String(64), index=True)
    flow_count = Column(Integer, default=1)
    risk_score = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    notes = Column(Text, default="")
    analyst = Column(String(64), default="Security Analyst")

class MonitoringSessionRecord(Base):
    __tablename__ = "monitoring_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(64), unique=True, index=True)
    interface = Column(String(64), index=True)
    status = Column(String(32), default="Stopped", index=True)  # "Running", "Stopped", "Error"
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    stopped_at = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    flow_count = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

