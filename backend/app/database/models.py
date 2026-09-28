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
    input_source = Column(String(32), default="manual")  # "manual" or "batch_upload"
    top_features_json = Column(Text, nullable=True)
    raw_input_json = Column(Text, nullable=True)
