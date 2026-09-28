from pydantic import BaseModel, Field
from typing import Optional, Dict

class PredictionHistoryQuery(BaseModel):
    limit: Optional[int] = 100
    dataset: Optional[str] = None
    risk_level: Optional[str] = None

class PredictionHistoryRecord(BaseModel):
    prediction_id: str
    timestamp: str
    dataset: str
    prediction: str
    is_attack: bool
    attack_probability: float
    confidence: float
    risk_score: float
    risk_level: str
    input_source: str
