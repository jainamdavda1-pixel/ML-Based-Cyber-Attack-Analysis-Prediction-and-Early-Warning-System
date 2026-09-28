from pydantic import BaseModel
from typing import Optional

class AlertItem(BaseModel):
    alert_id: str
    timestamp: str
    dataset: str
    prediction: str
    risk_score: float
    risk_level: str
    confidence: float
    status: str = "Active"
