from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class SingleFlowPredictRequest(BaseModel):
    dataset: str = Field(..., description="Dataset identifier: 'cicids2017' or 'unsw-nb15'")
    features: Dict[str, float] = Field(..., description="Feature name-value dictionary")

class FeatureContribution(BaseModel):
    feature: str
    value: float
    importance: float
    direction: str = Field("positive", description="'positive' increases risk/attack, 'negative' decreases")

class PredictionResponse(BaseModel):
    prediction_id: str
    dataset: str
    prediction: str
    is_attack: bool
    attack_probability: float
    confidence: float
    risk_score: float
    risk_level: str
    prediction_margin: Optional[float] = 0.0
    top_features: Optional[list[FeatureContribution]] = []

class BatchSummaryResponse(BaseModel):
    total_records: int
    benign_count: int
    attack_count: int
    attack_percentage: float
    average_risk_score: float
    high_risk_count: int
    critical_risk_count: int
    category_distribution: Dict[str, int]
    risk_level_distribution: Dict[str, int]
    sample_predictions: list[PredictionResponse]
