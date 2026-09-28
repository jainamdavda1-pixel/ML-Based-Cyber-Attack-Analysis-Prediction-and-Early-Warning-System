from pydantic import BaseModel, Field

class RiskCalculateRequest(BaseModel):
    dataset: str = Field("cicids2017", description="Dataset identifier")
    benign_probability: float = Field(..., ge=0.0, le=1.0, description="P(BENIGN)")

class RiskCalculateResponse(BaseModel):
    attack_probability: float
    risk_score: float
    risk_level: str
    calibrated_threshold: float = 0.94
    formula: str = "P(Attack) = 1 - P(BENIGN); Risk Score = P(Attack) * 100"
    interpretation: str
