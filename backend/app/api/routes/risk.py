from fastapi import APIRouter
from app.schemas.risk import RiskCalculateRequest, RiskCalculateResponse
from app.services.risk_service import RiskService

router = APIRouter()

@router.post("/risk", response_model=RiskCalculateResponse, tags=["Risk"])
def calculate_risk(payload: RiskCalculateRequest):
    res = RiskService.calculate_risk(payload.benign_probability)
    return res

@router.get("/risk/early-warning", tags=["Risk"])
def get_early_warning_threshold_info():
    return RiskService.get_threshold_metrics()
