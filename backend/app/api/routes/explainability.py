from fastapi import APIRouter
from app.services.shap_service import SHAPService

router = APIRouter()

@router.get("/explain", tags=["Explainability"])
def get_explainability(dataset: str = "cicids2017"):
    return SHAPService.get_explainability(dataset)

@router.post("/explain", tags=["Explainability"])
def explain_sample_prediction(payload: dict):
    dataset = payload.get("dataset", "cicids2017")
    features = payload.get("features", {})
    return SHAPService.get_explainability(dataset)
