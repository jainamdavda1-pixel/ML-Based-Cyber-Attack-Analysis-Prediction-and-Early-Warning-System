from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.database.repositories import PredictionRepository
from app.schemas.detection import SingleFlowPredictRequest, PredictionResponse, BatchSummaryResponse
from app.services.prediction_service import PredictionService
from app.services.recommendation_service import RecommendationService
from app.core.security import validate_csv_upload

router = APIRouter()

@router.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict_single_flow(
    payload: SingleFlowPredictRequest,
    db: Session = Depends(get_db)
):
    try:
        res = PredictionService.predict_single(
            db=db,
            dataset=payload.dataset,
            features=payload.features
        )
        return res
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Prediction error: {str(e)}"
        )

@router.post("/predict/batch", response_model=BatchSummaryResponse, tags=["Prediction"])
async def predict_batch_csv(
    dataset: str = Form("cicids2017"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    validate_csv_upload(file.filename, len(contents))
    try:
        res = PredictionService.predict_batch_csv(
            db=db,
            dataset=dataset,
            file_bytes=contents
        )
        return res
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch processing error: {str(e)}"
        )

@router.get("/history", tags=["History"])
def get_prediction_history(
    limit: int = 100,
    dataset: str = None,
    risk_level: str = None,
    db: Session = Depends(get_db)
):
    records = PredictionRepository.get_history(db=db, limit=limit, dataset=dataset, risk_level=risk_level)
    return [
        {
            "prediction_id": r.prediction_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
            "dataset": r.dataset,
            "prediction": r.prediction,
            "is_attack": r.is_attack,
            "attack_probability": r.attack_probability,
            "confidence": r.confidence,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "input_source": r.input_source,
            "recommendations": RecommendationService.get_recommendations(r.prediction) if r.is_attack else []
        }
        for r in records
    ]

@router.get("/dashboard/summary", tags=["Dashboard"])
def get_dashboard_summary(db: Session = Depends(get_db)):
    return PredictionRepository.get_dashboard_summary(db)
