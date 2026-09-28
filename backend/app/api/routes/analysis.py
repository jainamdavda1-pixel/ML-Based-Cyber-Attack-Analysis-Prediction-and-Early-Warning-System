from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.database.repositories import PredictionRepository
from app.services.prediction_service import PredictionService
from app.services.shap_service import SHAPService
from app.services.alert_service import AlertService
from app.core.security import validate_csv_upload

router = APIRouter()

@router.post("/analyze", tags=["Analysis"])
async def analyze_network_csv(
    dataset: str = Form("cicids2017"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    validate_csv_upload(file.filename, len(contents))
    try:
        batch_res = PredictionService.predict_batch_csv(
            db=db,
            dataset=dataset,
            file_bytes=contents
        )
        return {
            "analysis_id": f"analysis-{batch_res['sample_predictions'][0]['prediction_id'].replace('pred-', '')}" if batch_res['sample_predictions'] else "analysis-0001",
            "dataset": dataset,
            "status": "completed",
            "summary": {
                "total_records": batch_res["total_records"],
                "normal_records": batch_res["benign_count"],
                "attack_records": batch_res["attack_count"],
                "average_risk_score": batch_res["average_risk_score"],
                "high_risk_records": batch_res["high_risk_count"],
                "critical_risk_records": batch_res["critical_risk_count"],
                "category_distribution": batch_res["category_distribution"],
                "risk_level_distribution": batch_res["risk_level_distribution"]
            },
            "results": batch_res["sample_predictions"]
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis processing error: {str(e)}"
        )

@router.get("/analyses/{analysis_id}", tags=["Analysis"])
def get_analysis_summary(analysis_id: str, db: Session = Depends(get_db)):
    history = PredictionRepository.get_history(db=db, limit=100)
    if not history:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    total = len(history)
    attacks = sum(1 for r in history if r.is_attack)
    high_risk = sum(1 for r in history if r.risk_level in ["High", "Critical"])

    return {
        "analysis_id": analysis_id,
        "dataset": history[0].dataset if history else "cicids2017",
        "status": "completed",
        "summary": {
            "total_records": total,
            "normal_records": total - attacks,
            "attack_records": attacks,
            "high_risk_records": high_risk
        }
    }

@router.get("/analyses/{analysis_id}/results", tags=["Analysis"])
def get_analysis_results(
    analysis_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    offset = (page - 1) * limit
    history = PredictionRepository.get_history(db=db, limit=limit)
    return {
        "analysis_id": analysis_id,
        "page": page,
        "limit": limit,
        "total_records": len(history),
        "results": [
            {
                "record_id": idx + offset + 1,
                "prediction_id": r.prediction_id,
                "prediction": r.prediction,
                "is_attack": r.is_attack,
                "attack_probability": r.attack_probability,
                "confidence": r.confidence,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "warning": r.risk_level in ["High", "Critical"]
            }
            for idx, r in enumerate(history)
        ]
    }

@router.get("/analyses/{analysis_id}/warnings", tags=["Analysis"])
def get_analysis_warnings(analysis_id: str, db: Session = Depends(get_db)):
    history = PredictionRepository.get_history(db=db, limit=100)
    warnings = []
    for r in history:
        if r.risk_level in ["High", "Critical"]:
            w_details = AlertService.generate_alert_details(r.prediction, r.risk_score, r.risk_level)
            warnings.append({
                "warning_id": f"warn-{r.prediction_id}",
                "analysis_id": analysis_id,
                "record_id": r.prediction_id,
                "dataset": r.dataset,
                "predicted_category": r.prediction,
                "risk_level": r.risk_level,
                "risk_score": r.risk_score,
                "reason": w_details["title"],
                "recommendation": w_details["description"]
            })
    return {
        "analysis_id": analysis_id,
        "total_warnings": len(warnings),
        "warnings": warnings
    }

@router.get("/analyses/{analysis_id}/explanations", tags=["Analysis"])
def get_analysis_explanations(analysis_id: str, dataset: str = "cicids2017"):
    return {
        "analysis_id": analysis_id,
        "explainability": SHAPService.get_explainability(dataset)
    }
