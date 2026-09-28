from datetime import datetime, timezone
from fastapi import APIRouter
from app.models.cicids_xgboost import cicids_model_wrapper
from app.models.unsw_xgboost import unsw_model_wrapper
from app.models.lstm import lstm_model_wrapper

router = APIRouter()

@router.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_status": {
            "cicids2017_multiclass_xgboost": {
                "loaded": cicids_model_wrapper.is_loaded(),
                "feature_count": len(cicids_model_wrapper.features),
                "class_count": len(cicids_model_wrapper.classes)
            },
            "unsw_nb15_binary_xgboost": {
                "loaded": unsw_model_wrapper.binary_loaded,
                "feature_count": len(unsw_model_wrapper.features)
            },
            "unsw_nb15_rf_baseline": {
                "loaded": unsw_model_wrapper.rf_loaded
            },
            "unsw_nb15_multiclass_xgboost": {
                "loaded": unsw_model_wrapper.multi_loaded
            },
            "lstm_sequence_model": {
                "loaded": lstm_model_wrapper.is_loaded()
            }
        }
    }
