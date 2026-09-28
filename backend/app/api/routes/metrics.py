from fastapi import APIRouter
from app.services.metrics_service import MetricsService
from app.models.cicids_xgboost import CICIDS_70_FEATURES, CICIDS_CLASSES
from app.models.unsw_xgboost import UNSW_42_FEATURES, UNSW_ATTACK_CLASSES

router = APIRouter()

@router.get("/metrics", tags=["Metrics"])
def get_model_metrics(dataset: str = None):
    if dataset:
        ds = dataset.lower().strip()
        if "unsw" in ds:
            return MetricsService.get_unsw_metrics()
        else:
            return MetricsService.get_cicids_metrics()
    return MetricsService.get_all_metrics()

@router.get("/models", tags=["Models"])
def get_available_models():
    return {
        "datasets": [
            {
                "id": "cicids2017",
                "name": "CICIDS2017",
                "description": "Multiclass network intrusion detection dataset (15 classes, 70 features)",
                "features_count": len(CICIDS_70_FEATURES),
                "features": CICIDS_70_FEATURES,
                "classes": CICIDS_CLASSES
            },
            {
                "id": "unsw-nb15",
                "name": "UNSW-NB15",
                "description": "Comprehensive network flow attack dataset (10 classes, 42 features)",
                "features_count": len(UNSW_42_FEATURES),
                "features": UNSW_42_FEATURES,
                "classes": UNSW_ATTACK_CLASSES
            }
        ]
    }
