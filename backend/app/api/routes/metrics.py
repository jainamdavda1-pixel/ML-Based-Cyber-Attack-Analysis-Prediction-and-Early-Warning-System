from fastapi import APIRouter, HTTPException
from app.services.metrics_service import MetricsService
from app.ml.model_registry import model_registry

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
    readiness = model_registry.get_readiness()
    models_list = model_registry.list_all_models()
    return {
        "readiness": readiness,
        "models": models_list,
        "datasets": [
            {
                "id": "cicids2017",
                "name": "CICIDS2017",
                "description": "Multiclass network intrusion detection dataset (15 classes, 70 features)",
                "features_count": readiness["cicids2017"]["feature_count"],
                "features": readiness["cicids2017"]["features"],
                "classes": readiness["cicids2017"]["classes"],
                "is_ready": readiness["cicids2017"]["ready"]
            },
            {
                "id": "unsw-nb15",
                "name": "UNSW-NB15",
                "description": "Comprehensive network flow attack dataset (10 classes, 42 features)",
                "features_count": readiness["unsw-nb15"]["feature_count"],
                "features": readiness["unsw-nb15"]["features"],
                "classes": readiness["unsw-nb15"]["classes"],
                "is_ready": readiness["unsw-nb15"]["ready"]
            }
        ]
    }

@router.get("/models/{model_id}", tags=["Models"])
def get_model_detail(model_id: str):
    info = model_registry.get_model_info(model_id)
    if not info:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found in registry.")
    return info
