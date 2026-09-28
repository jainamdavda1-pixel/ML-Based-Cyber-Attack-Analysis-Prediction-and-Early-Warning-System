import logging
from typing import Dict, Any, Optional
from app.ml.dataset_pipelines.cicids2017 import CICIDS2017Pipeline
from app.ml.dataset_pipelines.unsw_nb15 import UNSWNB15Pipeline

logger = logging.getLogger(__name__)

class ModelRegistry:
    def __init__(self):
        self.cicids_pipeline = CICIDS2017Pipeline()
        self.unsw_pipeline = UNSWNB15Pipeline()

    def get_pipeline(self, dataset: str):
        ds = dataset.lower().strip()
        if "cicids" in ds:
            return self.cicids_pipeline
        elif "unsw" in ds:
            return self.unsw_pipeline
        else:
            raise ValueError(f"Unknown dataset '{dataset}'. Choose 'cicids2017' or 'unsw-nb15'.")

    def get_readiness(self) -> Dict[str, Any]:
        return {
            "cicids2017": {
                "dataset_name": "CICIDS2017",
                "ready": self.cicids_pipeline.is_ready(),
                "feature_count": len(self.cicids_pipeline.features),
                "class_count": len(self.cicids_pipeline.classes),
                "artifact_path": "model-artifacts/cicids2017/CICIDS_Multiclass_XGBoost.json"
            },
            "unsw-nb15": {
                "dataset_name": "UNSW-NB15",
                "ready": self.unsw_pipeline.is_ready(),
                "feature_count": len(self.unsw_pipeline.features),
                "class_count": len(self.unsw_pipeline.classes),
                "artifact_path": "model-artifacts/unsw-nb15/xgboost_cyberattack (1).pkl"
            }
        }

model_registry = ModelRegistry()
