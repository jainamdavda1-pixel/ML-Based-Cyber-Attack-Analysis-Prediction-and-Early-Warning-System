import os
import logging
from typing import Dict, Any, Optional, List
from app.core.config import settings
from app.ml.registry_metadata import MODEL_REGISTRY_METADATA, CICIDS_70_FEATURES, UNSW_42_FEATURES
from app.ml.dataset_pipelines.cicids2017 import CICIDS2017Pipeline
from app.ml.dataset_pipelines.unsw_nb15 import UNSWNB15Pipeline

logger = logging.getLogger(__name__)

class ModelRegistry:
    """
    Central Authoritative Model Registry.
    Tracks model loading, feature schemas, input validation requirements,
    provenance, and runtime inference readiness.
    """
    def __init__(self):
        self.cicids_pipeline = CICIDS2017Pipeline()
        self.unsw_pipeline = UNSWNB15Pipeline()
        self._metadata = MODEL_REGISTRY_METADATA

    def get_pipeline(self, dataset: str):
        ds = dataset.lower().strip()
        if "cicids" in ds:
            return self.cicids_pipeline
        elif "unsw" in ds:
            return self.unsw_pipeline
        else:
            raise ValueError(f"Unknown or unsupported dataset '{dataset}'. Registered datasets: 'cicids2017', 'unsw-nb15'.")

    def get_model_info(self, model_id: str) -> Optional[Dict[str, Any]]:
        meta = self._metadata.get(model_id)
        if not meta:
            return None
        
        info = dict(meta)
        if "cicids" in model_id:
            info["artifact_path"] = settings.CICIDS_MODEL_PATH
            info["artifact_exists"] = os.path.exists(settings.CICIDS_MODEL_PATH)
            info["is_ready"] = self.cicids_pipeline.is_ready()
        elif "unsw" in model_id:
            info["artifact_path"] = settings.UNSW_MULTI_PATH if "multi" in model_id else settings.UNSW_XGB_PATH
            info["artifact_exists"] = os.path.exists(info["artifact_path"])
            info["is_ready"] = self.unsw_pipeline.is_ready()
        return info

    def list_all_models(self) -> List[Dict[str, Any]]:
        results = []
        for model_id in self._metadata:
            info = self.get_model_info(model_id)
            if info:
                results.append(info)
        return results

    def get_readiness(self) -> Dict[str, Any]:
        return {
            "cicids2017": {
                "dataset_name": "CICIDS2017",
                "ready": self.cicids_pipeline.is_ready(),
                "feature_count": len(CICIDS_70_FEATURES),
                "features": CICIDS_70_FEATURES,
                "class_count": len(self.cicids_pipeline.classes),
                "classes": self.cicids_pipeline.classes,
                "model_type": "XGBoost Multiclass (Tree-based)",
                "artifact_path": settings.CICIDS_MODEL_PATH,
                "supported_sources": ["CSV", "PCAP", "Live Capture"]
            },
            "unsw-nb15": {
                "dataset_name": "UNSW-NB15",
                "ready": self.unsw_pipeline.is_ready(),
                "feature_count": len(UNSW_42_FEATURES),
                "features": UNSW_42_FEATURES,
                "class_count": len(self.unsw_pipeline.classes),
                "classes": self.unsw_pipeline.classes,
                "model_type": "XGBoost Binary + Multiclass",
                "artifact_path": settings.UNSW_XGB_PATH,
                "supported_sources": ["CSV", "PCAP", "Live Capture"]
            },
            "lstm_temporal": {
                "dataset_name": "Temporal LSTM",
                "ready": False,
                "status": "Untrained / Pending Chronological Sequence Training",
                "notes": "Deep learning LSTM requires sequential packet time series with continuous timestamp ordering."
            }
        }

model_registry = ModelRegistry()
