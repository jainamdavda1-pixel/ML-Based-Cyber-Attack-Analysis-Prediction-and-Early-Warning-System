import os
import json
import joblib
import logging
from typing import Any
import numpy as np
import pandas as pd
from app.core.config import settings
from app.ml.registry_metadata import GENERALIZED_10_FEATURES

logger = logging.getLogger(__name__)

def _patch_simple_imputer(pipeline):
    if hasattr(pipeline, "named_steps") and "imputer" in pipeline.named_steps:
        imp = pipeline.named_steps["imputer"]
        if not hasattr(imp, "_fill_dtype") and hasattr(imp, "_fit_dtype"):
            imp._fill_dtype = imp._fit_dtype

class IsolationForestModelWrapper:
    def __init__(self):
        self.model = None
        self.features = list(GENERALIZED_10_FEATURES)
        self.threshold = settings.ISOLATION_FOREST_THRESHOLD
        self.anomaly_rule = "decision_function_score < threshold"
        self.loaded = False
        self._load()

    def _load(self):
        try:
            if os.path.exists(settings.ISOLATION_FOREST_THRESHOLD_PATH):
                with open(settings.ISOLATION_FOREST_THRESHOLD_PATH, "r") as f:
                    cfg = json.load(f)
                    self.threshold = float(cfg.get("threshold", self.threshold))
                    self.anomaly_rule = cfg.get("anomaly_rule", self.anomaly_rule)

            if os.path.exists(settings.ISOLATION_FOREST_MODEL_PATH):
                self.model = joblib.load(settings.ISOLATION_FOREST_MODEL_PATH)
                _patch_simple_imputer(self.model)
                self.loaded = True
                logger.info("Successfully loaded Baseline Isolation Forest model.")
            else:
                logger.warning(f"Isolation Forest model file not found at {settings.ISOLATION_FOREST_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Error loading Isolation Forest model: {e}")
            self.loaded = False

    def is_loaded(self) -> bool:
        return self.loaded and self.model is not None

    def decision_function(self, input_data: Any) -> np.ndarray:
        if not self.loaded or self.model is None:
            raise RuntimeError("Isolation Forest model artifact is not loaded or configured.")
        if isinstance(input_data, np.ndarray):
            input_data = pd.DataFrame(input_data, columns=self.features)
        return self.model.decision_function(input_data)

    def predict_anomalies(self, input_data: Any) -> np.ndarray:
        scores = self.decision_function(input_data)
        return (scores < self.threshold).astype(bool)

isolation_forest_wrapper = IsolationForestModelWrapper()
