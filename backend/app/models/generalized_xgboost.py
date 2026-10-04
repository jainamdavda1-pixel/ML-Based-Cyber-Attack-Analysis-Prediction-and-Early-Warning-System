import os
import json
import joblib
import logging
from typing import Any
import numpy as np
import pandas as pd
from app.core.config import settings
from app.ml.registry_metadata import GENERALIZED_10_FEATURES, GENERALIZED_CLASSES

logger = logging.getLogger(__name__)

def _patch_simple_imputer(pipeline):
    if hasattr(pipeline, "named_steps") and "imputer" in pipeline.named_steps:
        imp = pipeline.named_steps["imputer"]
        if not hasattr(imp, "_fill_dtype") and hasattr(imp, "_fit_dtype"):
            imp._fill_dtype = imp._fit_dtype

class GeneralizedXGBoostModelWrapper:
    def __init__(self):
        self.model = None
        self.features = list(GENERALIZED_10_FEATURES)
        self.classes = list(GENERALIZED_CLASSES)
        self.threshold = settings.GENERALIZED_XGB_THRESHOLD
        self.loaded = False
        self._load()

    def _load(self):
        try:
            if os.path.exists(settings.GENERALIZED_XGB_THRESHOLD_PATH):
                with open(settings.GENERALIZED_XGB_THRESHOLD_PATH, "r") as f:
                    cfg = json.load(f)
                    self.threshold = float(cfg.get("threshold", self.threshold))

            if os.path.exists(settings.GENERALIZED_XGB_FEATURES_PATH):
                with open(settings.GENERALIZED_XGB_FEATURES_PATH, "r") as f:
                    self.features = json.load(f)

            if os.path.exists(settings.GENERALIZED_XGB_MODEL_PATH):
                self.model = joblib.load(settings.GENERALIZED_XGB_MODEL_PATH)
                _patch_simple_imputer(self.model)
                self.loaded = True
                logger.info("Successfully loaded Generalized Binary XGBoost model.")
            else:
                logger.warning(f"Generalized XGBoost model file not found at {settings.GENERALIZED_XGB_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Error loading Generalized XGBoost model: {e}")
            self.loaded = False

    def is_loaded(self) -> bool:
        return self.loaded and self.model is not None

    def predict_proba(self, input_data: Any) -> np.ndarray:
        if not self.loaded or self.model is None:
            raise RuntimeError("Generalized XGBoost model artifact is not loaded or configured.")
        if isinstance(input_data, np.ndarray):
            input_data = pd.DataFrame(input_data, columns=self.features)
        return self.model.predict_proba(input_data)

    def predict(self, input_data: Any) -> np.ndarray:
        probs = self.predict_proba(input_data)
        attack_probs = probs[:, 1]
        return (attack_probs >= self.threshold).astype(int)

generalized_xgb_wrapper = GeneralizedXGBoostModelWrapper()
