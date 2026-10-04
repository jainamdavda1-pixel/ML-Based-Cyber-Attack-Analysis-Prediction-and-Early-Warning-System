import os
import json
import joblib
import logging
from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd
from app.core.config import settings
from app.ml.registry_metadata import GENERALIZED_10_FEATURES, GENERALIZED_CLASSES

logger = logging.getLogger(__name__)

def _patch_simple_imputer(pipeline):
    """Ensures scikit-learn cross-version compatibility for SimpleImputer."""
    if hasattr(pipeline, "named_steps") and "imputer" in pipeline.named_steps:
        imp = pipeline.named_steps["imputer"]
        if not hasattr(imp, "_fill_dtype") and hasattr(imp, "_fit_dtype"):
            imp._fill_dtype = imp._fit_dtype

class GeneralizedXGBPipeline:
    """
    Inference pipeline for Generalized 10-feature Binary XGBoost model.
    Evaluates cross-dataset flow traffic using calibrated threshold (0.1743).
    """
    def __init__(self):
        self.dataset_name = "Generalized"
        self.features = list(GENERALIZED_10_FEATURES)
        self.classes = list(GENERALIZED_CLASSES)
        self.decision_threshold = settings.GENERALIZED_XGB_THRESHOLD
        self.model = None
        self.loaded = False
        self._load_artifacts()

    def _load_artifacts(self):
        if os.path.exists(settings.GENERALIZED_XGB_FEATURES_PATH):
            try:
                with open(settings.GENERALIZED_XGB_FEATURES_PATH, "r") as f:
                    self.features = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load feature list from {settings.GENERALIZED_XGB_FEATURES_PATH}: {e}")

        if os.path.exists(settings.GENERALIZED_XGB_THRESHOLD_PATH):
            try:
                with open(settings.GENERALIZED_XGB_THRESHOLD_PATH, "r") as f:
                    cfg = json.load(f)
                    self.decision_threshold = float(cfg.get("threshold", self.decision_threshold))
            except Exception as e:
                logger.warning(f"Could not load threshold config from {settings.GENERALIZED_XGB_THRESHOLD_PATH}: {e}")

        if os.path.exists(settings.GENERALIZED_XGB_MODEL_PATH):
            try:
                self.model = joblib.load(settings.GENERALIZED_XGB_MODEL_PATH)
                _patch_simple_imputer(self.model)
                self.loaded = True
                logger.info("Generalized XGBoost Pipeline loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load Generalized XGBoost model: {e}")
                self.loaded = False
        else:
            logger.warning(f"Generalized XGBoost model file not found at {settings.GENERALIZED_XGB_MODEL_PATH}")

    def is_ready(self) -> bool:
        return self.loaded and self.model is not None

    def validate_features(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        df_cols_map = {str(c).strip().lower(): str(c).strip() for c in df.columns}
        missing = []
        for feat in self.features:
            if feat not in df.columns and feat.lower() not in df_cols_map:
                missing.append(feat)
        return len(missing) == 0, missing

    def preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        df_cols_map = {str(c).strip().lower(): c for c in df.columns}
        missing = [f for f in self.features if f not in df.columns and f.lower() not in df_cols_map]
        if missing:
            raise ValueError(f"Input is missing {len(missing)} required Generalized features: {missing}. Incompatible input cannot be classified.")

        X = pd.DataFrame()
        for col in self.features:
            actual_col = col if col in df.columns else df_cols_map[col.lower()]
            s = pd.to_numeric(df[actual_col], errors='coerce')
            s = s.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            X[col] = s

        return X[self.features]

    def predict_probabilities(self, X: Any) -> np.ndarray:
        if not self.is_ready():
            raise RuntimeError("Generalized XGBoost model artifact is not configured or loaded.")
        if isinstance(X, np.ndarray):
            X = pd.DataFrame(X, columns=self.features)
        return self.model.predict_proba(X)

    def predict_binary(self, X: Any) -> np.ndarray:
        probs = self.predict_probabilities(X)
        attack_probs = probs[:, 1]
        return (attack_probs >= self.decision_threshold).astype(bool)
