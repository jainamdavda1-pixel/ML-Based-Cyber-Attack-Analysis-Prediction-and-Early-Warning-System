import os
import logging
from typing import Tuple, List
import numpy as np
import pandas as pd
import xgboost as xgb
from app.core.config import settings
from app.ml.registry_metadata import CICIDS_70_FEATURES, CICIDS_CLASSES

logger = logging.getLogger(__name__)

class CICIDS2017Pipeline:
    """
    Inference pipeline for CICIDS2017 70-feature Multiclass XGBoost model.
    Enforces strict feature validation, eliminates silent zero-filling,
    and maps class probabilities.
    """
    def __init__(self):
        self.dataset_name = "CICIDS2017"
        self.features = CICIDS_70_FEATURES
        self.classes = CICIDS_CLASSES
        self.model = None
        self.loaded = False
        self._load_artifacts()

    def _load_artifacts(self):
        if os.path.exists(settings.CICIDS_MODEL_PATH):
            try:
                self.model = xgb.XGBClassifier()
                self.model.load_model(settings.CICIDS_MODEL_PATH)
                if os.path.exists(settings.CICIDS_ENCODER_PATH):
                    enc = np.load(settings.CICIDS_ENCODER_PATH, allow_pickle=True)
                    self.classes = list(enc)
                self.loaded = True
                logger.info("CICIDS2017 Pipeline loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load CICIDS2017 model: {e}")
                self.loaded = False
        else:
            logger.warning(f"CICIDS2017 model file not found at {settings.CICIDS_MODEL_PATH}")

    def is_ready(self) -> bool:
        return self.loaded and self.model is not None

    def validate_features(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        # Check for presence of required 70 features (case-insensitive fallback)
        df_cols_map = {str(c).strip().lower(): str(c).strip() for c in df.columns}
        missing = []
        for feat in self.features:
            if feat not in df.columns and feat.lower() not in df_cols_map:
                missing.append(feat)
        return len(missing) == 0, missing

    def preprocess(self, df: pd.DataFrame) -> np.ndarray:
        # Validate that required features exist rather than filling missing with zero
        df_cols_map = {str(c).strip().lower(): c for c in df.columns}
        
        missing = [f for f in self.features if f not in df.columns and f.lower() not in df_cols_map]
        if missing:
            raise ValueError(f"Input is missing {len(missing)} required CICIDS2017 features. Incompatible input cannot be classified.")

        X = pd.DataFrame()
        for col in self.features:
            actual_col = col if col in df.columns else df_cols_map[col.lower()]
            # Convert to numeric, replace non-finite values (inf / -inf) with finite bounds
            s = pd.to_numeric(df[actual_col], errors='coerce')
            s = s.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            X[col] = s

        return X[self.features].to_numpy(dtype=np.float32)

    def predict_probabilities(self, X: np.ndarray) -> np.ndarray:
        if not self.is_ready():
            raise RuntimeError("CICIDS2017 model artifact is not configured or loaded.")
        return self.model.predict_proba(X)
