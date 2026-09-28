import os
import pickle
import logging
import numpy as np
import pandas as pd
from app.core.config import settings

logger = logging.getLogger(__name__)

UNSW_42_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt',
    'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt',
    'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

UNSW_ATTACK_CLASSES = [
    'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers',
    'Generic', 'Normal', 'Reconnaissance', 'Shellcode', 'Worms'
]

class UNSWNB15Pipeline:
    def __init__(self):
        self.dataset_name = "UNSW-NB15"
        self.features = UNSW_42_FEATURES
        self.classes = UNSW_ATTACK_CLASSES
        self.binary_model = None
        self.multi_model = None
        self.loaded = False
        self._load_artifacts()

    def _load_artifacts(self):
        if os.path.exists(settings.UNSW_XGB_PATH):
            try:
                with open(settings.UNSW_XGB_PATH, "rb") as f:
                    self.binary_model = pickle.load(f)
                self.loaded = True
                logger.info("UNSW-NB15 Binary XGBoost pipeline loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load UNSW Binary XGBoost model: {e}")

        if os.path.exists(settings.UNSW_MULTI_PATH):
            try:
                with open(settings.UNSW_MULTI_PATH, "rb") as f:
                    self.multi_model = pickle.load(f)
                logger.info("UNSW-NB15 Multiclass XGBoost pipeline loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load UNSW Multiclass model: {e}")

    def is_ready(self) -> bool:
        return self.loaded and self.binary_model is not None

    def preprocess(self, df: pd.DataFrame) -> np.ndarray:
        X = pd.DataFrame()
        for col in self.features:
            if col in df.columns:
                X[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            else:
                X[col] = 0.0
        return X[self.features].to_numpy(dtype=np.float32)

    def predict_binary_probabilities(self, X: np.ndarray) -> np.ndarray:
        if not self.is_ready():
            raise RuntimeError("UNSW-NB15 model artifact is not configured or loaded.")
        return self.binary_model.predict_proba(X)

    def predict_multi_probabilities(self, X: np.ndarray) -> np.ndarray:
        if self.multi_model is not None:
            return self.multi_model.predict_proba(X)
        # Fallback using binary probabilities
        bin_probs = self.predict_binary_probabilities(X)
        results = []
        for p in bin_probs:
            att_prob = float(p[1])
            if att_prob < 0.5:
                arr = np.zeros(len(self.classes))
                arr[6] = 1.0 # Normal
            else:
                arr = np.full(len(self.classes), att_prob / (len(self.classes) - 1))
                arr[6] = 1.0 - att_prob
            results.append(arr)
        return np.array(results)
