import os
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from app.core.config import settings

logger = logging.getLogger(__name__)

CICIDS_70_FEATURES = [
    'ACK Flag Count', 'Active Max', 'Active Mean', 'Active Min', 'Active Std',
    'Average Packet Size', 'Avg Bwd Segment Size', 'Avg Fwd Segment Size',
    'Bwd Header Length', 'Bwd IAT Max', 'Bwd IAT Mean', 'Bwd IAT Min',
    'Bwd IAT Std', 'Bwd IAT Total', 'Bwd Packet Length Max',
    'Bwd Packet Length Mean', 'Bwd Packet Length Min', 'Bwd Packet Length Std',
    'Bwd Packets/s', 'CWE Flag Count', 'Destination Port', 'Down/Up Ratio',
    'ECE Flag Count', 'FIN Flag Count', 'Flow Bytes/s', 'Flow Duration',
    'Flow IAT Max', 'Flow IAT Mean', 'Flow IAT Min', 'Flow IAT Std',
    'Flow Packets/s', 'Fwd Header Length', 'Fwd Header Length.1',
    'Fwd IAT Max', 'Fwd IAT Mean', 'Fwd IAT Min', 'Fwd IAT Std',
    'Fwd IAT Total', 'Fwd PSH Flags', 'Fwd Packet Length Max',
    'Fwd Packet Length Mean', 'Fwd Packet Length Min', 'Fwd Packet Length Std',
    'Fwd Packets/s', 'Fwd URG Flags', 'Idle Max', 'Idle Mean', 'Idle Min',
    'Idle Std', 'Init_Win_bytes_backward', 'Init_Win_bytes_forward',
    'Max Packet Length', 'Min Packet Length', 'PSH Flag Count',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'RST Flag Count', 'SYN Flag Count', 'Subflow Bwd Bytes',
    'Subflow Bwd Packets', 'Subflow Fwd Bytes', 'Subflow Fwd Packets',
    'Total Backward Packets', 'Total Fwd Packets',
    'Total Length of Bwd Packets', 'Total Length of Fwd Packets',
    'URG Flag Count', 'act_data_pkt_fwd', 'min_seg_size_forward'
]

CICIDS_CLASSES = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
    'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
    'SSH-Patator', 'Web Attack - Brute Force', 'Web Attack - SQL Injection',
    'Web Attack - XSS'
]

class CICIDS2017Pipeline:
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

    def preprocess(self, df: pd.DataFrame) -> np.ndarray:
        # Match feature order, fill missing columns with 0.0
        X = pd.DataFrame()
        for col in self.features:
            if col in df.columns:
                X[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            else:
                X[col] = 0.0
        return X[self.features].to_numpy(dtype=np.float32)

    def predict_probabilities(self, X: np.ndarray) -> np.ndarray:
        if not self.is_ready():
            raise RuntimeError("CICIDS2017 model artifact is not configured or loaded.")
        return self.model.predict_proba(X)
