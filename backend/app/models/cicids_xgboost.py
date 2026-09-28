import os
import json
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

class CICIDSXGBoostModelWrapper:
    def __init__(self):
        self.model = None
        self.classes = CICIDS_CLASSES
        self.features = CICIDS_70_FEATURES
        self.loaded = False
        self._load()

    def _load(self):
        try:
            if os.path.exists(settings.CICIDS_MODEL_PATH):
                self.model = xgb.XGBClassifier()
                self.model.load_model(settings.CICIDS_MODEL_PATH)
                if os.path.exists(settings.CICIDS_ENCODER_PATH):
                    enc = np.load(settings.CICIDS_ENCODER_PATH, allow_pickle=True)
                    self.classes = list(enc)
                self.loaded = True
                logger.info("Successfully loaded CICIDS2017 Multiclass XGBoost model.")
            else:
                logger.warning(f"CICIDS2017 model file not found at {settings.CICIDS_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Error loading CICIDS2017 model: {e}")
            self.loaded = False

    def is_loaded(self) -> bool:
        return self.loaded

    def predict_features(self, input_array: np.ndarray):

        if not self.loaded or self.model is None:
            raise RuntimeError("CICIDS2017 Model artifact is not loaded or configured.")
        
        probs = self.model.predict_proba(input_array)
        return probs

cicids_model_wrapper = CICIDSXGBoostModelWrapper()
