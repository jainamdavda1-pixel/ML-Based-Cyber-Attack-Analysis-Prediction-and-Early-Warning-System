import os
import pickle
import logging
import numpy as np
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

class UNSWXGBoostModelWrapper:
    def __init__(self):
        self.binary_model = None
        self.rf_model = None
        self.multi_model = None
        self.features = UNSW_42_FEATURES
        self.classes = UNSW_ATTACK_CLASSES
        self.binary_loaded = False
        self.rf_loaded = False
        self.multi_loaded = False
        self._load()

    def _load(self):
        if os.path.exists(settings.UNSW_XGB_PATH):
            try:
                with open(settings.UNSW_XGB_PATH, "rb") as f:
                    self.binary_model = pickle.load(f)
                self.binary_loaded = True
                logger.info("Loaded UNSW-NB15 Binary XGBoost model.")
            except Exception as e:
                logger.error(f"Failed to load UNSW Binary XGBoost model: {e}")

        if os.path.exists(settings.UNSW_RF_PATH):
            try:
                with open(settings.UNSW_RF_PATH, "rb") as f:
                    self.rf_model = pickle.load(f)
                self.rf_loaded = True
                logger.info("Loaded UNSW-NB15 Random Forest model.")
            except Exception as e:
                logger.error(f"Failed to load UNSW RF model: {e}")

        if os.path.exists(settings.UNSW_MULTI_PATH):
            try:
                with open(settings.UNSW_MULTI_PATH, "rb") as f:
                    self.multi_model = pickle.load(f)
                self.multi_loaded = True
                logger.info("Loaded UNSW-NB15 Multiclass XGBoost model.")
            except Exception as e:
                logger.error(f"Failed to load UNSW Multiclass model: {e}")

    def is_loaded(self) -> bool:
        return self.binary_loaded or self.rf_loaded or self.multi_loaded

    def predict_binary_probs(self, input_array: np.ndarray) -> np.ndarray:
        if not self.binary_loaded or self.binary_model is None:
            raise RuntimeError("UNSW-NB15 Binary XGBoost model is not loaded.")
        return self.binary_model.predict_proba(input_array)

    def predict_multi_probs(self, input_array: np.ndarray) -> np.ndarray:
        if not self.multi_loaded or self.multi_model is None:
            # Fallback if binary is loaded
            if self.binary_loaded:
                bin_probs = self.binary_model.predict_proba(input_array)
                # Map binary prob to attack classes
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
            raise RuntimeError("UNSW-NB15 Multiclass model is not loaded.")
        return self.multi_model.predict_proba(input_array)

unsw_model_wrapper = UNSWXGBoostModelWrapper()
