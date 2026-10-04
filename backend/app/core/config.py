import os
from pydantic_settings import BaseSettings, SettingsConfigDict

def resolve_artifact_path(base_dir: str, primary_filename: str) -> str:
    primary_path = os.path.join(base_dir, primary_filename)
    if os.path.exists(primary_path):
        return primary_path
    
    # Try fallback with (1) suffix before extension
    name, ext = os.path.splitext(primary_filename)
    fallback_path = os.path.join(base_dir, f"{name} (1){ext}")
    if os.path.exists(fallback_path):
        return fallback_path
    
    return primary_path

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True, extra="ignore")

    PROJECT_NAME: str = "ML Cyber Attack Analysis, Prediction & Early Warning API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5180",
        "http://127.0.0.1:5180",
        "http://localhost:5173",
        "http://localhost:3000",
        "*"
    ]
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyber_security.db")
    
    # Uploads & Storage
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "uploads"))
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    
    # Live Monitoring Settings
    PERMITTED_INTERFACES: list[str] = ["en0", "eth0", "wlan0", "lo", "lo0", "any", "test0"]
    MAX_LIVE_BUFFER_SIZE: int = 5000
    
    # Model Artifact Paths
    MODEL_DIR: str = os.getenv("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "..", "model-artifacts"))
    
    @property
    def CICIDS_MODEL_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "cicids2017"), "CICIDS_Multiclass_XGBoost.json")

    @property
    def CICIDS_ENCODER_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "cicids2017"), "CICIDS_Label_Encoder.npy")

    @property
    def UNSW_XGB_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "unsw-nb15"), "xgboost_cyberattack.pkl")

    @property
    def UNSW_RF_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "unsw-nb15"), "random_forest_cyberattack.pkl")

    @property
    def UNSW_MULTI_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "unsw-nb15"), "xgboost_multiclass_attack_classifier.pkl")

    @property
    def UNSW_ENCODER_PATH(self) -> str:
        return resolve_artifact_path(os.path.join(self.MODEL_DIR, "unsw-nb15"), "attack_category_label_encoder.pkl")
    
    # Generalized XGBoost Artifact Paths
    @property
    def GENERALIZED_XGB_MODEL_PATH(self) -> str:
        for sub in ["generalized-xgb", "generalized_xgb"]:
            p = resolve_artifact_path(os.path.join(self.MODEL_DIR, sub), "generalized_xgb_final.joblib")
            if os.path.exists(p):
                return p
        return os.path.join(self.MODEL_DIR, "generalized-xgb", "generalized_xgb_final.joblib")

    @property
    def GENERALIZED_XGB_FEATURES_PATH(self) -> str:
        for sub in ["generalized-xgb", "generalized_xgb"]:
            p = resolve_artifact_path(os.path.join(self.MODEL_DIR, sub), "generalized_xgb_features.json")
            if os.path.exists(p):
                return p
        return os.path.join(self.MODEL_DIR, "generalized-xgb", "generalized_xgb_features.json")

    @property
    def GENERALIZED_XGB_THRESHOLD_PATH(self) -> str:
        for sub in ["generalized-xgb", "generalized_xgb"]:
            p = resolve_artifact_path(os.path.join(self.MODEL_DIR, sub), "generalized_xgb_threshold_config.json")
            if os.path.exists(p):
                return p
        return os.path.join(self.MODEL_DIR, "generalized-xgb", "generalized_xgb_threshold_config.json")

    # Isolation Forest Artifact Paths
    @property
    def ISOLATION_FOREST_MODEL_PATH(self) -> str:
        for sub in ["isolation-forest", "isolation_forest"]:
            p = resolve_artifact_path(os.path.join(self.MODEL_DIR, sub), "isolation_forest_baseline.joblib")
            if os.path.exists(p):
                return p
        return os.path.join(self.MODEL_DIR, "isolation-forest", "isolation_forest_baseline.joblib")

    @property
    def ISOLATION_FOREST_THRESHOLD_PATH(self) -> str:
        for sub in ["isolation-forest", "isolation_forest"]:
            p = resolve_artifact_path(os.path.join(self.MODEL_DIR, sub), "isolation_forest_threshold_config.json")
            if os.path.exists(p):
                return p
        return os.path.join(self.MODEL_DIR, "isolation-forest", "isolation_forest_threshold_config.json")

    # Calibrated Thresholds
    CICIDS_RISK_THRESHOLD: float = 0.94
    GENERALIZED_XGB_THRESHOLD: float = 0.1743
    ISOLATION_FOREST_THRESHOLD: float = 0.02341647450041217

settings = Settings()

