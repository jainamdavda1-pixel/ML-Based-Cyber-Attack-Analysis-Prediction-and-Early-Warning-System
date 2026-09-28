import numpy as np

def fill_missing_features(features_dict: dict, required_features: list[str]) -> np.ndarray:
    vector = []
    for feat in required_features:
        val = float(features_dict.get(feat, 0.0))
        vector.append(val)
    return np.array([vector], dtype=np.float32)

def normalize_feature_name(name: str) -> str:
    return name.strip()
