# API Endpoints Documentation

## Base URL
`http://localhost:8090`

## Endpoints Summary

### 1. Health Check
- **Endpoint**: `GET /health`
- **Description**: Returns system health status and loaded model artifacts.

### 2. Single Flow Prediction
- **Endpoint**: `POST /api/v1/predict`
- **Body**:
```json
{
  "dataset": "cicids2017",
  "features": {
    "Destination Port": 80,
    "Flow Duration": 1200,
    "Total Fwd Packets": 5
  }
}
```
- **Response**:
```json
{
  "prediction_id": "pred-3143eae8e0f7",
  "dataset": "CICIDS2017",
  "prediction": "BENIGN",
  "is_attack": false,
  "attack_probability": 0.0001,
  "confidence": 0.9999,
  "risk_score": 0.01,
  "risk_level": "Low",
  "prediction_margin": 0.9998,
  "top_features": [...]
}
```

### 3. Batch Flow Prediction (CSV Upload)
- **Endpoint**: `POST /api/v1/predict/batch`
- **Form Data**: `dataset` (string), `file` (CSV file)
- **Response**: Summary metrics, risk distribution, sample prediction records.

### 4. Risk Calculation
- **Endpoint**: `POST /api/v1/risk`
- **Body**: `{"dataset": "cicids2017", "benign_probability": 0.05}`
- **Response**: Calibrated risk score, risk level band, formula details.

### 5. SHAP Explainability
- **Endpoint**: `GET /api/v1/explain?dataset=cicids2017`
- **Response**: Top 10 global SHAP feature attributions and known misclassification patterns.

### 6. Model Performance & Metrics
- **Endpoint**: `GET /api/v1/metrics`
- **Response**: Empirical accuracy, precision, recall, F1, per-class breakdown, and weak-class analysis.

### 7. Available Models
- **Endpoint**: `GET /api/v1/models`
- **Response**: Feature schemas and class taxonomies for CICIDS2017 & UNSW-NB15.

### 8. Prediction History
- **Endpoint**: `GET /api/v1/history?limit=100&risk_level=Critical`
- **Response**: Filtered prediction audit logs from SQLite database.
