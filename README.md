# ML-Based Cyber Attack Analysis, Prediction & Early Warning System

An end-to-end cybersecurity monitoring, threat classification, SHAP explainability, and calibrated risk estimation platform built around machine learning models for network flow intrusion detection.

## Key Features

- **Dual Benchmark Datasets**: Independent evaluation for `CICIDS2017` (70 features, 15 classes) and `UNSW-NB15` (42 features, 10 classes).
- **Real-Time ML Inference**: Live prediction using trained XGBoost and Random Forest models.
- **Single Flow & Batch CSV Analysis**: Interactive collapsible single-flow manual input forms and CSV upload processing.
- **Calibrated Risk Scoring**: Early warning risk scoring based on $P(\text{Attack}) = 1 - P(\text{BENIGN})$ with frozen validation threshold (0.94).
- **SHAP Explainability**: Feature attribution visual charts for top contributing features and known misclassification patterns (XSS ↔ Brute Force, BENIGN → Bot).
- **Model Performance Telemetry**: Per-class precision, recall, F1-scores, confusion matrices, and minority weak-class analysis.
- **SQLite Audit Log**: Historical prediction log retention.

## Quick Start (Local Development)

### 1. Backend Setup (FastAPI)
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Start FastAPI backend server
PYTHONPATH=backend uvicorn app.main:app --reload --host 0.0.0.0 --port 8090
```
Backend API will be accessible at: `http://localhost:8090` (Swagger docs at `/docs`).

### 2. Frontend Setup (React + TypeScript + Vite)
```bash
cd frontend
npm install
npm run dev
```
Frontend dashboard will be accessible at: `http://localhost:5180`.

---

## Quick Start (Docker Deployment)

Run both Backend and Frontend containerized with a single command:
```bash
docker compose up --build
```
- Dashboard UI: `http://localhost:5180`
- Backend API: `http://localhost:8090`

---

## Model Artifact Placement

Model files are loaded automatically from `model-artifacts/`:
- **CICIDS2017**: `model-artifacts/cicids2017/CICIDS_Multiclass_XGBoost.json` & `CICIDS_Label_Encoder.npy`
- **UNSW-NB15**: `model-artifacts/unsw-nb15/xgboost_cyberattack (1).pkl` & `xgboost_multiclass_attack_classifier (1).pkl`

If a model file is missing, the API gracefully reports `"Model artifact not configured"`.

---

## Environment Variables

- `DATABASE_URL`: Database connection string (default: `sqlite:///./cyber_security.db`).
- `VITE_API_URL`: Backend API base URL for frontend (default: `http://localhost:8090/api/v1`).
- `PORT`: Backend server port (default: `8090`).

---

## Documentation

- [System Architecture](docs/architecture/system-architecture.md)
- [API Documentation](docs/api/api-documentation.md)
- [Dataset Methodology](docs/methodology/datasets.md)
- [Model Specifications](docs/methodology/models.md)
- [Risk Scoring & Early Warning](docs/methodology/risk-and-early-warning.md)
