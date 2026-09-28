# System Architecture Specification

## Overview

The **ML-Based Cyber Attack Analysis, Prediction & Early Warning System** provides a modular, end-to-end framework for network traffic intrusion detection, threat classification, SHAP feature attribution, and calibrated risk estimation.

## Mermaid System Architecture Diagram

```mermaid
graph TD
    User[User / Analyst] -->|Network CSV Upload / Single Flow Input| Frontend[React + TypeScript + Vite Dashboard]
    Frontend -->|HTTP / JSON API Calls| Backend[FastAPI Backend Application]

    subgraph FastAPI Backend
        API[API Router Layer] -->|Dispatch| Service[Prediction & Risk Services]
        Service -->|Load / Infer| Models[Model Registry & Wrappers]
        Service -->|Log History| DB[(SQLite Database)]
        Service -->|Extract Attributions| SHAP[SHAP Explainability Engine]
    end

    subgraph ML Model Artifacts
        Models -->|CICIDS2017| CICIDS_XGB[Multiclass XGBoost JSON - 70 Features]
        Models -->|UNSW-NB15| UNSW_XGB[Binary/Multiclass XGBoost PKL - 42 Features]
    end

    Backend -->|Predictions, Risk Score & SHAP Data| Frontend
    Frontend -->|Telemetry Charts & Early Warning Alerts| User
```

## Component Architecture

1. **Frontend**: React 18 SPA built with TypeScript, Vite, Tailwind CSS, and Recharts. Serves responsive cybersecurity monitoring telemetry.
2. **Backend Services**: FastAPI RESTful API architecture running Uvicorn.
3. **Model Inference Wrappers**: XGBoost Python API wrappers for `CICIDS2017` (15 classes) and `UNSW-NB15` (10 classes).
4. **Database Layer**: SQLite repository layer storing prediction records, risk scores, confidence margins, and input flow audit logs.
