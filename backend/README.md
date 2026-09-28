# Backend Service (FastAPI)

This directory will contain the FastAPI application and API layer for the ML Cyber Attack Analysis platform.

## Directory Structure
- `app/api/routes/`: Endpoint route definitions (detection, prediction, risk, alerts, dashboard).
- `app/api/schemas/`: Pydantic request and response schemas.
- `app/services/`: Core business logic services for risk, detection, prediction, and alerts.
- `app/models/`: Machine learning model wrapper wrappers and inference pipeline integration.
- `app/core/`: Application settings, security, and global configurations.
- `app/utils/`: Preprocessing and helper utilities.
- `tests/`: Automated unit and integration tests.
