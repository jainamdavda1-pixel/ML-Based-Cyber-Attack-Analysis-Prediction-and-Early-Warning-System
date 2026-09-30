import io
import pandas as pd
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from app.services.compatibility_engine import CompatibilityEngine
from app.services.dataset_evaluator import DatasetEvaluatorService
from app.core.security import validate_csv_upload
from typing import Optional

router = APIRouter(prefix="/compatibility", tags=["Input Profiler & Compatibility"])

@router.post("/profile")
async def profile_input_csv(
    file: UploadFile = File(...),
    dataset: Optional[str] = Form(None)
):
    """
    Inspects and profiles uploaded CSV headers, feature distributions,
    missing columns, and schema compatibility with registered XGBoost models.
    """
    contents = await file.read()
    validate_csv_upload(file.filename, len(contents))
    try:
        profile = CompatibilityEngine.profile_csv(contents, requested_dataset=dataset)
        return profile
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Profiling failed: {str(e)}"
        )

@router.post("/evaluate")
async def evaluate_dataset_only(
    file: UploadFile = File(...)
):
    """
    Performs Evaluation-Only analysis on an uploaded dataset without model inference.
    Calculates summary statistics, missingness, infinite values, protocol distributions,
    and ground-truth label distributions.
    """
    contents = await file.read()
    validate_csv_upload(file.filename, len(contents))
    try:
        df = pd.read_csv(io.BytesIO(contents))
        profile = CompatibilityEngine.profile_csv(contents)
        eval_report = DatasetEvaluatorService.evaluate_dataset(df, dataset_name=file.filename or "Uploaded Dataset")
        eval_report["compatibility_profile"] = profile
        return eval_report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Evaluation failed: {str(e)}"
        )
