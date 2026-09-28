from fastapi import HTTPException, status
import os

MAX_FILE_SIZE_MB = 20
ALLOWED_EXTENSIONS = {".csv"}

def validate_csv_upload(filename: str, file_size: int):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only CSV files are allowed."
        )
    if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum limit of {MAX_FILE_SIZE_MB}MB."
        )
