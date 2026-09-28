import os
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Response
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any

from app.database.connection import get_db
from app.database.repositories import FlowRepository, JobRepository
from app.services.job_service import JobService
from app.core.config import settings

router = APIRouter(prefix="/traffic", tags=["Traffic Analysis"])

@router.post("/upload")
async def upload_traffic_file(
    file: UploadFile = File(...),
    dataset: str = Form("cicids2017"),
    db: Session = Depends(get_db)
):
    """
    Upload and analyze network traffic data from CSV, PCAP, or PCAPNG files.
    """
    filename = file.filename or "uploaded_traffic"
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in [".csv", ".pcap", ".pcapng"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Supported formats: .csv, .pcap, .pcapng"
        )

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES / (1024*1024):.0f}MB"
        )

    try:
        if ext == ".csv":
            res = JobService.create_and_run_csv_job(db, filename, content, dataset=dataset)
        else:
            res = JobService.create_and_run_pcap_job(db, filename, content, dataset=dataset)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/jobs")
def list_analysis_jobs(db: Session = Depends(get_db)):
    jobs = JobRepository.list_jobs(db, limit=50)
    return [
        {
            "job_id": j.job_id,
            "filename": j.filename,
            "file_type": j.file_type,
            "dataset": j.dataset,
            "status": j.status,
            "total_records": j.total_records,
            "analyzed_records": j.analyzed_records,
            "error_message": j.error_message,
            "created_at": j.created_at.isoformat() if j.created_at else "",
            "completed_at": j.completed_at.isoformat() if j.completed_at else ""
        }
        for j in jobs
    ]

@router.get("/jobs/{job_id}")
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    job = JobRepository.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    import json
    summary = json.loads(job.summary_json) if job.summary_json else None

    return {
        "job_id": job.job_id,
        "filename": job.filename,
        "file_type": job.file_type,
        "dataset": job.dataset,
        "status": job.status,
        "total_records": job.total_records,
        "analyzed_records": job.analyzed_records,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat() if job.created_at else "",
        "completed_at": job.completed_at.isoformat() if job.completed_at else "",
        "summary": summary
    }

@router.get("/jobs/{job_id}/results")
def get_job_results(job_id: str, limit: int = 100, db: Session = Depends(get_db)):
    flows = FlowRepository.get_flows_by_job(db, job_id, limit=limit)
    return [
        {
            "flow_id": f.flow_id,
            "timestamp": f.timestamp.isoformat() if f.timestamp else "",
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "duration": f.duration,
            "packet_count": f.packet_count,
            "byte_count": f.byte_count,
            "dataset": f.dataset,
            "prediction": f.prediction,
            "is_attack": f.is_attack,
            "confidence": f.confidence,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level
        }
        for f in flows
    ]

@router.get("/jobs/{job_id}/download")
def download_job_results(job_id: str, format: str = "csv", db: Session = Depends(get_db)):
    try:
        content, media_type = JobService.export_job_results(db, job_id, format_type=format)
        filename = f"{job_id}_results.{format.lower()}"
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/flows")
def get_recent_flows(limit: int = 100, source_type: Optional[str] = None, db: Session = Depends(get_db)):
    flows = FlowRepository.get_recent_flows(db, limit=limit, source_type=source_type)
    return [
        {
            "flow_id": f.flow_id,
            "job_id": f.job_id,
            "session_id": f.session_id,
            "source_type": f.source_type,
            "timestamp": f.timestamp.isoformat() if f.timestamp else "",
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "duration": f.duration,
            "packet_count": f.packet_count,
            "byte_count": f.byte_count,
            "dataset": f.dataset,
            "prediction": f.prediction,
            "is_attack": f.is_attack,
            "confidence": f.confidence,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level
        }
        for f in flows
    ]
