from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incident Management"])

class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None  # "New", "Investigating", "Acknowledged", "Resolved", "False Positive"
    notes: Optional[str] = None
    analyst: Optional[str] = None

@router.get("")
def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """
    List correlated security incidents with optional status and severity filtering.
    """
    return IncidentService.list_incidents(db, status=status, severity=severity, limit=limit)

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """
    Get detailed information for a specific security incident.
    """
    inc = IncidentService.get_incident(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@router.patch("/{incident_id}")
def update_incident(incident_id: str, req: UpdateIncidentRequest, db: Session = Depends(get_db)):
    """
    Update incident lifecycle status (New, Investigating, Acknowledged, Resolved, False Positive), analyst notes, or assignee.
    """
    inc = IncidentService.update_incident(
        db,
        incident_id,
        status=req.status,
        notes=req.notes,
        analyst=req.analyst
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@router.get("/{incident_id}/explanations")
def get_incident_explanations(incident_id: str, db: Session = Depends(get_db)):
    """
    Retrieve SHAP-based feature attribution and contextual evidence for an incident.
    """
    try:
        return IncidentService.get_incident_explanations(db, incident_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
