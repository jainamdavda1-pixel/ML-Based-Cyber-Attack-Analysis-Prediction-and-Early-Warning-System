from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.repositories import MonitoringRepository
from app.services.live_collector import live_collector_service

router = APIRouter(prefix="/monitoring", tags=["Live Monitoring"])

class StartMonitoringRequest(BaseModel):
    interface: str
    dataset: Optional[str] = "cicids2017"

@router.get("/interfaces")
def get_monitoring_interfaces():
    """
    List permitted network interfaces for authorized live packet capture.
    """
    return {
        "permitted_interfaces": live_collector_service.get_permitted_interfaces()
    }

@router.get("/status")
def get_monitoring_status():
    """
    Check current live monitoring status, running state, packet and flow statistics.
    """
    return live_collector_service.get_status()

@router.post("/start")
def start_live_monitoring(req: StartMonitoringRequest):
    """
    Start passive live monitoring on an explicitly permitted network interface.
    """
    try:
        res = live_collector_service.start_monitoring(req.interface, dataset=req.dataset or "cicids2017")
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {str(e)}")

@router.post("/stop")
def stop_live_monitoring():
    """
    Stop active live monitoring session.
    """
    return live_collector_service.stop_monitoring()

@router.get("/statistics")
def get_monitoring_statistics(db: Session = Depends(get_db)):
    """
    Retrieve live monitoring statistics and past sessions.
    """
    status = live_collector_service.get_status()
    history = MonitoringRepository.get_session_history(db, limit=10)
    
    return {
        "current_session": status,
        "past_sessions": [
            {
                "session_id": s.session_id,
                "interface": s.interface,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else "",
                "stopped_at": s.stopped_at.isoformat() if s.stopped_at else "",
                "packet_count": s.packet_count,
                "flow_count": s.flow_count,
                "alert_count": s.alert_count,
                "error_message": s.error_message
            }
            for s in history
        ]
    }

@router.get("/flows")
def get_live_flows(limit: int = Query(50, ge=1, le=200)):
    """
    Retrieve the most recent live classified flows from memory buffer.
    """
    flows = live_collector_service.get_live_flows(limit=limit)
    return flows
