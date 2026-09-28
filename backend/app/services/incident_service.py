import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.database.models import IncidentRecord
from app.database.repositories import IncidentRepository
from app.services.shap_service import SHAPService

logger = logging.getLogger(__name__)

class IncidentService:
    @staticmethod
    def list_incidents(db: Session, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        records = IncidentRepository.list_incidents(db, status=status, severity=severity, limit=limit)
        return [
            {
                "incident_id": r.incident_id,
                "title": r.title,
                "status": r.status,
                "severity": r.severity,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "attack_category": r.attack_category,
                "flow_count": r.flow_count,
                "risk_score": r.risk_score,
                "first_seen": r.first_seen.isoformat() if r.first_seen else "",
                "last_seen": r.last_seen.isoformat() if r.last_seen else "",
                "notes": r.notes,
                "analyst": r.analyst
            }
            for r in records
        ]

    @staticmethod
    def get_incident(db: Session, incident_id: str) -> Optional[Dict[str, Any]]:
        r = IncidentRepository.get_incident(db, incident_id)
        if not r:
            return None
        return {
            "incident_id": r.incident_id,
            "title": r.title,
            "status": r.status,
            "severity": r.severity,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "attack_category": r.attack_category,
            "flow_count": r.flow_count,
            "risk_score": r.risk_score,
            "first_seen": r.first_seen.isoformat() if r.first_seen else "",
            "last_seen": r.last_seen.isoformat() if r.last_seen else "",
            "notes": r.notes,
            "analyst": r.analyst
        }

    @staticmethod
    def update_incident(db: Session, incident_id: str, status: Optional[str] = None, notes: Optional[str] = None, analyst: Optional[str] = None) -> Optional[Dict[str, Any]]:
        r = IncidentRepository.update_incident(db, incident_id, status=status, notes=notes, analyst=analyst)
        if not r:
            return None
        return {
            "incident_id": r.incident_id,
            "title": r.title,
            "status": r.status,
            "severity": r.severity,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "attack_category": r.attack_category,
            "flow_count": r.flow_count,
            "risk_score": r.risk_score,
            "notes": r.notes,
            "analyst": r.analyst
        }

    @staticmethod
    def get_incident_explanations(db: Session, incident_id: str) -> Dict[str, Any]:
        inc = IncidentRepository.get_incident(db, incident_id)
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")
        
        # Pull global + attack category explanations
        explain_info = SHAPService.get_explainability("cicids2017")
        return {
            "incident_id": incident_id,
            "attack_category": inc.attack_category,
            "risk_score": inc.risk_score,
            "severity": inc.severity,
            "explanation": explain_info
        }
