import os
import io
import json
import uuid
import logging
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.connection import SessionLocal
from app.database.repositories import JobRepository, FlowRepository
from app.services.traffic_parser import TrafficParserService
from app.services.shared_pipeline import SharedPipelineService

logger = logging.getLogger(__name__)

class JobService:
    """
    Manages batch upload and analysis jobs for CSV and PCAP/PCAPNG files.
    """

    @staticmethod
    def create_and_run_csv_job(db: Session, filename: str, content_bytes: bytes, dataset: str = "cicids2017") -> Dict[str, Any]:
        job = JobRepository.create_job(db, filename=filename, file_type="csv", dataset=dataset)
        
        try:
            df = pd.read_csv(io.BytesIO(content_bytes))
            total_rows = len(df)
            
            # Limit processing to max 2000 rows per job to prevent memory exhaustion
            process_limit = min(total_rows, 2000)
            eval_df = df.head(process_limit)

            flows_to_process = []
            for idx, row in eval_df.iterrows():
                row_dict = row.to_dict()
                flows_to_process.append({
                    "flow_id": f"flow-{uuid.uuid4().hex[:12]}",
                    "job_id": job.job_id,
                    "source_type": "csv",
                    "timestamp": datetime.now(timezone.utc),
                    "src_ip": str(row_dict.get("src_ip", f"192.168.1.{10 + (idx % 200)}")),
                    "dst_ip": str(row_dict.get("dst_ip", "10.0.0.1")),
                    "src_port": int(row_dict.get("src_port", 1024 + (idx % 60000))),
                    "dst_port": int(row_dict.get("Destination Port", row_dict.get("dst_port", 80))),
                    "protocol": str(row_dict.get("protocol", "TCP")),
                    "duration": float(row_dict.get("Flow Duration", row_dict.get("dur", 0.0))),
                    "packet_count": int(row_dict.get("Total Fwd Packets", row_dict.get("spkts", 1))),
                    "byte_count": int(row_dict.get("Total Length of Fwd Packets", row_dict.get("sbytes", 0))),
                    "features": row_dict
                })

            results = SharedPipelineService.process_flow_batch(
                db=db,
                flows=flows_to_process,
                dataset=dataset,
                job_id=job.job_id,
                source_type="csv",
                persist=True
            )

            # Summarize metrics
            attack_cnt = sum(1 for r in results if r["is_attack"])
            benign_cnt = len(results) - attack_cnt
            cat_dist = {}
            risk_dist = {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0}
            sum_risk = 0.0

            for r in results:
                c = r["prediction"]
                cat_dist[c] = cat_dist.get(c, 0) + 1
                rl = r["risk_level"]
                risk_dist[rl] = risk_dist.get(rl, 0) + 1
                sum_risk += r["risk_score"]

            avg_risk = round(sum_risk / len(results), 2) if results else 0.0

            summary = {
                "total_rows": total_rows,
                "analyzed_rows": len(results),
                "benign_count": benign_cnt,
                "attack_count": attack_cnt,
                "attack_percentage": round((attack_cnt / len(results) * 100), 2) if results else 0.0,
                "average_risk_score": avg_risk,
                "category_distribution": cat_dist,
                "risk_distribution": risk_dist
            }

            JobRepository.update_job_status(
                db=db,
                job_id=job.job_id,
                status="completed",
                total=total_rows,
                analyzed=len(results),
                summary=summary
            )

            return {
                "job_id": job.job_id,
                "status": "completed",
                "summary": summary,
                "sample_results": results[:50]
            }

        except Exception as e:
            logger.error(f"Failed CSV job {job.job_id}: {e}")
            JobRepository.update_job_status(
                db=db,
                job_id=job.job_id,
                status="failed",
                error=str(e)
            )
            raise

    @staticmethod
    def create_and_run_pcap_job(db: Session, filename: str, content_bytes: bytes, dataset: str = "cicids2017") -> Dict[str, Any]:
        os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
        file_ext = os.path.splitext(filename)[1].lower() or ".pcap"
        temp_path = os.path.join(settings.UPLOAD_DIR, f"{uuid.uuid4().hex}{file_ext}")

        with open(temp_path, "wb") as f:
            f.write(content_bytes)

        job = JobRepository.create_job(db, filename=filename, file_type=file_ext.lstrip("."), dataset=dataset)

        try:
            # Parse capture file
            raw_flows = TrafficParserService.parse_pcap_to_flows(temp_path, max_packets=5000)
            
            # Enrich with job info
            for rf in raw_flows:
                rf["job_id"] = job.job_id
                rf["source_type"] = "pcap"

            results = SharedPipelineService.process_flow_batch(
                db=db,
                flows=raw_flows,
                dataset=dataset,
                job_id=job.job_id,
                source_type="pcap",
                persist=True
            )

            attack_cnt = sum(1 for r in results if r["is_attack"])
            benign_cnt = len(results) - attack_cnt
            cat_dist = {}
            risk_dist = {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0}
            sum_risk = 0.0

            for r in results:
                c = r["prediction"]
                cat_dist[c] = cat_dist.get(c, 0) + 1
                rl = r["risk_level"]
                risk_dist[rl] = risk_dist.get(rl, 0) + 1
                sum_risk += r["risk_score"]

            avg_risk = round(sum_risk / len(results), 2) if results else 0.0

            summary = {
                "total_flows": len(raw_flows),
                "analyzed_flows": len(results),
                "benign_count": benign_cnt,
                "attack_count": attack_cnt,
                "attack_percentage": round((attack_cnt / len(results) * 100), 2) if results else 0.0,
                "average_risk_score": avg_risk,
                "category_distribution": cat_dist,
                "risk_distribution": risk_dist
            }

            JobRepository.update_job_status(
                db=db,
                job_id=job.job_id,
                status="completed",
                total=len(raw_flows),
                analyzed=len(results),
                summary=summary
            )

            return {
                "job_id": job.job_id,
                "status": "completed",
                "summary": summary,
                "sample_results": results[:50]
            }

        except Exception as e:
            logger.error(f"Failed PCAP job {job.job_id}: {e}")
            JobRepository.update_job_status(
                db=db,
                job_id=job.job_id,
                status="failed",
                error=str(e)
            )
            raise
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    @staticmethod
    def export_job_results(db: Session, job_id: str, format_type: str = "csv") -> Any:
        flows = FlowRepository.get_flows_by_job(db, job_id, limit=5000)
        if not flows:
            raise ValueError(f"No flows found for job {job_id}")

        data = []
        for f in flows:
            data.append({
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
            })

        if format_type.lower() == "json":
            return json.dumps(data, indent=2), "application/json"
        else:
            df = pd.DataFrame(data)
            csv_str = df.to_csv(index=False)
            return csv_str, "text/csv"
