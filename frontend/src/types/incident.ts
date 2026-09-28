export interface Incident {
  incident_id: string;
  title: string;
  status: 'New' | 'Investigating' | 'Acknowledged' | 'Resolved' | 'False Positive';
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  src_ip: string;
  dst_ip: string;
  attack_category: string;
  flow_count: number;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  notes: string;
  analyst: string;
}
