export interface AnalysisJob {
  job_id: string;
  filename: string;
  file_type: string;
  dataset: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  total_records: number;
  analyzed_records: number;
  error_message?: string;
  created_at: string;
  completed_at?: string;
  summary?: {
    total_rows?: number;
    total_flows?: number;
    analyzed_rows?: number;
    analyzed_flows?: number;
    benign_count: number;
    attack_count: number;
    attack_percentage: number;
    average_risk_score: number;
    category_distribution: Record<string, number>;
    risk_distribution: Record<string, number>;
  };
}

export interface NetworkFlow {
  flow_id: string;
  job_id?: string;
  session_id?: string;
  source_type: 'csv' | 'pcap' | 'live';
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  duration: number;
  packet_count: number;
  byte_count: number;
  dataset: string;
  prediction: string;
  is_attack: boolean;
  confidence: number;
  risk_score: number;
  risk_level: string;
}
