export interface InterfaceInfo {
  name: string;
  description: string;
  is_virtual: boolean;
  is_permitted: boolean;
}

export interface MonitoringStatus {
  running: boolean;
  interface: string | null;
  dataset?: string | null;
  session_id: string | null;
  start_time?: string | null;
  stop_time?: string | null;
  uptime_seconds: number;
  total_packets: number;
  total_flows: number;
  total_attacks: number;
  total_anomalies?: number;
  flows_per_second?: number;
  last_event_time?: string | null;
  last_error: string | null;
  permitted_interfaces: string[];
}

export interface MonitoringSession {
  session_id: string;
  interface: string;
  status: string;
  started_at: string;
  stopped_at?: string;
  packet_count: number;
  flow_count: number;
  alert_count: number;
  error_message?: string;
}

export interface LiveNetworkFlow {
  flow_id: string;
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
  attack_probability: number;
  risk_score: number;
  risk_level: string;
  prediction_margin?: number;
  anomaly_score?: number;
  is_anomaly?: boolean;
  generalized_prob?: number;
  generalized_prediction?: string;
  features?: Record<string, number>;
}
