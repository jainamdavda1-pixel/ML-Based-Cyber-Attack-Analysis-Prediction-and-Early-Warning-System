export interface MonitoringStatus {
  running: boolean;
  interface: string | null;
  session_id: string | null;
  uptime_seconds: number;
  total_packets: number;
  total_flows: number;
  total_attacks: number;
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
