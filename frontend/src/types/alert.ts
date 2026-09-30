export interface AlertItem {
  prediction_id: string;
  timestamp: string;
  dataset: string;
  prediction: string;
  is_attack: boolean;
  risk_score: number;
  risk_level: 'Low' | 'Moderate' | 'High' | 'Critical';
  confidence: number;
  input_source: string;
  recommendations?: string[];
}

export interface DashboardSummary {
  dataset?: string;
  total_analyzed: number;
  attacks_detected: number;
  attack_percentage: number;
  average_risk_score: number;
  low_risk_count?: number;
  moderate_risk_count?: number;
  high_risk_count: number;
  critical_risk_count: number;
  risk_distribution?: Record<string, number>;
  category_distribution?: Record<string, number>;
  recent_alerts: AlertItem[];
}
