export interface FeatureContribution {
  feature: string;
  value: number;
  importance: number;
  direction: 'positive' | 'negative';
}

export interface PredictionResult {
  prediction_id: string;
  dataset: string;
  prediction: string;
  is_attack: boolean;
  attack_probability: number;
  confidence: number;
  risk_score: number;
  risk_level: 'Low' | 'Moderate' | 'High' | 'Critical';
  prediction_margin?: number;
  top_features?: FeatureContribution[];
  recommendations?: string[];
}

export interface BatchSummary {
  total_records: number;
  benign_count: number;
  attack_count: number;
  attack_percentage: number;
  average_risk_score: number;
  high_risk_count: number;
  critical_risk_count: number;
  category_distribution: Record<string, number>;
  risk_level_distribution: Record<string, number>;
  sample_predictions: PredictionResult[];
}

export interface ModelDatasetInfo {
  id: string;
  name: string;
  description: string;
  features_count: number;
  features: string[];
  classes: string[];
}
