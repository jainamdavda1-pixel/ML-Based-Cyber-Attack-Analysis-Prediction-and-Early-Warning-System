export interface RiskCalculation {
  attack_probability: number;
  risk_score: number;
  risk_level: 'Low' | 'Moderate' | 'High' | 'Critical';
  calibrated_threshold: number;
  formula: string;
  interpretation: string;
}

export interface EarlyWarningMetrics {
  validation_threshold: number;
  validation_metrics: {
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
  };
  test_metrics_frozen: {
    precision: number;
    recall: number;
    f1_score: number;
    accuracy: number;
    false_positive_rate: number;
    false_negative_rate: number;
    confusion_matrix: {
      true_negatives: number;
      false_positives: number;
      false_negatives: number;
      true_positives: number;
    };
  };
}
