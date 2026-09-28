class RiskService:
    CALIBRATED_THRESHOLD = 0.94

    @staticmethod
    def calculate_risk(benign_prob: float) -> dict:
        attack_prob = max(0.0, min(1.0, 1.0 - benign_prob))
        risk_score = round(attack_prob * 100.0, 2)
        risk_level = RiskService.get_risk_level(risk_score)
        
        return {
            "attack_probability": round(attack_prob, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "calibrated_threshold": RiskService.CALIBRATED_THRESHOLD,
            "formula": "P(Attack) = 1 - P(BENIGN); Risk Score = P(Attack) * 100",
            "interpretation": f"Project-defined risk band: {risk_level} ({risk_score}/100)"
        }

    @staticmethod
    def get_risk_level(score: float) -> str:
        if score < 30.0:
            return "Low"
        elif score < 60.0:
            return "Moderate"
        elif score < 80.0:
            return "High"
        else:
            return "Critical"

    @staticmethod
    def get_threshold_metrics():
        return {
            "validation_threshold": 0.94,
            "validation_metrics": {
                "precision": 99.5030,
                "recall": 99.9781,
                "f1_score": 99.7400,
                "false_positive_rate": 0.0999
            },
            "test_metrics_frozen": {
                "precision": 99.4766,
                "recall": 99.9640,
                "f1_score": 99.7197,
                "accuracy": 99.9063,
                "false_positive_rate": 0.1052,
                "false_negative_rate": 0.0360,
                "confusion_matrix": {
                    "true_negatives": 318985,
                    "false_positives": 336,
                    "false_negatives": 23,
                    "true_positives": 63859
                }
            }
        }
