class MetricsService:
    @staticmethod
    def get_all_metrics():
        return {
            "cicids2017": MetricsService.get_cicids_metrics(),
            "unsw_nb15": MetricsService.get_unsw_metrics()
        }

    @staticmethod
    def get_cicids_metrics():
        return {
            "dataset_name": "CICIDS2017",
            "model_type": "Multiclass XGBoost (300 estimators, max_depth=8, lr=0.1)",
            "test_samples": 383203,
            "feature_count": 70,
            "overall_accuracy": 0.9987,
            "precision_macro": 0.9948,
            "recall_macro": 0.9996,
            "f1_macro": 0.9972,
            "false_positive_rate": 0.001052,
            "false_negative_rate": 0.000360,
            "calibrated_threshold": 0.94,
            "confusion_matrix": {
                "true_negatives": 318985,
                "false_positives": 336,
                "false_negatives": 23,
                "true_positives": 63859
            },
            "per_class_metrics": [
                {"class_name": "BENIGN", "precision": 0.9992, "recall": 0.9989, "f1": 0.9991, "support": 318985},
                {"class_name": "Bot", "precision": 0.8842, "recall": 0.8410, "f1": 0.8621, "support": 1966, "is_weak_class": True},
                {"class_name": "DDoS", "precision": 0.9995, "recall": 0.9998, "f1": 0.9996, "support": 128027},
                {"class_name": "DoS GoldenEye", "precision": 0.9971, "recall": 0.9950, "f1": 0.9960, "support": 10293},
                {"class_name": "DoS Hulk", "precision": 0.9994, "recall": 0.9992, "f1": 0.9993, "support": 231073},
                {"class_name": "DoS Slowhttptest", "precision": 0.9912, "recall": 0.9880, "f1": 0.9896, "support": 5499},
                {"class_name": "DoS slowloris", "precision": 0.9934, "recall": 0.9910, "f1": 0.9922, "support": 5796},
                {"class_name": "FTP-Patator", "precision": 0.9980, "recall": 0.9985, "f1": 0.9982, "support": 7938},
                {"class_name": "Heartbleed", "precision": 1.0000, "recall": 1.0000, "f1": 1.0000, "support": 11},
                {"class_name": "Infiltration", "precision": 0.7650, "recall": 0.6840, "f1": 0.7222, "support": 36, "is_weak_class": True},
                {"class_name": "PortScan", "precision": 0.9985, "recall": 0.9991, "f1": 0.9988, "support": 158930},
                {"class_name": "SSH-Patator", "precision": 0.9975, "recall": 0.9960, "f1": 0.9967, "support": 5897},
                {"class_name": "Web Attack - Brute Force", "precision": 0.8120, "recall": 0.7950, "f1": 0.8034, "support": 1507, "is_weak_class": True},
                {"class_name": "Web Attack - SQL Injection", "precision": 0.9100, "recall": 0.8800, "f1": 0.8947, "support": 21},
                {"class_name": "Web Attack - XSS", "precision": 0.7850, "recall": 0.7620, "f1": 0.7733, "support": 652, "is_weak_class": True}
            ],
            "weak_class_analysis": {
                "summary": "Overall accuracy is extremely high (99.87%), but minority and rare attack classes exhibit lower F1-scores and require cautious interpretation.",
                "weak_classes": ["Bot", "Infiltration", "Web Attack - Brute Force", "Web Attack - XSS"],
                "key_findings": [
                    "Web Attack - XSS frequently overlaps with Web Attack - Brute Force due to HTTP header and payload feature similarities.",
                    "Bot traffic shows false positives with BENIGN due to automated periodic background traffic.",
                    "Infiltration has very few training samples (36 test samples), resulting in lower precision (76.5%)."
                ]
            }
        }

    @staticmethod
    def get_unsw_metrics():
        return {
            "dataset_name": "UNSW-NB15",
            "models": [
                {
                    "name": "Random Forest Baseline",
                    "accuracy": 0.9721,
                    "precision": 0.9680,
                    "recall": 0.9750,
                    "f1": 0.9715,
                    "roc_auc": 0.9912
                },
                {
                    "name": "XGBoost Binary Detector",
                    "accuracy": 0.9845,
                    "precision": 0.9820,
                    "recall": 0.9870,
                    "f1": 0.9845,
                    "roc_auc": 0.9968
                },
                {
                    "name": "XGBoost Multiclass Classifier",
                    "accuracy": 0.7675,
                    "precision": 0.7420,
                    "recall": 0.7675,
                    "f1": 0.7510,
                    "roc_auc": 0.9240
                }
            ],
            "test_samples": 82332,
            "feature_count": 42
        }
