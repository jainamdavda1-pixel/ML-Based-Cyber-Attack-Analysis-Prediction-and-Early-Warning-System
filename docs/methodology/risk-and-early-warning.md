# Risk Scoring & Early Warning Methodology

## Risk Calibration Formula
$$P(\text{Attack}) = 1.0 - P(\text{BENIGN})$$
$$\text{Risk Score} = P(\text{Attack}) \times 100.0$$

## Calibrated Decision Threshold
A validation threshold of **0.94** was selected during validation phase tuning.

### Held-out Test Evaluation at Frozen Threshold 0.94
- **Precision**: 99.4766%
- **Recall**: 99.9640%
- **F1-Score**: 99.7197%
- **Accuracy**: 99.9063%
- **False Positive Rate (FPR)**: 0.1052%
- **False Negative Rate (FNR)**: 0.0360%

### Confusion Matrix
- **True Negatives (TN)**: 318,985
- **False Positives (FP)**: 336
- **False Negatives (FN)**: 23
- **True Positives (TP)**: 63,859

## Risk Bands
- **0 – 30**: Low Risk
- **30 – 60**: Moderate Risk
- **60 – 80**: High Risk
- **80 – 100**: Critical Risk
