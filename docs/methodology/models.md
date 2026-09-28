# Machine Learning Models Methodology

## Model Specifications

### 1. CICIDS2017 Multiclass XGBoost
- **Architecture**: XGBoost Classifier (`objective="multi:softprob"`, `n_estimators=300`, `max_depth=8`, `learning_rate=0.1`).
- **Features**: 70 features.
- **Accuracy**: 99.87% on 383,203 test samples.
- **Weak Classes**: Bot (F1: 86.21%), Infiltration (F1: 72.22%), Web Attack - Brute Force (F1: 80.34%), Web Attack - XSS (F1: 77.33%).

### 2. UNSW-NB15 Models
- **Random Forest Baseline**: Accuracy 97.21%, F1: 97.15%.
- **XGBoost Binary Detector**: Accuracy 98.45%, F1: 98.45%.
- **XGBoost Multiclass Classifier**: Accuracy 76.75%, F1: 75.10%.
