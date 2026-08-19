"""
Evaluation Metrics, Stratified K-Fold Benchmarking, and Confusion Matrix Diagnostics
Computes F1-Macro, Detection Rate, False Alarm Rate, and Class-level Metrics.
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score
)
from sklearn.model_selection import StratifiedKFold, cross_validate


def calculate_nids_metrics(y_true: np.ndarray, y_pred: np.ndarray, label_encoder=None) -> Dict[str, Any]:
    """
    Computes standard SecOps NIDS evaluation metrics including Detection Rate and False Alarm Rate.
    """
    acc = float(accuracy_score(y_true, y_pred))
    f1_macro = float(f1_score(y_true, y_pred, average="macro"))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted"))
    precision_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    recall_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    
    # Compute Detection Rate & False Alarm Rate
    # Assuming label 0 or "Benign" is normal
    if label_encoder:
        benign_idx = list(label_encoder.classes_).index("Benign") if "Benign" in label_encoder.classes_ else 0
    else:
        benign_idx = 0
        
    cm = confusion_matrix(y_true, y_pred)
    
    # False Alarm Rate: Benign predicted as Attack / Total Benign
    total_benign = np.sum(y_true == benign_idx)
    benign_false_alarms = np.sum((y_true == benign_idx) & (y_pred != benign_idx))
    far = float(benign_false_alarms / (total_benign + 1e-5) * 100.0)
    
    # Attack Detection Rate: Actual Attacks detected as any Attack / Total Attacks
    total_attacks = np.sum(y_true != benign_idx)
    attacks_detected = np.sum((y_true != benign_idx) & (y_pred != benign_idx))
    detection_rate = float(attacks_detected / (total_attacks + 1e-5) * 100.0)
    
    return {
        "Accuracy": round(acc, 4),
        "F1_Macro": round(f1_macro, 4),
        "F1_Weighted": round(f1_weighted, 4),
        "Precision_Macro": round(precision_macro, 4),
        "Recall_Macro": round(recall_macro, 4),
        "Detection_Rate_Percent": round(detection_rate, 2),
        "False_Alarm_Rate_Percent": round(far, 2),
        "Confusion_Matrix": cm.tolist()
    }


def benchmark_classifiers(
    models: Dict[str, Any],
    X_train: np.ndarray,
    y_train: np.ndarray,
    cv_folds: int = 5,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Runs Stratified K-Fold Cross-Validation across threat classification architectures.
    """
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    results = []
    
    scoring = {
        "accuracy": "accuracy",
        "f1_macro": "f1_macro",
        "precision_macro": "precision_macro",
        "recall_macro": "recall_macro"
    }
    
    for model_name, model in models.items():
        print(f"[*] Benchmarking {model_name} with {cv_folds}-Fold Stratified CV...")
        cv_res = cross_validate(model, X_train, y_train, cv=skf, scoring=scoring, n_jobs=-1)
        
        mean_acc = np.mean(cv_res["test_accuracy"])
        mean_f1 = np.mean(cv_res["test_f1_macro"])
        std_f1 = np.std(cv_res["test_f1_macro"])
        mean_prec = np.mean(cv_res["test_precision_macro"])
        mean_rec = np.mean(cv_res["test_recall_macro"])
        
        results.append({
            "Model": model_name,
            "CV_F1_Macro_Mean": round(mean_f1, 4),
            "CV_F1_Macro_Std": round(std_f1, 4),
            "CV_Accuracy": round(mean_acc, 4),
            "CV_Precision": round(mean_prec, 4),
            "CV_Recall": round(mean_rec, 4)
        })
        
    df_results = pd.DataFrame(results).sort_values(by="CV_F1_Macro_Mean", ascending=False).reset_index(drop=True)
    return df_results
