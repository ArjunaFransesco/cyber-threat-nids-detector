"""
End-to-End Network Intrusion Detection Machine Learning Pipeline
Author: Arjuna Fransesco
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from src.data_loader import load_dataset, split_features_targets
from src.feature_engineering import build_preprocessor
from src.models import (
    get_supervised_classifiers,
    build_voting_threat_detector,
    build_zero_day_anomaly_detector,
    save_artifacts
)
from src.evaluate import calculate_nids_metrics, benchmark_classifiers


def run_pipeline(
    data_path: str = None,
    artifacts_dir: str = None,
    random_state: int = 42
):
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 80)
    print("      NETWORK INTRUSION & ANOMALY DETECTION SYSTEM (NIDS) PIPELINE      ")
    print("=" * 80)
    
    # 1. Path Setup
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if data_path is None:
        data_path = os.path.join(base_dir, "data", "network_traffic_dataset.csv")
    if artifacts_dir is None:
        artifacts_dir = os.path.join(base_dir, "artifacts")
        
    # 2. Data Loading
    print("\n[1/6] Loading / Synthesizing Network Flow Telemetry...")
    df = load_dataset(data_path)
    print(f"      Total flow records: {len(df):,} | Features: {df.shape[1]}")
    print(f"      Threat Distribution:\n{df['attack_category'].value_counts().to_string()}")
    
    # 3. Train-Test Splitting (Stratified)
    print("\n[2/6] Splitting Features & Stratified Targets (80% Train / 20% Test)...")
    X, y_cat, y_bin = split_features_targets(df)
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_cat)
    
    X_train, X_test, y_train, y_test, y_bin_train, y_bin_test = train_test_split(
        X, y_encoded, y_bin.values, test_size=0.20, stratify=y_encoded, random_state=random_state
    )
    print(f"      Train samples: {len(X_train):,} | Test samples: {len(X_test):,}")
    print(f"      Target Classes: {list(le.classes_)}")
    
    # 4. Feature Engineering
    print("\n[3/6] Fitting Network Telemetry Preprocessor...")
    preprocessor = build_preprocessor()
    X_train_trans = preprocessor.fit_transform(X_train)
    X_test_trans = preprocessor.transform(X_test)
    
    ohe_cats = preprocessor.named_steps["col_transforms"].named_transformers_["cat"].get_feature_names_out()
    num_cols = preprocessor.named_steps["col_transforms"].transformers[0][2]
    feature_names = list(num_cols) + list(ohe_cats)
    print(f"      Total Transformed Features: {len(feature_names)}")
    
    # 5. Candidate Classifier Benchmarking
    print("\n[4/6] Running 5-Fold Stratified Cross-Validation on Candidate Classifiers...")
    candidate_models = get_supervised_classifiers(random_state=random_state)
    benchmark_df = benchmark_classifiers(
        candidate_models,
        X_train_trans,
        y_train,
        cv_folds=5,
        random_state=random_state
    )
    print("\n--- 5-Fold Cross-Validation Benchmark Results ---")
    print(benchmark_df.to_string(index=False))
    
    # 6. Training Final Voting Ensemble Classifier
    print("\n[5/6] Training Multi-Class Threat Voting Ensemble...")
    threat_classifier = build_voting_threat_detector(random_state=random_state)
    threat_classifier.fit(X_train_trans, y_train)
    
    # Train Unsupervised Zero-Day Anomaly Detector (on Benign + Train flows)
    print("\n[6/6] Training Unsupervised Zero-Day Isolation Forest...")
    benign_class_idx = list(le.classes_).index("Benign")
    benign_train_mask = (y_train == benign_class_idx)
    anomaly_detector = build_zero_day_anomaly_detector(contamination=0.04, random_state=random_state)
    anomaly_detector.fit(X_train_trans[benign_train_mask])
    
    # Holdout Test Evaluation
    y_test_pred = threat_classifier.predict(X_test_trans)
    test_metrics = calculate_nids_metrics(y_test, y_test_pred, label_encoder=le)
    
    print("\n" + "=" * 60)
    print("        FINAL TEST SET EVALUATION (THREAT DETECTOR)        ")
    print("=" * 60)
    print(f"  * Accuracy                 : {test_metrics['Accuracy'] * 100:.2f}%")
    print(f"  * F1-Macro                 : {test_metrics['F1_Macro']:.4f}")
    print(f"  * F1-Weighted              : {test_metrics['F1_Weighted']:.4f}")
    print(f"  * Precision-Macro          : {test_metrics['Precision_Macro']:.4f}")
    print(f"  * Recall-Macro             : {test_metrics['Recall_Macro']:.4f}")
    print(f"  * Attack Detection Rate    : {test_metrics['Detection_Rate_Percent']:.2f}%")
    print(f"  * False Alarm Rate (FAR)   : {test_metrics['False_Alarm_Rate_Percent']:.2f}%")
    print("=" * 60)
    
    # Save artifacts
    all_metrics = {
        "test_performance": test_metrics,
        "cv_benchmark": benchmark_df.to_dict(orient="records"),
        "classes": list(le.classes_),
        "dataset_summary": {
            "total_records": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "features_count": len(feature_names)
        }
    }
    
    save_artifacts(
        pipeline=preprocessor,
        classifier=threat_classifier,
        anomaly_detector=anomaly_detector,
        label_encoder=le,
        metrics=all_metrics,
        feature_names=feature_names,
        output_dir=artifacts_dir
    )
    
    print("\n[+] NIDS Pipeline execution completed successfully!\n")
    return test_metrics


if __name__ == "__main__":
    run_pipeline()
