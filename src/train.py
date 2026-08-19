"""
Model Training, Benchmarking, and Evaluation Pipeline for Network Intrusion Detection
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
    precision_score,
    recall_score
)

# Set UTF-8 safe output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from data_loader import load_dataset, split_features_targets
from feature_engineering import build_preprocessor
from models import (
    get_supervised_classifiers,
    build_voting_threat_detector,
    build_zero_day_anomaly_detector,
    save_artifacts
)


def run_training_pipeline(
    data_path=None,
    artifacts_dir="models",
    reports_dir="reports"
):
    print("=" * 70)
    print("    CYBER THREAT & NETWORK INTRUSION DETECTION TRAINING PIPELINE     ")
    print("=" * 70)

    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # 1. Load Data
    data_csv = data_path or os.path.join("data", "raw", "network_traffic_dataset.csv")
    df = load_dataset(data_csv)
    print(f"[+] Loaded network telemetry dataset: {len(df)} flow records, {df.shape[1]} features")

    # 2. Split Features & Targets
    X, y_cat, y_bin = split_features_targets(df)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_cat)
    classes = list(label_encoder.classes_)
    print(f"[+] Identified Attack Categories ({len(classes)}): {classes}")

    # 3. Train/Test Stratified Split (80% Train, 20% Holdout Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    print(f"[+] Partition: Train = {len(X_train)} flows, Test = {len(X_test)} flows")

    # 4. Feature Pipeline
    preprocessor = build_preprocessor()
    print("[+] Fitting telemetry preprocessing pipeline...")
    X_train_trans = preprocessor.fit_transform(X_train)
    X_test_trans = preprocessor.transform(X_test)

    # Feature names
    try:
        cat_features = list(preprocessor.named_steps["preprocessor"].named_transformers_["cat"].get_feature_names_out())
        num_features = preprocessor.named_steps["preprocessor"].transformers_[1][2]
        feature_names = num_features + cat_features
    except Exception:
        feature_names = [f"feat_{i}" for i in range(X_train_trans.shape[1])]

    # 5. Multi-Class Model Benchmarking
    candidate_models = get_supervised_classifiers()
    candidate_models["Ensemble_Voting"] = build_voting_threat_detector()

    benchmark_results = {}
    fitted_models = {}

    for name, model in candidate_models.items():
        print(f"\n[>] Training model: {name}...")
        model.fit(X_train_trans, y_train)
        fitted_models[name] = model

        y_pred = model.predict(X_test_trans)

        acc = accuracy_score(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average="macro")
        f1_weighted = f1_score(y_test, y_pred, average="weighted")
        prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)

        # False Alarm Rate on Benign class (index of Benign)
        benign_idx = list(label_encoder.classes_).index("Benign") if "Benign" in label_encoder.classes_ else 0
        cm = confusion_matrix(y_test, y_pred)
        # FP for benign is when actual benign is predicted as attack
        benign_total = np.sum(cm[benign_idx, :])
        benign_correct = cm[benign_idx, benign_idx]
        far = (benign_total - benign_correct) / (benign_total + 1e-5)

        benchmark_results[name] = {
            "accuracy": round(float(acc), 4),
            "f1_macro": round(float(f1_macro), 4),
            "f1_weighted": round(float(f1_weighted), 4),
            "precision_macro": round(float(prec_macro), 4),
            "recall_macro": round(float(rec_macro), 4),
            "false_alarm_rate": round(float(far), 4)
        }

        print(f"    Accuracy: {acc:.4f} | F1-Macro: {f1_macro:.4f} | Recall: {rec_macro:.4f} | FAR: {far:.4f}")

    # Best Model Selection
    best_model_name = max(benchmark_results, key=lambda k: benchmark_results[k]["f1_macro"])
    best_model = fitted_models[best_model_name]
    print(f"\n[*] Selected Production Threat Classifier: {best_model_name} (F1-Macro: {benchmark_results[best_model_name]['f1_macro']})")

    # 6. Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
    print("\n[>] Training Unsupervised Zero-Day Anomaly Detector (Isolation Forest)...")
    # Train on Benign traffic only to establish baseline normal behavior
    benign_mask = (y_train == benign_idx)
    X_train_benign = X_train_trans[benign_mask]
    iso_forest = build_zero_day_anomaly_detector(contamination=0.04)
    iso_forest.fit(X_train_benign)
    print("[+] Zero-Day Isolation Forest trained successfully.")

    # 7. Classification Report on Best Model
    y_test_pred = best_model.predict(X_test_trans)
    cls_report = classification_report(y_test, y_test_pred, target_names=classes, output_dict=True)

    # 8. Save Artifacts & Reports
    save_artifacts(
        pipeline=preprocessor,
        classifier=best_model,
        anomaly_detector=iso_forest,
        label_encoder=label_encoder,
        metrics={
            "best_model": best_model_name,
            "benchmark_summary": benchmark_results,
            "classification_report": cls_report,
            "classes": classes,
            "cohort": {
                "total_records": len(df),
                "train_records": len(X_train),
                "test_records": len(X_test)
            }
        },
        feature_names=feature_names,
        output_dir=artifacts_dir
    )

    with open(os.path.join(reports_dir, "model_evaluation_metrics.json"), "w", encoding="utf-8") as f:
        json.dump({
            "best_model": best_model_name,
            "benchmark_comparison": benchmark_results,
            "classification_report": cls_report,
            "classes": classes
        }, f, indent=4)

    print("=================================================================\n")


if __name__ == "__main__":
    run_training_pipeline()
