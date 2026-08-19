"""
Supervised Multi-Class Intrusion Classifier & Unsupervised Zero-Day Anomaly Detection Models
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

import joblib


def get_supervised_classifiers(random_state: int = 42) -> Dict[str, Any]:
    """
    Returns candidate multi-class classification models for network threat categorization.
    """
    models = {
        "Random_Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            class_weight="balanced",
            n_jobs=1,
            random_state=random_state
        ),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=100,
            learning_rate=0.08,
            max_depth=5,
            subsample=0.85,
            colsample_bytree=0.85,
            n_jobs=1,
            random_state=random_state
        )
    }
    
    if HAS_LIGHTGBM:
        models["LightGBM"] = lgb.LGBMClassifier(
            n_estimators=100,
            learning_rate=0.08,
            num_leaves=31,
            class_weight="balanced",
            n_jobs=1,
            random_state=random_state,
            verbose=-1
        )
        
    return models


def build_voting_threat_detector(random_state: int = 42) -> VotingClassifier:
    """
    Constructs soft-voting ensemble for high-precision multi-class attack detection.
    """
    estimators = [
        ("rf", RandomForestClassifier(n_estimators=100, max_depth=10, class_weight="balanced", n_jobs=1, random_state=random_state)),
        ("xgb", xgb.XGBClassifier(n_estimators=100, learning_rate=0.08, max_depth=5, n_jobs=1, random_state=random_state))
    ]
    
    if HAS_LIGHTGBM:
        estimators.append(
            ("lgbm", lgb.LGBMClassifier(n_estimators=100, learning_rate=0.08, num_leaves=31, class_weight="balanced", n_jobs=1, random_state=random_state, verbose=-1))
        )
        
    ensemble = VotingClassifier(
        estimators=estimators,
        voting="soft",
        n_jobs=1
    )
    return ensemble


def build_zero_day_anomaly_detector(contamination: float = 0.05, random_state: int = 42) -> IsolationForest:
    """
    Builds unsupervised Isolation Forest for zero-day network anomaly detection.
    """
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1
    )
    return iso_forest


def save_artifacts(
    pipeline: Any,
    classifier: Any,
    anomaly_detector: Any,
    label_encoder: LabelEncoder,
    metrics: Dict[str, Any],
    feature_names: list,
    output_dir: str
) -> None:
    """Saves serialized model pipelines and telemetry metadata."""
    os.makedirs(output_dir, exist_ok=True)
    
    joblib.dump(pipeline, os.path.join(output_dir, "preprocessor.joblib"))
    joblib.dump(classifier, os.path.join(output_dir, "intrusion_detector.joblib"))
    joblib.dump(anomaly_detector, os.path.join(output_dir, "anomaly_detector.joblib"))
    joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.joblib"))
    
    with open(os.path.join(output_dir, "metrics_summary.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    with open(os.path.join(output_dir, "feature_metadata.json"), "w", encoding="utf-8") as f:
        json.dump({
            "feature_names": feature_names,
            "classes": list(label_encoder.classes_),
            "total_features": len(feature_names)
        }, f, indent=2)
        
    print(f"[+] Artifacts saved to {output_dir}")
