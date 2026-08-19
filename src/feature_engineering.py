"""
Feature Engineering and Network Telemetry Preprocessing Pipeline
Computes flow ratios, TCP flag proportions, host dispersion, and error composites.
"""

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, RobustScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline


class NetworkFlowFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    Computes domain-specific network security ratios and telemetry representations.
    """
    def __init__(self):
        pass
        
    def fit(self, X: pd.DataFrame, y=None):
        return self
        
    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        df = X.copy()
        
        # 1. Byte and Packet Balance
        df["src_to_dst_byte_ratio"] = df["src_bytes"] / (df["dst_bytes"] + 1.0)
        df["dst_to_src_byte_ratio"] = df["dst_bytes"] / (df["src_bytes"] + 1.0)
        df["bytes_per_packet"] = (df["src_bytes"] + df["dst_bytes"]) / (df["packet_count"] + 1e-5)
        
        # 2. TCP Flag Dynamics
        df["syn_ratio"] = df["syn_count"] / (df["packet_count"] + 1e-5)
        df["ack_ratio"] = df["ack_count"] / (df["packet_count"] + 1e-5)
        df["rst_ratio"] = df["rst_count"] / (df["packet_count"] + 1e-5)
        df["syn_ack_disparity"] = np.abs(df["syn_count"] - df["ack_count"])
        
        # 3. Connection and Error Aggregations
        df["total_error_rate"] = df["dst_host_serror_rate"] + df["dst_host_rerror_rate"]
        df["host_srv_dispersion"] = df["dst_host_srv_count"] / (df["dst_host_count"] + 1e-5)
        df["srv_diff_ratio"] = df["diff_srv_rate"] / (df["same_srv_rate"] + 1e-4)
        
        # 4. Log-transformed Volume & Rate Distributions
        df["log_flow_duration"] = np.log1p(df["flow_duration_ms"])
        df["log_byte_rate"] = np.log1p(df["byte_rate"])
        df["log_packet_rate"] = np.log1p(df["packet_rate"])
        df["log_src_bytes"] = np.log1p(df["src_bytes"])
        df["log_dst_bytes"] = np.log1p(df["dst_bytes"])
        
        return df


def build_preprocessor() -> Pipeline:
    """
    Constructs complete Scikit-Learn transformer for network telemetry.
    """
    categorical_cols = ["protocol_type", "service"]
    
    numeric_cols = [
        "flow_duration_ms", "src_bytes", "dst_bytes", "packet_count", "byte_rate",
        "packet_rate", "syn_count", "ack_count", "fin_count", "rst_count",
        "failed_logins", "same_srv_rate", "diff_srv_rate", "dst_host_count",
        "dst_host_srv_count", "dst_host_serror_rate", "dst_host_rerror_rate",
        "src_to_dst_byte_ratio", "dst_to_src_byte_ratio", "bytes_per_packet",
        "syn_ratio", "ack_ratio", "rst_ratio", "syn_ack_disparity",
        "total_error_rate", "host_srv_dispersion", "srv_diff_ratio",
        "log_flow_duration", "log_byte_rate", "log_packet_rate",
        "log_src_bytes", "log_dst_bytes"
    ]
    
    col_transformer = ColumnTransformer(
        transformers=[
            ("num", RobustScaler(), numeric_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical_cols)
        ],
        remainder="drop"
    )
    
    pipeline = Pipeline([
        ("custom_telemetry", NetworkFlowFeatureTransformer()),
        ("col_transforms", col_transformer)
    ])
    
    return pipeline
