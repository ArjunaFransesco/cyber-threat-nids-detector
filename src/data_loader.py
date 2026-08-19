"""
Network Flow Traffic Dataset Generator & Ingestion Module
Generates high-fidelity network telemetry with multi-class attack profiles and zero-day anomalies.
"""

import os
import sys
import numpy as np
import pandas as pd
from typing import Tuple, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def generate_network_traffic_data(
    n_samples: int = 6000,
    random_state: int = 42,
    output_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Generates synthetic network telemetry records across Benign and Cyber Threat attack vectors.
    """
    np.random.seed(random_state)
    
    categories = [
        ("Benign", 0.60),
        ("DoS_DDoS", 0.18),
        ("PortScan", 0.10),
        ("BruteForce", 0.07),
        ("Botnet_C2", 0.05)
    ]
    
    records = []
    
    for cat_name, cat_ratio in categories:
        n_cat = int(n_samples * cat_ratio)
        
        for _ in range(n_cat):
            if cat_name == "Benign":
                protocol = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.70, 0.28, 0.02])
                service = np.random.choice(["HTTPS", "HTTP", "DNS", "SSH", "SMTP"], p=[0.50, 0.25, 0.15, 0.07, 0.03])
                flow_duration = int(np.random.exponential(scale=1200)) + 10
                src_bytes = int(np.random.lognormal(mean=7.5, sigma=1.2))
                dst_bytes = int(np.random.lognormal(mean=8.5, sigma=1.5))
                packet_count = int(np.random.lognormal(mean=3.0, sigma=0.8)) + 2
                syn_count = np.random.choice([1, 2], p=[0.85, 0.15])
                ack_count = packet_count
                fin_count = np.random.choice([1, 2], p=[0.90, 0.10])
                rst_count = 0 if np.random.rand() < 0.95 else 1
                failed_logins = 0
                same_srv_rate = round(float(np.random.uniform(0.75, 1.0)), 3)
                diff_srv_rate = round(float(np.random.uniform(0.0, 0.15)), 3)
                dst_host_count = int(np.random.randint(1, 50))
                dst_host_srv_count = int(np.random.randint(dst_host_count, 100))
                dst_host_serror_rate = round(float(np.random.uniform(0.0, 0.05)), 3)
                dst_host_rerror_rate = round(float(np.random.uniform(0.0, 0.04)), 3)
                is_intrusion = 0
                
            elif cat_name == "DoS_DDoS":
                protocol = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.60, 0.35, 0.05])
                service = np.random.choice(["HTTP", "HTTPS", "DNS"], p=[0.50, 0.30, 0.20])
                flow_duration = int(np.random.exponential(scale=150)) + 5
                src_bytes = int(np.random.lognormal(mean=9.5, sigma=1.0))
                dst_bytes = int(np.random.lognormal(mean=4.0, sigma=1.0))  # Low response
                packet_count = int(np.random.lognormal(mean=6.5, sigma=1.0)) + 20
                syn_count = int(packet_count * np.random.uniform(0.7, 0.95))
                ack_count = int(packet_count * np.random.uniform(0.0, 0.1))
                fin_count = 0
                rst_count = int(packet_count * np.random.uniform(0.1, 0.4))
                failed_logins = 0
                same_srv_rate = round(float(np.random.uniform(0.85, 1.0)), 3)
                diff_srv_rate = round(float(np.random.uniform(0.0, 0.08)), 3)
                dst_host_count = int(np.random.randint(180, 255))
                dst_host_srv_count = int(np.random.randint(150, 255))
                dst_host_serror_rate = round(float(np.random.uniform(0.70, 1.0)), 3)
                dst_host_rerror_rate = round(float(np.random.uniform(0.0, 0.20)), 3)
                is_intrusion = 1
                
            elif cat_name == "PortScan":
                protocol = "TCP"
                service = np.random.choice(["OTHER", "HTTP", "SSH", "FTP"], p=[0.60, 0.15, 0.15, 0.10])
                flow_duration = int(np.random.uniform(1, 45))
                src_bytes = int(np.random.uniform(40, 120))
                dst_bytes = 0 if np.random.rand() < 0.8 else int(np.random.uniform(20, 60))
                packet_count = np.random.choice([1, 2, 3])
                syn_count = packet_count
                ack_count = 0
                fin_count = 0
                rst_count = 1 if dst_bytes > 0 else 0
                failed_logins = 0
                same_srv_rate = round(float(np.random.uniform(0.0, 0.20)), 3)
                diff_srv_rate = round(float(np.random.uniform(0.70, 1.0)), 3)
                dst_host_count = int(np.random.randint(200, 255))
                dst_host_srv_count = int(np.random.randint(1, 15))
                dst_host_serror_rate = round(float(np.random.uniform(0.50, 0.95)), 3)
                dst_host_rerror_rate = round(float(np.random.uniform(0.30, 0.80)), 3)
                is_intrusion = 1
                
            elif cat_name == "BruteForce":
                protocol = "TCP"
                service = np.random.choice(["SSH", "FTP", "TELNET"], p=[0.60, 0.30, 0.10])
                flow_duration = int(np.random.exponential(scale=3500)) + 500
                src_bytes = int(np.random.lognormal(mean=6.8, sigma=0.5))
                dst_bytes = int(np.random.lognormal(mean=6.5, sigma=0.6))
                packet_count = int(np.random.randint(15, 60))
                syn_count = int(np.random.randint(2, 6))
                ack_count = packet_count - syn_count
                fin_count = 1
                rst_count = int(np.random.randint(1, 4))
                failed_logins = int(np.random.randint(3, 15))
                same_srv_rate = round(float(np.random.uniform(0.80, 1.0)), 3)
                diff_srv_rate = round(float(np.random.uniform(0.0, 0.10)), 3)
                dst_host_count = int(np.random.randint(10, 80))
                dst_host_srv_count = int(np.random.randint(5, 40))
                dst_host_serror_rate = round(float(np.random.uniform(0.0, 0.25)), 3)
                dst_host_rerror_rate = round(float(np.random.uniform(0.20, 0.60)), 3)
                is_intrusion = 1
                
            else:  # Botnet / C2
                protocol = np.random.choice(["TCP", "UDP"], p=[0.75, 0.25])
                service = np.random.choice(["IRC", "HTTPS", "DNS", "OTHER"], p=[0.35, 0.35, 0.20, 0.10])
                flow_duration = int(np.random.normal(5000, 400))  # Periodic beaconing
                src_bytes = int(np.random.lognormal(mean=6.0, sigma=0.4))
                dst_bytes = int(np.random.lognormal(mean=8.8, sigma=1.0))
                packet_count = int(np.random.randint(8, 25))
                syn_count = 1
                ack_count = packet_count - 1
                fin_count = 1
                rst_count = 0
                failed_logins = 0
                same_srv_rate = round(float(np.random.uniform(0.40, 0.85)), 3)
                diff_srv_rate = round(float(np.random.uniform(0.15, 0.50)), 3)
                dst_host_count = int(np.random.randint(5, 50))
                dst_host_srv_count = int(np.random.randint(2, 30))
                dst_host_serror_rate = round(float(np.random.uniform(0.0, 0.15)), 3)
                dst_host_rerror_rate = round(float(np.random.uniform(0.0, 0.10)), 3)
                is_intrusion = 1
                
            # Derived rates
            byte_rate = (src_bytes + dst_bytes) / (flow_duration / 1000.0 + 1e-4)
            packet_rate = packet_count / (flow_duration / 1000.0 + 1e-4)
            
            records.append({
                "flow_duration_ms": flow_duration,
                "protocol_type": protocol,
                "service": service,
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
                "packet_count": packet_count,
                "byte_rate": round(byte_rate, 2),
                "packet_rate": round(packet_rate, 2),
                "syn_count": syn_count,
                "ack_count": ack_count,
                "fin_count": fin_count,
                "rst_count": rst_count,
                "failed_logins": failed_logins,
                "same_srv_rate": same_srv_rate,
                "diff_srv_rate": diff_srv_rate,
                "dst_host_count": dst_host_count,
                "dst_host_srv_count": dst_host_srv_count,
                "dst_host_serror_rate": dst_host_serror_rate,
                "dst_host_rerror_rate": dst_host_rerror_rate,
                "attack_category": cat_name,
                "is_intrusion": is_intrusion
            })
            
    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"[+] Generated and saved {len(df)} network flow records to {output_path}")
        
    return df


def load_dataset(data_path: Optional[str] = None) -> pd.DataFrame:
    """Loads dataset from path or synthesizes if not present."""
    if data_path and os.path.exists(data_path):
        return pd.read_csv(data_path)
    
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "network_traffic_dataset.csv"
    )
    if os.path.exists(default_path):
        return pd.read_csv(default_path)
    
    return generate_network_traffic_data(output_path=default_path)


def split_features_targets(
    df: pd.DataFrame
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Separates feature matrix X, multi-class target y_cat, and binary target y_bin."""
    X = df.drop(columns=["attack_category", "is_intrusion"])
    y_cat = df["attack_category"]
    y_bin = df["is_intrusion"]
    return X, y_cat, y_bin
