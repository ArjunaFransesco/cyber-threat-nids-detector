"""
Real-time Network Flow Inspection & Threat Inference Engine
Evaluates multi-class attack probabilities, zero-day anomaly scores, and SOC mitigation actions.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple


class NetworkThreatPredictor:
    def __init__(self, artifacts_dir: str = "models"):
        if not os.path.isabs(artifacts_dir):
            artifacts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), artifacts_dir)

        self.preprocessor = joblib.load(os.path.join(artifacts_dir, "preprocessor.joblib"))
        self.classifier = joblib.load(os.path.join(artifacts_dir, "intrusion_detector.joblib"))
        self.anomaly_detector = joblib.load(os.path.join(artifacts_dir, "anomaly_detector.joblib"))
        self.label_encoder = joblib.load(os.path.join(artifacts_dir, "label_encoder.joblib"))
        self.classes = list(self.label_encoder.classes_)

    def determine_mitigation_action(self, threat_category: str, severity_score: float, is_anomaly: bool) -> Tuple[str, str, str]:
        """
        Determines automated firewall action, risk level, and color code.
        """
        if threat_category == "Benign" and not is_anomaly:
            return "ALLOW_TRAFFIC", "Clean Traffic", "#10b981"
        elif threat_category == "Benign" and is_anomaly:
            return "RATE_LIMIT_IP", "Suspicious Zero-Day Anomaly", "#f59e0b"
        elif threat_category in ["PortScan", "BruteForce"] or severity_score < 75:
            return "DROP_PACKET_ALERT", f"Active Threat: {threat_category}", "#f97316"
        else:
            return "BLOCK_IP_QUARANTINE", f"Critical Attack: {threat_category}", "#ef4444"

    def extract_threat_indicators(self, flow: Dict[str, Any]) -> List[str]:
        indicators = []
        syn = float(flow.get("syn_count", 0))
        ack = float(flow.get("ack_count", 0))
        pkts = float(flow.get("packet_count", 1))

        if pkts > 0 and (syn / pkts) > 0.70 and ack <= 2:
            indicators.append(f"SYN Flood Signature: Excessive SYN packets ({syn:.0f}) with minimal ACK ({ack:.0f})")

        pkt_rate = float(flow.get("packet_rate", 0))
        if pkt_rate > 5000:
            indicators.append(f"Volumetric Anomaly: Packet rate ({pkt_rate:,.0f} pkts/sec) exceeds normal baseline")

        failed_logins = int(flow.get("failed_logins", 0))
        if failed_logins >= 3:
            indicators.append(f"Authentication Attack: {failed_logins} consecutive failed login attempts detected")

        diff_srv = float(flow.get("diff_srv_rate", 0))
        if diff_srv > 0.40:
            indicators.append(f"Reconnaissance Scan: High cross-service scan rate ({diff_srv:.1%}) targeting multiple ports")

        serror = float(flow.get("dst_host_serror_rate", 0))
        if serror > 0.30:
            indicators.append(f"TCP SYN Error Rate ({serror:.1%}) indicates connection exhaustion attempt")

        return indicators

    def inspect_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        df_input = pd.DataFrame([flow_dict])
        X_trans = self.preprocessor.transform(df_input)

        # 1. Supervised Attack Classification
        probs = self.classifier.predict_proba(X_trans)[0]
        pred_idx = np.argmax(probs)
        threat_class = self.classes[pred_idx]
        confidence = float(probs[pred_idx])

        # 2. Unsupervised Zero-Day Anomaly Detection
        # Isolation Forest score: negative = anomaly, positive = normal
        iso_score = float(self.anomaly_detector.decision_function(X_trans)[0])
        is_zero_day_anomaly = bool(iso_score < 0)

        # 3. Composite Threat Severity Score (0 - 100)
        if threat_class == "Benign":
            base_severity = (1.0 - confidence) * 35.0
            if is_zero_day_anomaly:
                base_severity += 30.0 + min(abs(iso_score) * 50.0, 30.0)
        else:
            base_severity = 50.0 + (confidence * 50.0)

        severity_score = min(max(round(float(base_severity), 1), 0.0), 100.0)

        # 4. Action & Risk Tiers
        action, threat_level, color = self.determine_mitigation_action(
            threat_class, severity_score, is_zero_day_anomaly
        )

        indicators = self.extract_threat_indicators(flow_dict)

        # Probabilities breakdown
        prob_breakdown = {
            cls_name: round(float(p), 4)
            for cls_name, p in sorted(zip(self.classes, probs), key=lambda x: x[1], reverse=True)
        }

        return {
            "threat_category": threat_class,
            "threat_level": threat_level,
            "confidence": round(confidence, 4),
            "severity_score": severity_score,
            "is_zero_day_anomaly": is_zero_day_anomaly,
            "anomaly_score": round(iso_score, 4),
            "firewall_action": action,
            "color_code": color,
            "indicators": indicators,
            "probability_breakdown": prob_breakdown
        }


if __name__ == "__main__":
    predictor = NetworkThreatPredictor()

    sample_benign = {
        "flow_duration_ms": 1200, "protocol_type": "TCP", "service": "HTTPS",
        "src_bytes": 1400, "dst_bytes": 4500, "packet_count": 18,
        "byte_rate": 4900, "packet_rate": 15, "syn_count": 1, "ack_count": 18,
        "fin_count": 1, "rst_count": 0, "failed_logins": 0, "same_srv_rate": 0.95,
        "diff_srv_rate": 0.02, "dst_host_count": 12, "dst_host_srv_count": 45,
        "dst_host_serror_rate": 0.01, "dst_host_rerror_rate": 0.0
    }

    sample_ddos = {
        "flow_duration_ms": 120, "protocol_type": "TCP", "service": "HTTP",
        "src_bytes": 12000, "dst_bytes": 200, "packet_count": 450,
        "byte_rate": 95000, "packet_rate": 3750, "syn_count": 440, "ack_count": 2,
        "fin_count": 0, "rst_count": 0, "failed_logins": 0, "same_srv_rate": 0.99,
        "diff_srv_rate": 0.01, "dst_host_count": 255, "dst_host_srv_count": 255,
        "dst_host_serror_rate": 0.85, "dst_host_rerror_rate": 0.0
    }

    print("\n--- Benign Telemetry Inspection ---")
    print(predictor.inspect_flow(sample_benign))

    print("\n--- DDoS Attack Telemetry Inspection ---")
    print(predictor.inspect_flow(sample_ddos))
