"""
Flask Application & Cyber Threat Intelligence API for Network Intrusion Detection
"""

import json
import os
import random
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, jsonify, render_template, request
from src.predict import NetworkThreatPredictor

app = Flask(__name__)

# Initialize predictor
try:
    predictor = NetworkThreatPredictor(artifacts_dir=os.path.join(os.path.dirname(__file__), "../models"))
except Exception as e:
    print(f"[!] Warning: Falling back to default models dir ({e})")
    predictor = NetworkThreatPredictor()

# Load stats
metrics_path = os.path.join(os.path.dirname(__file__), "../reports/model_evaluation_metrics.json")
if os.path.exists(metrics_path):
    with open(metrics_path, "r", encoding="utf-8") as f:
        MODEL_STATS = json.load(f)
else:
    MODEL_STATS = {}


@app.route("/")
def home():
    return render_template("index.html", stats=MODEL_STATS)


@app.route("/api/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "message": "No telemetry payload provided"}), 400

        result = predictor.inspect_flow(data)
        return jsonify({
            "status": "success",
            "data": result
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(MODEL_STATS)


@app.route("/api/simulate", methods=["GET"])
def simulate():
    """Generates synthetic live packet flow for real-time SOC monitoring demo."""
    attack_type = request.args.get("type", random.choice(["benign", "ddos", "portscan", "bruteforce", "botnet"]))

    if attack_type == "benign":
        payload = {
            "flow_duration_ms": random.randint(200, 2500), "protocol_type": "TCP", "service": "HTTPS",
            "src_bytes": random.randint(800, 3500), "dst_bytes": random.randint(2000, 15000), "packet_count": random.randint(10, 35),
            "byte_rate": random.randint(1500, 8000), "packet_rate": random.randint(5, 30),
            "syn_count": 1, "ack_count": random.randint(10, 35), "fin_count": 1, "rst_count": 0,
            "failed_logins": 0, "same_srv_rate": round(random.uniform(0.85, 1.0), 3),
            "diff_srv_rate": round(random.uniform(0.0, 0.05), 3), "dst_host_count": random.randint(5, 30),
            "dst_host_srv_count": random.randint(30, 80), "dst_host_serror_rate": 0.01, "dst_host_rerror_rate": 0.0
        }
    elif attack_type == "ddos":
        pkts = random.randint(300, 800)
        payload = {
            "flow_duration_ms": random.randint(50, 250), "protocol_type": "TCP", "service": "HTTP",
            "src_bytes": random.randint(8000, 35000), "dst_bytes": random.randint(50, 400), "packet_count": pkts,
            "byte_rate": random.randint(80000, 250000), "packet_rate": random.randint(2000, 7000),
            "syn_count": pkts - random.randint(0, 5), "ack_count": random.randint(0, 2), "fin_count": 0, "rst_count": 0,
            "failed_logins": 0, "same_srv_rate": 0.99, "diff_srv_rate": 0.01,
            "dst_host_count": 255, "dst_host_srv_count": 255, "dst_host_serror_rate": 0.92, "dst_host_rerror_rate": 0.0
        }
    elif attack_type == "portscan":
        payload = {
            "flow_duration_ms": random.randint(10, 100), "protocol_type": "TCP", "service": "HTTP",
            "src_bytes": 0, "dst_bytes": 0, "packet_count": random.randint(1, 3),
            "byte_rate": 0, "packet_rate": random.randint(50, 400),
            "syn_count": random.randint(1, 3), "ack_count": 0, "fin_count": 0, "rst_count": 1,
            "failed_logins": 0, "same_srv_rate": 0.05, "diff_srv_rate": 0.85,
            "dst_host_count": random.randint(150, 255), "dst_host_srv_count": random.randint(1, 5),
            "dst_host_serror_rate": 0.75, "dst_host_rerror_rate": 0.15
        }
    elif attack_type == "bruteforce":
        payload = {
            "flow_duration_ms": random.randint(500, 4000), "protocol_type": "TCP", "service": "SSH",
            "src_bytes": random.randint(500, 1500), "dst_bytes": random.randint(200, 800), "packet_count": random.randint(15, 40),
            "byte_rate": random.randint(800, 2000), "packet_rate": random.randint(5, 20),
            "syn_count": random.randint(2, 6), "ack_count": random.randint(12, 35), "fin_count": random.randint(2, 6), "rst_count": 0,
            "failed_logins": random.randint(4, 12), "same_srv_rate": 0.95, "diff_srv_rate": 0.02,
            "dst_host_count": random.randint(2, 10), "dst_host_srv_count": random.randint(2, 10),
            "dst_host_serror_rate": 0.05, "dst_host_rerror_rate": 0.0
        }
    else: # botnet
        payload = {
            "flow_duration_ms": random.randint(3000, 12000), "protocol_type": "TCP", "service": "HTTPS",
            "src_bytes": random.randint(400, 1200), "dst_bytes": random.randint(400, 1200), "packet_count": random.randint(8, 20),
            "byte_rate": random.randint(200, 600), "packet_rate": random.randint(1, 4),
            "syn_count": 1, "ack_count": random.randint(7, 18), "fin_count": 1, "rst_count": 0,
            "failed_logins": 0, "same_srv_rate": 0.40, "diff_srv_rate": 0.30,
            "dst_host_count": random.randint(50, 120), "dst_host_srv_count": random.randint(10, 40),
            "dst_host_serror_rate": 0.10, "dst_host_rerror_rate": 0.05
        }

    return jsonify({"attack_type": attack_type, "flow": payload})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "active", "service": "Cyber Threat NIDS AI Engine v1.0"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    print(f"[*] Starting Cyber Threat NIDS SOC Dashboard on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
