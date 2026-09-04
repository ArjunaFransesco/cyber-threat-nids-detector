# 🛡️ Cyber Threat NIDS & Network Anomaly Detection Engine

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-111?style=for-the-badge&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

A dual-engine Cybersecurity Machine Learning system engineered for real-time Network Intrusion Detection (NIDS), multi-class attack classification, and unsupervised zero-day anomaly scoring on IPFIX / NetFlow telemetry.

---

## 📌 Executive Summary & SOC SecOps Value

Modern Security Operations Centers (SOCs) face alert fatigue and evasion techniques from sophisticated cyber adversaries. Traditional signature-only firewalls fail against polymorphic malware and zero-day volumetric anomalies.

This platform bridges the gap with a **hybrid AI architecture**:
1. **Supervised Multi-Class Classifier**: Accurately categorizes explicit attack vectors (DoS/DDoS, Port Scanning, SSH Brute Force, Botnet C2).
2. **Unsupervised Isolation Forest**: Establishes a mathematical baseline of benign network flow to detect zero-day telemetry anomalies without prior signatures.
3. **Automated Firewall Triage**: Calculates composite Threat Severity Scores (0–100) and triggers automated mitigation rules (`ALLOW`, `RATE_LIMIT`, `DROP_ALERT`, `BLOCK_IP`).

---

## 🏗️ Dual-Engine NIDS Architecture

```
┌─────────────────────────────────┐
│ IPFIX / NetFlow Packet Streams  │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ Flow Preprocessor (SYN/ACK Ratios, Byte Rates, Host Dispersion) │
└────────────────┬────────────────────────────────────────────────┘
                 │
        ┌────────┴────────────────────────┐
        ▼                                 ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│ Supervised Threat Engine  │   │ Unsupervised Zero-Day     │
│ (Random Forest & XGBoost) │   │ Isolation Forest Engine   │
└───────────────┬───────────┘   └─────────────┬─────────────┘
                │                             │
                └──────────────┬──────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Threat Severity Scoring (0-100) & Automated Firewall Mitigation │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Production REST API & Interactive SOC SIEM Incident Dashboard   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Model Benchmark & Detection Metrics

Evaluated on stratified holdout test partitions (1,200 network flows):

| Model Architecture | Accuracy | F1-Macro | Recall (Detection Rate) | False Alarm Rate (FAR) |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** 🌟 | **1.0000** | **1.0000** | **1.0000** | **0.0000** |
| **XGBoost Classifier** | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **LightGBM Classifier** | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **Soft-Voting Ensemble** | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

---

## 🎯 Target Threat Vectors & Signatures

| Attack Vector | Category Code | Telemetry Indicators | Firewall Automated Action |
| :--- | :---: | :--- | :--- |
| **Benign Traffic** | `Benign` | Balanced SYN/ACK ratios, standard byte volumes | `ALLOW_TRAFFIC` |
| **SYN Flood DDoS** | `DoS_DDoS` | Massive packet rate (>3,000 pkts/s), SYN:ACK disparity | `BLOCK_IP_QUARANTINE` |
| **Port Scan Recon** | `PortScan` | High cross-service scan rates, low packet count | `DROP_PACKET_ALERT` |
| **SSH Brute Force** | `BruteForce` | Repeated failed authentication attempts, uniform flows | `DROP_PACKET_ALERT` |
| **Botnet C2** | `Botnet_C2` | Periodic beaconing packets, distributed host dispersion | `BLOCK_IP_QUARANTINE` |

---

## 📁 Repository Structure

```
cyber-threat-nids-detector/
├── app/
│   ├── static/
│   │   ├── css/style.css       # Dark SOC / SIEM styling
│   │   └── js/app.js           # Live telemetry simulator & risk engine
│   ├── templates/
│   │   └── index.html          # Interactive SOC incident dashboard
│   └── main.py                 # Flask server & REST API
├── data/
│   └── raw/
│       └── network_traffic_dataset.csv # NetFlow telemetry dataset
├── models/
│   ├── intrusion_detector.joblib # Multi-class classifier artifact
│   ├── anomaly_detector.joblib   # Zero-day Isolation Forest artifact
│   ├── preprocessor.joblib       # Scikit-Learn transformer
│   └── label_encoder.joblib      # Threat class encoder
├── notebooks/
│   └── network_intrusion_detection_pipeline.ipynb # Full SecOps EDA & Pipeline
├── reports/
│   └── model_evaluation_metrics.json # Automated evaluation report
├── src/
│   ├── __init__.py
│   ├── data_loader.py          # NetFlow telemetry dataset generator
│   ├── feature_engineering.py  # Network security ratios & transformers
│   ├── models.py               # Model builders & serialization
│   ├── train.py                # Multi-model training pipeline
│   └── predict.py              # Real-time flow inspector & mitigation engine
├── requirements.txt            # Dependencies
├── .gitignore                  # Git exclusions
└── README.md                   # Documentation
```

---

## 🚀 Quickstart & Setup

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/ArjunaFransesco/cyber-threat-nids-detector.git
cd cyber-threat-nids-detector
pip install -r requirements.txt
```

### 2. Train and Benchmark Models
```bash
python src/train.py
```

### 3. Launch Interactive SOC Incident Response Dashboard
```bash
python app/main.py
```
Open [http://localhost:5002](http://localhost:5002) in your browser.

---

## 🔌 SecOps REST API Specification

### Endpoint: `POST /api/predict`
Inspects network packet flow and classifies threat:

```json
{
  "flow_duration_ms": 120,
  "protocol_type": "TCP",
  "service": "HTTP",
  "src_bytes": 12000,
  "dst_bytes": 200,
  "packet_count": 450,
  "byte_rate": 95000,
  "packet_rate": 3750,
  "syn_count": 440,
  "ack_count": 2,
  "fin_count": 0,
  "rst_count": 0,
  "failed_logins": 0,
  "same_srv_rate": 0.99,
  "diff_srv_rate": 0.01,
  "dst_host_count": 255,
  "dst_host_srv_count": 255,
  "dst_host_serror_rate": 0.85,
  "dst_host_rerror_rate": 0.0
}
```

#### Response:
```json
{
  "status": "success",
  "data": {
    "threat_category": "DoS_DDoS",
    "threat_level": "Critical Attack: DoS_DDoS",
    "confidence": 0.77,
    "severity_score": 88.5,
    "is_zero_day_anomaly": true,
    "anomaly_score": -0.1329,
    "firewall_action": "BLOCK_IP_QUARANTINE",
    "color_code": "#ef4444",
    "indicators": [
      "SYN Flood Signature: Excessive SYN packets (440) with minimal ACK (2)",
      "TCP SYN Error Rate (85.0%) indicates connection exhaustion attempt"
    ],
    "probability_breakdown": {
      "DoS_DDoS": 0.77,
      "Benign": 0.11,
      "PortScan": 0.06,
      "Botnet_C2": 0.03,
      "BruteForce": 0.03
    }
  }
}
```

---

## 👤 Author & Portfolio
- **Author:** [Arjuna Fransesco](https://github.com/ArjunaFransesco)
- **GitHub Repositories:** [https://github.com/ArjunaFransesco?tab=repositories](https://github.com/ArjunaFransesco?tab=repositories)
- **Portfolio Website:** [https://github.com/ArjunaFransesco/arjuna-portfolio](https://github.com/ArjunaFransesco/arjuna-portfolio)


<!-- Last Maintenance Audit: 2026-09-04 -->
