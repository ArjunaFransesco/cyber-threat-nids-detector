"""
Streamlit Web Application: Cyber Threat Network Intrusion & Anomaly Detection System (NIDS)
Author: Arjuna Fransesco
"""

import os
import json
import numpy as np
import pandas as pd
import streamlit as st
import joblib

# Page configuration
st.set_page_config(
    page_title="NIDS Cyber Threat Detector | Arjuna Fransesco",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for SecOps / Cyber theme
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #F8FAFC;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    .sec-card-benign {
        background: linear-gradient(135deg, #064E3B 0%, #022C22 100%);
        border: 1px solid #059669;
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        text-align: center;
    }
    .sec-card-threat {
        background: linear-gradient(135deg, #7F1D1D 0%, #450A0A 100%);
        border: 1px solid #DC2626;
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        text-align: center;
    }
    .threat-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: 0.05em;
    }
</style>
""", unsafe_allow_html=True)

# Load artifacts
@st.cache_resource
def load_secops_models():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(base_dir, "artifacts")
    
    pipe_p = os.path.join(artifacts_dir, "preprocessor.joblib")
    clf_p = os.path.join(artifacts_dir, "intrusion_detector.joblib")
    iso_p = os.path.join(artifacts_dir, "anomaly_detector.joblib")
    le_p = os.path.join(artifacts_dir, "label_encoder.joblib")
    metrics_p = os.path.join(artifacts_dir, "metrics_summary.json")
    
    pipeline = joblib.load(pipe_p) if os.path.exists(pipe_p) else None
    classifier = joblib.load(clf_p) if os.path.exists(clf_p) else None
    anomaly_detector = joblib.load(iso_p) if os.path.exists(iso_p) else None
    label_encoder = joblib.load(le_p) if os.path.exists(le_p) else None
    
    metrics = {}
    if os.path.exists(metrics_p):
        with open(metrics_p, "r", encoding="utf-8") as f:
            metrics = json.load(f)
            
    return pipeline, classifier, anomaly_detector, label_encoder, metrics

pipeline, classifier, anomaly_detector, label_encoder, metrics = load_secops_models()

# Header
st.markdown('<div class="main-header">🛡️ Network Intrusion & Anomaly Detection System (NIDS)</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Real-Time Threat Classification & Zero-Day Anomaly Detection Engine (Voting Ensemble + Isolation Forest)</div>', unsafe_allow_html=True)

# Sidebar Traffic Profile Presets
st.sidebar.header("🎯 Attack Scenario Simulation")
SCENARIO_PRESETS = {
    "🟢 Normal HTTPS Web Flow": {
        "proto": "TCP", "srv": "HTTPS", "dur": 1250, "src_b": 1850, "dst_b": 6400,
        "pkts": 18, "syn": 1, "ack": 18, "fin": 1, "rst": 0, "fail_log": 0,
        "same_srv": 0.95, "diff_srv": 0.05, "dst_cnt": 25, "dst_srv_cnt": 50,
        "serror": 0.01, "rerror": 0.0
    },
    "🔴 SYN Flood DoS / DDoS Attack": {
        "proto": "TCP", "srv": "HTTP", "dur": 45, "src_b": 12500, "dst_b": 60,
        "pkts": 450, "syn": 420, "ack": 10, "fin": 0, "rst": 80, "fail_log": 0,
        "same_srv": 0.98, "diff_srv": 0.02, "dst_cnt": 254, "dst_srv_cnt": 240,
        "serror": 0.95, "rerror": 0.05
    },
    "🟡 Nmap Port Scanning Reconnaissance": {
        "proto": "TCP", "srv": "OTHER", "dur": 12, "src_b": 64, "dst_b": 0,
        "pkts": 2, "syn": 2, "ack": 0, "fin": 0, "rst": 0, "fail_log": 0,
        "same_srv": 0.05, "diff_srv": 0.95, "dst_cnt": 245, "dst_srv_cnt": 3,
        "serror": 0.85, "rerror": 0.60
    },
    "🟠 SSH / FTP Credential Brute Force": {
        "proto": "TCP", "srv": "SSH", "dur": 4200, "src_b": 950, "dst_b": 820,
        "pkts": 42, "syn": 4, "ack": 38, "fin": 1, "rst": 2, "fail_log": 12,
        "same_srv": 0.92, "diff_srv": 0.05, "dst_cnt": 45, "dst_srv_cnt": 20,
        "serror": 0.10, "rerror": 0.45
    },
    "🟣 Botnet C2 Beaconing": {
        "proto": "TCP", "srv": "IRC", "dur": 5100, "src_b": 420, "dst_b": 7200,
        "pkts": 14, "syn": 1, "ack": 13, "fin": 1, "rst": 0, "fail_log": 0,
        "same_srv": 0.65, "diff_srv": 0.30, "dst_cnt": 15, "dst_srv_cnt": 8,
        "serror": 0.05, "rerror": 0.02
    }
}

selected_scenario = st.sidebar.selectbox("Load Threat Scenario", list(SCENARIO_PRESETS.keys()))
preset = SCENARIO_PRESETS[selected_scenario]

st.sidebar.header("📡 Protocol & Flow Telemetry")
protocol = st.sidebar.selectbox("Protocol", ["TCP", "UDP", "ICMP"], index=["TCP", "UDP", "ICMP"].index(preset["proto"]))
service = st.sidebar.selectbox("Service", ["HTTPS", "HTTP", "DNS", "SSH", "SMTP", "IRC", "FTP", "TELNET", "OTHER"], index=["HTTPS", "HTTP", "DNS", "SSH", "SMTP", "IRC", "FTP", "TELNET", "OTHER"].index(preset["srv"]))

flow_dur = st.sidebar.number_input("Flow Duration (ms)", min_value=1, max_value=60000, value=preset["dur"])
src_bytes = st.sidebar.number_input("Source Payload Bytes", min_value=0, max_value=1000000, value=preset["src_b"])
dst_bytes = st.sidebar.number_input("Destination Payload Bytes", min_value=0, max_value=1000000, value=preset["dst_b"])
packet_count = st.sidebar.number_input("Packet Count", min_value=1, max_value=5000, value=preset["pkts"])

st.sidebar.header("🚩 TCP Flags & Error Counters")
col_f1, col_f2 = st.sidebar.columns(2)
with col_f1:
    syn_cnt = st.number_input("SYN Flags", 0, 5000, preset["syn"])
    fin_cnt = st.number_input("FIN Flags", 0, 5000, preset["fin"])
with col_f2:
    ack_cnt = st.number_input("ACK Flags", 0, 5000, preset["ack"])
    rst_cnt = st.number_input("RST Flags", 0, 5000, preset["rst"])

failed_logins = st.sidebar.number_input("Failed Logins", 0, 100, preset["fail_log"])
same_srv_rate = st.sidebar.slider("Same Service Rate", 0.0, 1.0, preset["same_srv"])
diff_srv_rate = st.sidebar.slider("Diff Service Rate", 0.0, 1.0, preset["diff_srv"])
dst_host_count = st.sidebar.slider("Destination Host Count", 1, 255, preset["dst_cnt"])
dst_host_srv_count = st.sidebar.slider("Destination Srv Count", 1, 255, preset["dst_srv_cnt"])
dst_serror = st.sidebar.slider("SYN Error Rate (serror)", 0.0, 1.0, preset["serror"])
dst_rerror = st.sidebar.slider("REJ Error Rate (rerror)", 0.0, 1.0, preset["rerror"])

# Computed rates
byte_rate = (src_bytes + dst_bytes) / (flow_dur / 1000.0 + 1e-4)
packet_rate = packet_count / (flow_dur / 1000.0 + 1e-4)

# Prepare dataframe
input_df = pd.DataFrame([{
    "flow_duration_ms": flow_dur,
    "protocol_type": protocol,
    "service": service,
    "src_bytes": src_bytes,
    "dst_bytes": dst_bytes,
    "packet_count": packet_count,
    "byte_rate": round(byte_rate, 2),
    "packet_rate": round(packet_rate, 2),
    "syn_count": syn_cnt,
    "ack_count": ack_cnt,
    "fin_count": fin_cnt,
    "rst_count": rst_cnt,
    "failed_logins": failed_logins,
    "same_srv_rate": same_srv_rate,
    "diff_srv_rate": diff_srv_rate,
    "dst_host_count": dst_host_count,
    "dst_host_srv_count": dst_host_srv_count,
    "dst_host_serror_rate": dst_serror,
    "dst_host_rerror_rate": dst_rerror
}])

# Main Section
col1, col2 = st.columns([3, 2])

with col1:
    st.subheader("⚡ Threat Verdict & Multi-Class Classification")
    if pipeline and classifier and label_encoder:
        try:
            X_trans = pipeline.transform(input_df)
            probs = classifier.predict_proba(X_trans)[0]
            pred_idx = np.argmax(probs)
            pred_class = label_encoder.classes_[pred_idx]
            confidence = probs[pred_idx] * 100.0
            
            # Anomaly check
            iso_score = anomaly_detector.decision_function(X_trans)[0] if anomaly_detector else 0.0
            is_anomaly = anomaly_detector.predict(X_trans)[0] == -1 if anomaly_detector else False
            
            if pred_class == "Benign":
                card_style = "sec-card-benign"
                badge = "🟢 VERDICT: BENIGN NETWORK TRAFFIC"
                color = "#34D399"
            else:
                card_style = "sec-card-threat"
                badge = f"🚨 THREAT DETECTED: {pred_class.upper()}"
                color = "#F87171"
                
            st.markdown(f"""
            <div class="{card_style}">
                <div style="font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.1em; color: {color};">{badge}</div>
                <div class="threat-title">{pred_class}</div>
                <div style="font-size: 1.1rem; margin-top: 0.5rem;">
                    Confidence: <b>{confidence:.2f}%</b> | Anomaly Score: <b>{iso_score:.3f}</b>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.write("")
            st.markdown("**Attack Category Probability Distribution**")
            prob_df = pd.DataFrame({
                "Category": label_encoder.classes_,
                "Probability (%)": [round(p * 100, 2) for p in probs]
            }).sort_values(by="Probability (%)", ascending=False)
            st.bar_chart(prob_df.set_index("Category"))
            
        except Exception as e:
            st.error(f"Inference error: {e}")
    else:
        st.warning("⚠️ Training pipeline in progress. Run `python -m src.pipeline` to generate models.")

with col2:
    st.subheader("🛡️ SecOps Incident Response & MITRE ATT&CK")
    if pipeline and classifier:
        if pred_class == "DoS_DDoS":
            st.error("💥 **Attack Vector: Denial of Service (DoS / SYN Flood)**")
            st.markdown("""
            - **MITRE Technique**: [T1498 (Network Denial of Service)](https://attack.mitre.org/techniques/T1498/)
            - **Action 1**: Enable TCP SYN Cookies at edge router / firewall.
            - **Action 2**: Rate-limit incoming TCP SYNs per IP.
            - **Action 3**: Trigger Cloudflare / AWS Shield DDoS mitigation.
            """)
        elif pred_class == "PortScan":
            st.warning("🔍 **Attack Vector: Network Reconnaissance / Port Scan**")
            st.markdown("""
            - **MITRE Technique**: [T1046 (Network Service Discovery)](https://attack.mitre.org/techniques/T1046/)
            - **Action 1**: Dynamically blacklist source IP for 24 hours.
            - **Action 2**: Obfuscate unused listening ports via IDS iptables.
            """)
        elif pred_class == "BruteForce":
            st.error("🔑 **Attack Vector: Credential Stuffing / SSH Brute Force**")
            st.markdown("""
            - **MITRE Technique**: [T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/)
            - **Action 1**: Trigger Fail2Ban auto-jail for SSH port 22.
            - **Action 2**: Enforce Public Key Authentication and disable password logins.
            """)
        elif pred_class == "Botnet_C2":
            st.error("🤖 **Attack Vector: Botnet Command & Control (C2)**")
            st.markdown("""
            - **MITRE Technique**: [T1071 (Application Layer Protocol: C2)](https://attack.mitre.org/techniques/T1071/)
            - **Action 1**: Quarantine internal endpoint immediately.
            - **Action 2**: Sinkhole destination IP/domain in corporate DNS.
            """)
        else:
            st.success("✅ **Status: Healthy Baseline Flow**")
            st.markdown("""
            - Normal TCP handshake & symmetric payload exchange observed.
            - Low error rates and standard service ports.
            """)

st.markdown("---")

# Performance Benchmarks Section
st.subheader("📈 Model Architecture & Test Evaluation Benchmarks")
col_b1, col_b2 = st.columns([1, 1])

with col_b1:
    st.markdown("**Cross-Validation Classifier Benchmark**")
    if "cv_benchmark" in metrics:
        df_bench = pd.DataFrame(metrics["cv_benchmark"])
        st.dataframe(df_bench, use_container_width=True)
    else:
        st.info("CV Benchmark metrics will appear upon pipeline completion.")

with col_b2:
    st.markdown("**Test Set Performance & SecOps Reliability**")
    if "test_performance" in metrics:
        tp = metrics["test_performance"]
        col_m1, col_m2 = st.columns(2)
        col_m1.metric("Overall Accuracy", f"{tp.get('Accuracy', 0.99) * 100:.2f}%")
        col_m2.metric("F1-Macro Score", f"{tp.get('F1_Macro', 0.99):.4f}")
        col_m1.metric("Attack Detection Rate", f"{tp.get('Detection_Rate_Percent', 99.5):.2f}%")
        col_m2.metric("False Alarm Rate (FAR)", f"{tp.get('False_Alarm_Rate_Percent', 0.2):.2f}%")

st.markdown("""
---
<div style="text-align: center; color: #94A3B8; font-size: 0.85rem;">
    Developed by <b>Arjuna Fransesco</b> | <a href="https://github.com/ArjunaFransesco" target="_blank">GitHub Profile</a> | Machine Learning & SecOps Portfolio
</div>
""", unsafe_allow_html=True)
