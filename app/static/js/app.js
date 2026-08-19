document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('nids-form');
    const btnInspect = document.getElementById('btn-inspect');
    const spinner = document.getElementById('form-spinner');
    const btnText = btnInspect.querySelector('.btn-text');

    // UI Result Elements
    const severityVal = document.getElementById('severity-val');
    const severityTier = document.getElementById('severity-tier');
    const severityCircle = document.querySelector('.severity-circle');
    const badgeAction = document.getElementById('badge-action');
    const threatCategory = document.getElementById('threat-category');
    const meterSeverityFill = document.getElementById('meter-severity-fill');
    const anomalyScore = document.getElementById('anomaly-score');
    const probList = document.getElementById('prob-list');
    const indicatorList = document.getElementById('indicator-list');

    // Simulation Buttons
    document.querySelectorAll('.btn-sim').forEach(btn => {
        btn.addEventListener('click', async () => {
            const attackType = btn.getAttribute('data-type');
            try {
                const res = await fetch(`/api/simulate?type=${attackType}`);
                const data = await res.json();
                if (data.flow) {
                    for (const [key, value] of Object.entries(data.flow)) {
                        const el = document.getElementById(key);
                        if (el) el.value = value;
                    }
                    triggerInspection();
                }
            } catch (e) {
                console.error("Simulation fetch error:", e);
            }
        });
    });

    async function triggerInspection() {
        btnInspect.disabled = true;
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Inspecting Packet Flow Telemetry...';

        const flowPayload = {
            protocol_type: document.getElementById('protocol_type').value,
            service: document.getElementById('service').value,
            flow_duration_ms: parseFloat(document.getElementById('flow_duration_ms').value),
            packet_count: parseFloat(document.getElementById('packet_count').value),
            src_bytes: parseFloat(document.getElementById('src_bytes').value),
            dst_bytes: parseFloat(document.getElementById('dst_bytes').value),
            packet_rate: parseFloat(document.getElementById('packet_rate').value),
            byte_rate: parseFloat(document.getElementById('byte_rate').value),
            syn_count: parseFloat(document.getElementById('syn_count').value),
            ack_count: parseFloat(document.getElementById('ack_count').value),
            fin_count: parseFloat(document.getElementById('fin_count').value),
            rst_count: parseFloat(document.getElementById('rst_count').value),
            failed_logins: parseInt(document.getElementById('failed_logins').value),
            same_srv_rate: parseFloat(document.getElementById('same_srv_rate').value),
            diff_srv_rate: parseFloat(document.getElementById('diff_srv_rate').value),
            dst_host_count: parseInt(document.getElementById('dst_host_count').value),
            dst_host_srv_count: parseInt(document.getElementById('dst_host_srv_count').value),
            dst_host_serror_rate: parseFloat(document.getElementById('dst_host_serror_rate').value),
            dst_host_rerror_rate: parseFloat(document.getElementById('dst_host_rerror_rate').value)
        };

        try {
            const response = await fetch('/api/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(flowPayload)
            });

            const res = await response.json();
            if (res.status === 'success') {
                const data = res.data;

                // Animate severity score
                const currentVal = parseFloat(severityVal.textContent) || 0;
                animateValue(severityVal, currentVal, Math.round(data.severity_score), 500);

                severityTier.textContent = data.threat_level;
                severityTier.style.color = data.color_code;
                severityCircle.style.borderColor = data.color_code;
                severityCircle.style.boxShadow = `0 0 25px ${data.color_code}40`;

                // Action Badge
                badgeAction.textContent = data.firewall_action.replace(/_/g, ' ');
                badgeAction.style.background = `${data.color_code}20`;
                badgeAction.style.color = data.color_code;
                badgeAction.style.border = `1px solid ${data.color_code}60`;

                // Detected category & meters
                threatCategory.textContent = `${data.threat_category} (${(data.confidence * 100).toFixed(1)}% Conf)`;
                threatCategory.style.color = data.color_code;
                meterSeverityFill.style.width = `${Math.min(data.severity_score, 100)}%`;
                meterSeverityFill.style.background = data.color_code;

                // Anomaly Score
                const anomalyLabel = data.is_zero_day_anomaly ? '⚠️ ZERO-DAY ANOMALY' : 'NORMAL PATTERN';
                anomalyScore.textContent = `${data.anomaly_score > 0 ? '+' : ''}${data.anomaly_score.toFixed(3)} (${anomalyLabel})`;
                anomalyScore.style.color = data.is_zero_day_anomaly ? '#f59e0b' : '#10b981';

                // Probability breakdown
                probList.innerHTML = '';
                if (data.probability_breakdown) {
                    for (const [clsName, prob] of Object.entries(data.probability_breakdown)) {
                        const pct = (prob * 100).toFixed(1);
                        const item = document.createElement('div');
                        item.className = 'prob-item';
                        item.innerHTML = `
                            <span class="prob-label">${clsName}</span>
                            <div class="prob-bar">
                                <div class="prob-fill" style="width: ${pct}%; background: ${clsName === data.threat_category ? data.color_code : '#334155'};"></div>
                            </div>
                            <span class="prob-pct">${pct}%</span>
                        `;
                        probList.appendChild(item);
                    }
                }

                // Threat Indicators
                indicatorList.innerHTML = '';
                if (data.indicators && data.indicators.length > 0) {
                    data.indicators.forEach(ind => {
                        const li = document.createElement('li');
                        li.textContent = `[IoC ALERT] ${ind}`;
                        indicatorList.appendChild(li);
                    });
                } else {
                    const li = document.createElement('li');
                    li.className = 'indicator-placeholder';
                    li.textContent = 'Clean baseline traffic. No active indicators of compromise (IoC).';
                    indicatorList.appendChild(li);
                }
            }
        } catch (err) {
            console.error('NIDS API Error:', err);
            alert('Failed to inspect network packet flow.');
        } finally {
            btnInspect.disabled = false;
            spinner.style.display = 'none';
            btnText.textContent = 'Inspect Network Flow & Classify Threat';
        }
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const current = Math.floor(progress * (end - start) + start);
            obj.innerHTML = current;
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                obj.innerHTML = end;
            }
        };
        window.requestAnimationFrame(step);
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        triggerInspection();
    });

    // Run initial inspection
    triggerInspection();
});
