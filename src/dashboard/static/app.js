/* ==========================================================================
   AEGIS-SRE // MISSION CONTROL DASHBOARD JAVASCRIPT APPLICATION
   Manages WebSockets telemetry, DOM updates, DFIR modal, HITL drawer, & chaos triggers.
   ========================================================================== */

let socket = null;
let currentActiveEscalation = null;

document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
});

function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        appendTerminalLog("SUCCESS", "WEBSOCKET", "Connected to Aegis Mission Control real-time telemetry stream.");
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleServerEvent(data);
        } catch (e) {
            console.error("Error parsing WebSocket message:", e);
        }
    };

    socket.onclose = () => {
        appendTerminalLog("WARN", "WEBSOCKET", "Connection closed. Reconnecting in 3s...");
        setTimeout(initWebSocket, 3000);
    };

    socket.onerror = (err) => {
        console.error("WebSocket error:", err);
    };
}

function handleServerEvent(data) {
    if (data.event === "INITIAL_STATE" || data.event === "TELEMETRY_TICK" || data.event === "ESCALATION_RESOLVED") {
        if (data.pods) renderPodCards(data.pods);
        if (data.quarantines) renderQuarantineList(data.quarantines);
        if (data.escalations) renderEscalationsSummary(data.escalations);
        if (data.metrics_summary) updateBannerScorecards(data.metrics_summary);
        if (data.terminal_logs) {
            data.terminal_logs.forEach(log => appendTerminalLog(log.level, log.category, log.message));
        }
    } else if (data.event === "CHAOS_TRIGGERED") {
        if (data.latest_terminal_log) {
            appendTerminalLog(data.latest_terminal_log.level, data.latest_terminal_log.category, data.latest_terminal_log.message);
        }
    }
}

function updateBannerScorecards(summary) {
    document.getElementById("val-health-score").innerText = `${summary.health_score_pct.toFixed(1)}%`;
    document.getElementById("val-active-pods").innerText = summary.active_pods;
    document.getElementById("val-quarantined-pods").innerText = summary.quarantined_pods;
    document.getElementById("val-escalations-count").innerText = summary.escalated_count;
    
    const subEsc = document.getElementById("sub-escalations");
    if (summary.escalated_count > 0) {
        subEsc.innerText = "⚠️ CLICK POD FOR HITL FIX";
        subEsc.style.color = "var(--neon-alert)";
    } else {
        subEsc.innerText = "No Action Needed";
        subEsc.style.color = "var(--color-text-muted)";
    }
}

function renderPodCards(pods) {
    const container = document.getElementById("pod-cards-list");
    container.innerHTML = "";

    pods.forEach(pod => {
        const card = document.createElement("div");
        card.className = `pod-card ${pod.status.toLowerCase()}`;
        
        let statusBadgeClass = "badge-cyan";
        if (pod.status === "QUARANTINED") statusBadgeClass = "badge-red";
        if (pod.status === "DEGRADED") statusBadgeClass = "badge-purple";

        card.innerHTML = `
            <div class="pod-header">
                <div class="pod-name">${pod.pod_name}</div>
                <span class="badge ${statusBadgeClass}">${pod.status}</span>
            </div>
            <div class="pod-metrics">
                <div class="metric-bar-group">
                    <div class="bar-label"><span>CPU</span> <strong>${pod.cpu_pct}%</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${pod.cpu_pct}%"></div></div>
                </div>
                <div class="metric-bar-group">
                    <div class="bar-label"><span>MEM</span> <strong>${pod.mem_pct}%</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${pod.mem_pct}%"></div></div>
                </div>
                <div class="metric-bar-group">
                    <div class="bar-label"><span>ERR</span> <strong>${pod.error_rate_pct}%</strong></div>
                    <div class="progress-track"><div class="progress-fill" style="width: ${Math.min(100, pod.error_rate_pct * 10)}%; background: var(--neon-alert)"></div></div>
                </div>
            </div>
        `;
        container.appendChild(card);
    });

    document.getElementById("pod-count-badge").innerText = `${pods.length} Pods Active`;
}

function renderQuarantineList(quarantines) {
    const container = document.getElementById("quarantine-list");
    container.innerHTML = "";

    if (!quarantines || quarantines.length === 0) {
        container.innerHTML = `<div class="empty-state">No pods currently isolated under eBPF network quarantine.</div>`;
        document.getElementById("quarantine-count-badge").innerText = "0 Isolated";
        return;
    }

    quarantines.forEach(item => {
        const div = document.createElement("div");
        div.className = "quarantine-item";
        div.innerHTML = `
            <div>
                <strong style="color: var(--neon-alert); font-family: var(--font-mono); font-size: 13px;">${item.pod_name}</strong>
                <div style="font-size: 11px; color: var(--color-text-muted); margin-top: 2px;">
                    eBPF Cage Active • ${item.mitre_technique}
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="action-btn action-restart" onclick="openForensicsModal('${item.pod_name}')">
                    🔍 Inspect DFIR
                </button>
                <button class="action-btn action-unquarantine" onclick="openHITLDrawerForPod('${item.pod_name}')">
                    🛠️ HITL Fix
                </button>
            </div>
        `;
        container.appendChild(div);
    });

    document.getElementById("quarantine-count-badge").innerText = `${quarantines.length} Isolated`;
}

function renderEscalationsSummary(escalations) {
    if (escalations && escalations.length > 0) {
        currentActiveEscalation = escalations[0];
    } else {
        currentActiveEscalation = null;
    }
}

function appendTerminalLog(level, category, message) {
    const windowEl = document.getElementById("terminal-window");
    if (!windowEl) return;

    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `terminal-log-line log-${level.toLowerCase()}`;
    line.innerHTML = `
        <span class="log-time">[${timeStr}]</span>
        <span class="log-cat">[${category}]</span>
        <span class="log-msg">${message}</span>
    `;

    windowEl.appendChild(line);
    windowEl.scrollTop = windowEl.scrollHeight;
}

// Chaos Injection Trigger
async function triggerChaos(chaosType) {
    appendTerminalLog("WARN", "USER", `Triggering chaos injection '${chaosType}' from UI...`);
    try {
        const resp = await fetch("/api/v1/chaos/trigger", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pod_name: "aegis-storefront-prod-1", chaos_type: chaosType })
        });
        const res = await resp.json();
        if (res.decision && !res.decision.approved) {
            // Open HITL drawer if escalation triggered!
            setTimeout(() => {
                openHITLDrawerForPod("aegis-storefront-prod-1", res);
            }, 600);
        }
    } catch (e) {
        console.error("Error triggering chaos:", e);
    }
}

// Forensics Modal Functions
async function openForensicsModal(podName) {
    try {
        const resp = await fetch(`/api/v1/forensics/${podName}`);
        const forensics = await resp.json();

        const bodyEl = document.getElementById("forensics-modal-body");
        bodyEl.innerHTML = `
            <div><strong>Target Pod:</strong> ${forensics.target_pod}</div>
            <div><strong>Trigger Reason:</strong> ${forensics.trigger_reason}</div>
            <div><strong>MITRE Technique:</strong> ${forensics.mitre_technique}</div>
            
            <h4 style="margin-top: 10px;">Process Tree Snapshot:</h4>
            <pre class="code-box">${JSON.stringify(forensics.simulated_process_tree, null, 2)}</pre>
            
            <h4 style="margin-top: 10px;">TCP Socket Connections:</h4>
            <pre class="code-box">${JSON.stringify(forensics.simulated_tcp_sockets, null, 2)}</pre>
        `;

        document.getElementById("forensics-modal").style.display = "flex";
    } catch (e) {
        console.error("Failed to load forensics snapshot:", e);
    }
}

function closeForensicsModal() {
    document.getElementById("forensics-modal").style.display = "none";
}

// Human-in-the-Loop (HITL) Drawer Functions
function openHITLDrawerForPod(podName, chaosResult) {
    document.getElementById("hitl-pod-name").innerText = podName;

    if (chaosResult) {
        document.getElementById("hitl-inc-id").innerText = `Incident ID: ${chaosResult.verdict.incident_id || 'INC-ESCALATE'}`;
        document.getElementById("hitl-problem-type").innerText = chaosResult.verdict.problem_type || 'UNKNOWN';
        document.getElementById("hitl-confidence").innerText = `${chaosResult.decision.confidence || 0.45} (LOW/REJECTED)`;
        document.getElementById("hitl-reason").innerText = chaosResult.decision.reason || 'Escalation triggered.';
    }

    document.getElementById("hitl-drawer-overlay").style.display = "block";
    document.getElementById("hitl-drawer").classList.add("open");
}

function closeHITLDrawer() {
    document.getElementById("hitl-drawer-overlay").style.display = "none";
    document.getElementById("hitl-drawer").classList.remove("open");
}

async function executeHITLAction(actionType) {
    const podName = document.getElementById("hitl-pod-name").innerText;
    const notes = document.getElementById("hitl-custom-notes").value;
    const incId = document.getElementById("hitl-inc-id").innerText.replace("Incident ID: ", "");

    appendTerminalLog("WARN", "HITL", `Human operator dispatching action '${actionType}' for '${podName}'...`);

    try {
        const resp = await fetch("/api/v1/escalation/resolve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                incident_id: incId,
                target_pod: podName,
                action: actionType,
                notes: notes
            })
        });
        const result = await resp.json();
        appendTerminalLog("SUCCESS", "HITL", result.message);
        closeHITLDrawer();
    } catch (e) {
        console.error("Error dispatching HITL resolution:", e);
    }
}
