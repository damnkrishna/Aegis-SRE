import time
import random
import logging
import json
import subprocess
import os
from fastapi import FastAPI, Response, status, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# --- Structured JSON Logger Setup ---
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "pod_name": os.getenv("HOSTNAME", "aegis-target-app-production")
        }
        if hasattr(record, "event"):
            log_obj["event"] = record.event
        if hasattr(record, "extra_data"):
            log_obj["extra"] = record.extra_data
        return json.dumps(log_obj)

logger = logging.getLogger("aegis-production-app")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# --- FastAPI App & Templates ---
app = FastAPI(title="Aegis Cloud Store", version="1.0.0")

app.mount("/static", StaticFiles(directory="src/target_app/static"), name="static")
templates = Jinja2Templates(directory="src/target_app/templates")

# --- Prometheus Metrics Definitions ---
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP Requests",
    ["method", "endpoint", "status"]
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP Request Latency in Seconds",
    ["endpoint"]
)

ACTIVE_REQUESTS = Gauge(
    "active_requests",
    "Number of active concurrent requests"
)

# --- Metric & Logging Middleware ---
@app.middleware("http")
async def track_metrics_and_logs(request: Request, call_next):
    ACTIVE_REQUESTS.inc()
    start_time = time.time()
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
    except Exception as e:
        status_code = "500"
        logger.error(
            f"Unhandled server exception on {request.url.path}: {str(e)}",
            extra={"event": "unhandled_exception", "extra_data": {"path": request.url.path}}
        )
        raise e
    finally:
        duration = time.time() - start_time
        ACTIVE_REQUESTS.dec()

    endpoint = request.url.path
    if endpoint.startswith("/api/"):
        metric_endpoint = endpoint
    else:
        metric_endpoint = "frontend"

    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        endpoint=metric_endpoint,
        status=status_code
    ).inc()

    HTTP_REQUEST_DURATION_SECONDS.labels(
        endpoint=metric_endpoint
    ).observe(duration)

    logger.info(
        f"Handled {request.method} {request.url.path} with status {status_code} in {duration:.4f}s",
        extra={
            "event": "http_request",
            "extra_data": {
                "method": request.method,
                "path": request.url.path,
                "status": status_code,
                "latency_sec": round(duration, 4)
            }
        }
    )
    return response

# --- Storefront UI Endpoint ---
@app.get("/")
async def render_storefront(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# --- Health & Metrics Endpoints ---
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "aegis-target-app", "version": "1.0.0"}

@app.get("/metrics")
async def get_prometheus_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# --- Storefront REST Business Endpoints ---
@app.get("/api/v1/order/compute")
async def order_compute():
    time.sleep(random.uniform(0.05, 0.15))
    return {"order_id": f"ORD-{random.randint(1000, 9999)}", "item": "ARM64 Compute Node", "status": "CONFIRMED"}

@app.get("/api/v1/order/security-key")
async def order_security_key():
    time.sleep(random.uniform(0.05, 0.12))
    return {"order_id": f"ORD-{random.randint(1000, 9999)}", "item": "eBPF Security Key", "status": "CONFIRMED"}

@app.get("/api/v1/inventory/telemetry")
async def check_inventory():
    return {"item": "Telemetry Pipeline", "available_stock": 42, "status": "IN_STOCK"}

@app.get("/api/v1/good")
async def api_good():
    return {"status": "success", "message": "API endpoint responding normally 200 OK"}

@app.get("/api/v1/slow")
async def api_slow():
    delay = random.uniform(1.5, 2.5)
    time.sleep(delay)
    return {"status": "slow", "delay_seconds": round(delay, 2)}

@app.get("/api/v1/error")
async def api_error(response: Response):
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    logger.error("Database connection failure triggered on /api/v1/error", extra={"event": "database_error"})
    return {"status": "error", "message": "HTTP 500 Internal Server Error"}

# --- Chaos & Security Simulation Endpoints ---
@app.get("/api/v1/chaos/shell")
async def chaos_shell():
    """Simulates MITRE ATT&CK T1059: Spawns process shell to trigger Falco eBPF probe."""
    logger.warning("Simulating T1059 Command Execution", extra={"event": "security_simulation"})
    try:
        res = subprocess.run(["sh", "-c", "whoami && uname -a"], capture_output=True, text=True, timeout=2)
        cmd_out = res.stdout.strip()
    except Exception:
        cmd_out = "Shell process spawned (simulated)"

    return {
        "status": "ATTACK_SIMULATED",
        "technique": "MITRE T1059 - Command and Scripting Interpreter",
        "falco_alert": "Shell Spawned in Container",
        "output": cmd_out
    }

@app.get("/api/v1/chaos/oom")
async def chaos_oom():
    """Simulates memory pressure anomaly."""
    logger.warning("Simulating memory allocation spike", extra={"event": "oom_simulation"})
    # Allocate temporary memory buffer
    data = [0] * (5 * 1024 * 1024)  # ~40MB
    return {"status": "OOM_SIMULATED", "allocated_elements": len(data)}
