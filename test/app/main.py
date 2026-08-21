import time
import random
import logging
import json
import subprocess
import os
from fastapi import FastAPI, Response, status, Request
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# --- Structured JSON Logger Setup ---
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        }
        if hasattr(record, "event"):
            log_obj["event"] = record.event
        if hasattr(record, "extra_data"):
            log_obj["extra"] = record.extra_data
        return json.dumps(log_obj)

logger = logging.getLogger("aegis-app")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

app = FastAPI(title="Aegis Hands-on Test Microservice")

# --- Prometheus Metrics Definitions ---
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total count of HTTP requests received",
    ["method", "endpoint", "status"]
)

ACTIVE_REQUESTS = Gauge(
    "active_requests",
    "Number of currently active in-flight requests"
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["endpoint"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

LEAK_MEMORY_STORE = []

# --- Middleware ---
@app.middleware("http")
async def track_metrics(request: Request, call_next):
    ACTIVE_REQUESTS.inc()
    start_time = time.time()
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
    except Exception as e:
        status_code = "500"
        logger.error(f"Unhandled exception during request: {str(e)}", extra={"event": "unhandled_exception"})
        raise
    finally:
        duration = time.time() - start_time
        ACTIVE_REQUESTS.dec()
    
    endpoint = request.url.path
    if endpoint.startswith("/api/"):
        metric_endpoint = endpoint
    else:
        metric_endpoint = "other"
        
    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        endpoint=metric_endpoint,
        status=status_code
    ).inc()
    
    HTTP_REQUEST_DURATION_SECONDS.labels(
        endpoint=metric_endpoint
    ).observe(duration)
    
    return response


@app.get("/")
def read_root():
    logger.info("Root endpoint accessed", extra={"event": "root_access"})
    return {"message": "Aegis Test Microservice is running!", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/good")
def simulated_good_endpoint():
    """Simulates a fast, successful 200 OK API call."""
    time.sleep(random.uniform(0.01, 0.05))
    logger.info("Payment transaction processed successfully", extra={"event": "payment_success"})
    return {"status": "success", "data": "Payment processed successfully"}


@app.get("/api/error")
def simulated_error_endpoint(response: Response):
    """Simulates a 500 Internal Server Error."""
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    logger.error("Database connection pool exhausted", extra={"event": "db_pool_exhausted"})
    return {"status": "error", "message": "Database connection pool exhausted"}


@app.get("/api/slow")
def simulated_slow_endpoint():
    """Simulates a slow 200 OK endpoint (high latency)."""
    delay = random.uniform(0.8, 2.0)
    time.sleep(delay)
    logger.warning(f"High response latency detected: {round(delay, 2)}s", extra={"event": "high_latency"})
    return {"status": "success", "delay_seconds": round(delay, 2)}


# --- Security & Operational Chaos Simulation Endpoints ---

@app.get("/api/attack/shell")
def trigger_shell_spawn():
    """
    Triggers Falco Rule: Aegis Shell Spawned in Container (MITRE T1059).
    Executes a subshell process via execve.
    """
    logger.warning("Simulating attack: Spawning shell process inside container...", extra={"event": "attack_shell_spawn"})
    try:
        res = subprocess.run(["sh", "-c", "whoami && id"], capture_output=True, text=True)
        out = res.stdout.strip()
    except Exception as e:
        out = str(e)
    return {
        "status": "attack_simulated",
        "mitre_ttp": "T1059 (Command & Scripting Interpreter)",
        "output": out
    }


@app.get("/api/attack/sensitive-file")
def trigger_sensitive_file_read():
    """
    Triggers Falco Rule: Aegis Sensitive File Read (MITRE T1552).
    Attempts to open /etc/passwd or /etc/shadow.
    """
    logger.error("Simulating attack: Attempting access to sensitive file /etc/passwd", extra={"event": "attack_sensitive_file"})
    content = ""
    try:
        with open("/etc/passwd", "r") as f:
            content = f.readline().strip()
    except Exception as e:
        content = f"Failed reading: {str(e)}"
        
    return {
        "status": "attack_simulated",
        "mitre_ttp": "T1552 (Unsecured Credentials)",
        "first_line": content
    }


@app.get("/api/attack/memory-leak")
def trigger_memory_leak():
    """
    Simulates operational anomaly: Memory leak leading to potential OOM kill.
    """
    # Allocate ~10 MB chunk of bytes
    chunk = b"A" * (10 * 1024 * 1024)
    LEAK_MEMORY_STORE.append(chunk)
    total_allocated_mb = len(LEAK_MEMORY_STORE) * 10
    logger.warning(f"Simulating memory leak: Total allocated {total_allocated_mb} MB", extra={"event": "memory_leak_step"})
    return {
        "status": "memory_leaked",
        "allocated_mb": total_allocated_mb,
        "chunks_count": len(LEAK_MEMORY_STORE)
    }


@app.get("/metrics")
def metrics():
    """Exposes Prometheus formatted metrics for scraping."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
