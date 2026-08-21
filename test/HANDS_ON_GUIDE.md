# 🧪 Aegis-SRE: Full Practice Lab & Verification Guide (Stage 0.1 → 2.3)

Welcome to the complete, isolated **Aegis Practice Lab**! Everything in this guide is executed inside `c:\dev\aegis-sre\test\`.

---

## 🎯 Big Picture: Why Are We Doing This?

Before writing AI logic or Go controllers, we must build and verify the **Sensory System** (Metrics + Logs + eBPF Security Tracing).

| Telemetry Layer | Technology | What it Detects | What Aegis Learns |
|---|---|---|---|
| 📊 **Metrics** | Prometheus | CPU/Memory spikes, 500 error rates, latency | *"Is a service failing or leaking memory?"* |
| 📜 **Logs** | Loki + Promtail | Application stack traces, structured JSON events | *"What was the root cause message?"* |
| 🛡️ **Syscall Tracing** | Falco + eBPF | Process execution, file access, network scans | *"Did an attacker spawn a shell or steal keys?"* |
| 🖥️ **Visualization** | Grafana | Combined dashboard overlay | *"Single pane of glass for human SRE review."* |

---

## 🚀 Quick Start: Launching the Lab Environment

Run the following commands in PowerShell / Terminal:

```bash
# 1. Navigate to the test directory
cd c:\dev\aegis-sre\test

# 2. Build and launch all 6 core services in detached mode
docker compose up --build -d

# 3. Verify all containers are running
docker compose ps
```

You will see 6 active containers:
* 🟢 `aegis-sample-app` — http://localhost:8000
* 🟡 `aegis-prometheus` — http://localhost:9090
* 🔴 `aegis-loki` — http://localhost:3100
* 🔵 `aegis-promtail` — (Background Log Shipper)
* 🦅 `aegis-falco` — (Background eBPF Security Watcher)
* 📊 `aegis-grafana` — http://localhost:3000 (User: `admin`, Pass: `admin`)

---

## 🟢 LAB 1: Stage 0.1 — Linux & Process Basics

### What We Are Testing:
Containers are just Linux processes with namespaces and cgroups. We verify how PID 1 handles signals and how `/proc` exposes kernel stats.

### Commands:
```bash
# 1. Exec into the container
docker exec -it aegis-sample-app sh

# 2. Inspect running processes (Observe Python running as PID 1)
ps aux

# 3. Inspect CPU & Memory info exposed by Linux kernel
cat /proc/cpuinfo
cat /proc/meminfo

# 4. Exit container
exit
```

---

## 🔵 LAB 2: Stage 0.2 — Networking & Endpoints

### What We Are Testing:
HTTP status codes (200 OK vs 500 Error vs high latency) and container-to-container DNS resolution.

### Commands:
```bash
# 1. Test normal 200 OK endpoint
curl -i http://localhost:8000/api/good

# 2. Test 500 Internal Server Error endpoint
curl -i http://localhost:8000/api/error

# 3. Test slow endpoint
curl -i http://localhost:8000/api/slow

# 4. Verify container DNS (Prometheus resolving sample-app)
docker exec -it aegis-prometheus ping -c 2 sample-app
```

---

## 🔴 LAB 3: Stage 2.1 — Prometheus & PromQL (Metrics)

### What We Are Testing:
Prometheus scraping metric counters, gauges, and histograms.

### Step 3.1: Generate traffic load
Run this loop in PowerShell:
```powershell
1..20 | ForEach-Object { Invoke-RestMethod -Uri "http://localhost:8000/api/good" }
1..5  | ForEach-Object { Invoke-RestMethod -Uri "http://localhost:8000/api/error" -ErrorAction SilentlyContinue }
1..3  | ForEach-Object { Invoke-RestMethod -Uri "http://localhost:8000/api/slow" }
```

### Step 3.2: Query metrics in Prometheus UI (`http://localhost:9090`)
* **Total Request Count:** `http_requests_total`
* **Error Rate (500 errors):** `http_requests_total{status="500"}`
* **Request Rate per second:** `rate(http_requests_total[1m])`

---

## 📜 LAB 4: Stage 2.2 — Loki & LogQL (Structured Logging)

### What We Are Testing:
Promtail shipping container JSON logs to Loki, enabling fast LogQL log searching.

### Step 4.1: Query Loki Logs in Grafana (`http://localhost:3000`)
1. Open **http://localhost:3000** in your browser. Login with `admin` / `admin`.
2. Go to **Explore** (compass icon on left menu).
3. Select **Loki** as the datasource.
4. Run LogQL query:
   ```logql
   {container="aegis-sample-app"}
   ```
5. Filter by error logs:
   ```logql
   {container="aegis-sample-app"} |= "error"
   ```

---

## 🦅 LAB 5: Stage 2.3 — Falco & eBPF Security Tracing

### What We Are Testing:
Kernel syscall monitoring. We trigger simulated security attacks on the container and verify that Falco detects them in real time and tags them with MITRE ATT&CK TTPs.

### Step 5.1: Simulate Security Attacks via API
Run the following attack endpoints:

```bash
# 1. Trigger Shell Spawn Attack (MITRE T1059)
curl http://localhost:8000/api/attack/shell

# 2. Trigger Sensitive File Access Attack (MITRE T1552)
curl http://localhost:8000/api/attack/sensitive-file

# 3. Trigger Memory Leak Anomaly
curl http://localhost:8000/api/attack/memory-leak
```

### Step 5.2: Inspect Live Falco Security Alerts
Check Falco logs to see the detected syscall anomalies:

```bash
docker logs aegis-falco --tail 50
```

**What you will see in output:**
```json
{
  "priority": "Warning",
  "rule": "Aegis Shell Spawned in Container",
  "output": "Aegis Security Alert: Shell spawned in container (user=root container=aegis-sample-app cmd=sh -c whoami && id mitre_ttp=T1059)",
  "output_fields": {
    "container.name": "aegis-sample-app",
    "proc.cmdline": "sh -c whoami && id",
    "user.name": "root"
  }
}
```

---

## 📊 LAB 6: Unified Grafana Command Center

### What We Are Testing:
Observing metrics, logs, and security events in a single dashboard view.

1. Open **http://localhost:3000/explore**.
2. Split view: Left window = **Prometheus** (Query: `rate(http_requests_total[1m])`), Right window = **Loki** (Query: `{container="aegis-sample-app"}`).
3. Now you have full visibility into the cluster's health and security status!

---

## 🎓 Connecting the Dots to Aegis-SRE Phase 3+

Once these 3 streams (Prometheus, Loki, Falco) are working:

```
                  ┌──────────────────────┐
                  │   Prometheus Alert   │
                  │ (CPU 99% / Error 500)│
                  └──────────┬───────────┘
                             │
                             ▼
┌──────────────────┐   ┌───────────┐   ┌───────────────────┐
│   Falco Alert    │──>│  AEGIS    │<──│    Loki Logs      │
│ (MITRE T1059/T1552)│  │ LLM BRAIN │   │(Stack trace/JSON) │
└──────────────────┘   └─────┬─────┘   └───────────────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │ Ollama Llama 3.1 Decision │
               │  - BUG -> Restart Pod     │
               │  - ATTACK -> Quarantine   │
               └───────────────────────────┘
```

When an alert fires, Aegis compiles the **Prometheus metric + Loki log snippet + Falco security event** into the LLM prompt. The LLM then immediately knows whether it is dealing with an operational bug or an active intrusion!
