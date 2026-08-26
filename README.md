# 🛡️ Aegis-SRE: Autonomous Self-Healing Infrastructure

> *An Adaptive Immune System for Cloud-Native Kubernetes Environments*

[![Kubernetes](https://img.shields.io/badge/Kubernetes-K3s-326CE5)](https://k3s.io/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20(Llama%203.2%20%2F%203.1)-green)](https://ollama.com/)
[![Falco](https://img.shields.io/badge/Security-Falco%20%2B%20eBPF-blue)](https://falco.org/)
[![Cilium](https://img.shields.io/badge/Network-Cilium-F8C517)](https://cilium.io/)

---

> 🚀 **Phase 1 Cloud Setup Guide:** Ready to provision the $0/month Oracle Cloud ARM Kubernetes cluster? Follow [`PHASE1_CLOUD_SETUP.md`](file:///c:/dev/aegis-sre/PHASE1_CLOUD_SETUP.md).

## 🧠 What is Aegis-SRE?

**Aegis-SRE** is an autonomous operations platform that acts as an **Adaptive Immune System** for Kubernetes environments. It combines **LLM-driven diagnostics** (Llama 3.2 3B / Llama 3.1 8B via Ollama) and **eBPF-powered security rules** (Falco + Cilium) to automatically distinguish between two fundamentally different types of infrastructure failure:

| Problem Type | Nature | Aegis Response |
|---|---|---|
| 🐛 **Operational Bug** | Memory leak, OOM crash, pod failure | **HEAL** → Rollout Restart / Scale |
| 🔴 **Security Attack** | Reverse shell, credential scrape, T1059 | **DEFEND** → Isolate via Cilium eBPF |

**Key Insight:** Restarting a container under active intrusion does not eliminate the attacker. Aegis isolates security threats while maintaining container state for forensic analysis.

---

## 💻 Implementation & Execution Modes

Aegis-SRE is structured into two distinct execution modes:

1. **Local Reference Software Implementation (Built & Tested in Repository)**:
   - **Local LLM & RAG Engine**: Python-based AI diagnostic brain interfacing with local Ollama (`llama3.2:3b` / `llama3.1:8b`) with automatic model discovery and TF-IDF vector retrieval.
   - **Guardrail Safety Engine**: Rule-based validator enforcing action blocklists (`DELETE_NAMESPACE`), confidence thresholds ($\ge 0.70$), rate limits (max 3 restarts/hr), and audit logging.
   - **Go Controller**: Native Go Kubernetes controller (`controller/main.go`) built with `client-go` executing restarts, scaling, and Cilium NetworkPolicy quarantine YAML generation.
   - **Real-Time Command Dashboard**: FastAPI & WebSockets server (`src/dashboard/server.py`) rendering telemetry, live pod matrix, HITL remediation drawer, and DFIR forensic modal.
   - **Full Test Battery**: 30 automated tests across 6 test suites including the 8-category Cloud-OpsBench chaos suite (`test/test_chaos_benchmark.py`).

2. **Target Cloud Deployment Architecture**:
   - Manifests and step-by-step guides ([`PHASE1_CLOUD_SETUP.md`](file:///c:/dev/aegis-sre/PHASE1_CLOUD_SETUP.md)) for deploying K3s on Oracle Cloud ARM A1 (Always Free) connected to an Azure B1s monitoring host.

---

## 🏗️ Architecture Mental Model

Think of cloud infrastructure monitoring like a **facility management system**:

- 🌡️ **Prometheus** = Telemetry sensors measuring CPU/RAM saturation.
- 📷 **Falco** = Kernel security sensors detecting unauthorized process execution.
- 🧠 **Ollama LLM** = Diagnostic brain reading runbooks to classify incidents.
- 📋 **Guardrails** = Safety controller vetoing destructive or un-confident actions.
- 🤖 **Go Controller** = Execution engine applying Kubernetes state changes.
- 🔒 **Cilium** = eBPF network isolation cage blocking threat ingress/egress.
- 📱 **Dashboard** = WebSockets command interface for human oversight and control.

---

## 🔄 The Two Remediation Paths

### Path A — The Operational Bug Path
```text
Alert: "OOMKilled on pod checkout-service"
  → Ollama LLM: "Memory leak detected, no threat indicators"
  → Action: {"action": "RESTART_POD", "target": "checkout-service"}
  → Guardrails: ✅ APPROVED (Passed confidence & rate limits)
  → Go Controller: Executes rollout restart & verifies post-health state
```

### Path B — The Security Threat Path
```text
Alert: "Falco: Shell spawned in container (T1059)"
  → Ollama LLM: "Active intrusion detected"
  → Action: {"action": "CILIUM_QUARANTINE_EBPF", "target": "pod-xyz", "reason": "T1059"}
  → Guardrails: ✅ APPROVED (Forces isolation over restart)
  → Go Controller: Applies Cilium NetworkPolicy → DROP all traffic
  → Result: Attacker isolated in eBPF cage; pod preserved for DFIR forensics
```

---

## 📊 Verification & Test Battery (30 / 30 Tests Passed)

Aegis-SRE is benchmarked against the 8 real-world microservice failure categories defined in ***Cloud-OpsBench: A Reproducible Benchmark for Agentic RCA*** (`arXiv:2603.00468`):

```text
Ran 6 tests in test_guardrails.py      -> OK
Ran 5 tests in test_controller.py      -> OK
Ran 2 tests in test_pipeline.py        -> OK
Ran 4 tests in test_edge_cases.py      -> OK
Ran 8 tests in test_chaos_benchmark.py -> OK
Ran 5 tests in test_dashboard.py       -> OK

TOTAL: 30 / 30 Tests PASSED (100% Success Rate)
```

Run full test suite:
```powershell
$env:PYTHONPATH="."; python test/test_chaos_benchmark.py
```

Run Real-Time Command Dashboard:
```powershell
$env:PYTHONPATH="."; python -m src.dashboard.server
```

Or Run via Docker (Zero Dependencies):
```bash
docker compose -f deploy/docker-compose.yml up -d --build
```
Open browser to: `http://localhost:8000`

- Benchmark JSON report: [`logs/cloud_opsbench_report.json`](file:///c:/dev/aegis-sre/logs/cloud_opsbench_report.json)
- Executive Markdown report: [`logs/EXECUTIVE_BENCHMARK_REPORT.md`](file:///c:/dev/aegis-sre/logs/EXECUTIVE_BENCHMARK_REPORT.md)
- Escalations Log: [`logs/escalations.jsonl`](file:///c:/dev/aegis-sre/logs/escalations.jsonl)

---

## 🏛️ Target Cloud Architecture Overview

```text
┌─────────────────────────────────────────────────────┐
│          ORACLE ARM A1 — Always Free                │
│          4 OCPU | 24 GB RAM | K3s Cluster           │
│                                                     │
│  Microservices + Chaos Injection Pods               │
│          ↓                                          │
│  Prometheus + Falco eBPF + Loki (Sensing Layer)     │
│          ↓                                          │
│  Ollama (Llama 3.2 3B / 3.1 8B) + RAG DB (Brain)    │
│          ↓                                          │
│  Guardrail Engine → Go K8s Controller (Muscle)      │
│          ↓                                          │
│  Cilium NetworkPolicy (eBPF Isolation Cage)         │
└───────────────────────┬─────────────────────────────┘
                        │ Tailscale VPN
                        ↓
┌─────────────────────────────────────────────────────┐
│          AZURE B1s — Free Tier                      │
│     FastAPI + WebSockets Dashboard                  │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ Core Tech Stack

| Layer | Technology | Implementation Role |
|---|---|---|
| Cluster | K3s / Docker Compose | Container orchestration & target workloads |
| Metrics | Prometheus + AlertManager | Metric collection & threshold alerts |
| Security | Falco + eBPF | Kernel syscall security event detection |
| Logs | Loki + Promtail | Centralized log aggregation |
| AI Brain | Ollama (Llama 3.2 3B / 3.1 8B) | Local LLM diagnostic inference |
| Memory | Vector Search RAG | SRE runbooks + MITRE ATT&CK TTP lookup |
| Guardrails | Python Safety Engine | Blocklists, confidence gates, rate limits |
| Controller | Go + client-go | Kubernetes reconcile loop & action execution |
| Isolation | Cilium NetworkPolicy | eBPF pod network quarantine |
| Dashboard | FastAPI + WebSockets | Real-time command dashboard & HITL drawer |

---

## 🔐 Security: MITRE ATT&CK Mapping

| Falco Alert | MITRE TTP | Aegis Response |
|---|---|---|
| Shell spawned in container | T1059 — Command Execution | CILIUM_QUARANTINE_EBPF |
| Sensitive file read (/etc/shadow) | T1552 — Credential Access | CILIUM_QUARANTINE_EBPF |
| Network tool launched | T1046 — Network Discovery | CILIUM_QUARANTINE_EBPF |
| Memory spike + OOM Kill | (Operational) | RESTART_POD |
| CPU throttling loop | (Operational) | SCALE_DEPLOYMENT |

---

## 📊 The Verification Loop

The system verifies every action it takes:

```
Action Taken → Re-check Sensors → Still broken? → Escalate to Human
                               → Healthy?      → Log success ✅
```

**Formula:**  
`Success = Verify(Action(LLM_Output)) ∈ {Healthy_Metrics, No_Security_Alerts}`

---

## 💰 Zero-Cost Infrastructure

| Resource | Platform | Tier | Cost |
|---|---|---|---|
| K3s Cluster | Oracle Cloud ARM A1 | Always Free | $0/mo |
| Dashboard | Azure B1s VM | Free 750 hrs/mo | $0/mo |
| **Total** | | | **$0/mo** |

---

## 🌐 Real-World Production & Public Web Deployment Roadmap

While local container testing verifies the core sensory and controller logic, **Aegis-SRE is engineered for real-world production Kubernetes deployments**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PUBLIC INTERNET ACCESS                          │
│        (Real External Web Users & Red-Team Attack Simulators)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS (TLS)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  INGRESS GATEWAY (Traefik / NGINX)                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Internal K8s Routing
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               ONLINE BOUTIQUE E-COMMERCE MICROSERVICES                 │
│      (Frontend, Checkout, Payment, Cart, Currency, Ads Pods)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Real-time Telemetry
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│           AEGIS-SRE AUTONOMOUS IMMUNE SYSTEM (ORACLE ARM / CLOUD)      │
│     Prometheus + Falco eBPF ➔ Ollama Llama 3.1 ➔ Go Cilium Controller  │
└────────────────────────────────────────────────────────────────────────┘
```

### 🚀 Production Deployment Extensions

1. **Targeting Real E-Commerce Web Apps:**  
   Transitioning from synthetic test endpoints to deploying **Google Cloud's Online Boutique** — a 10-microservice polyglot e-commerce web application running live on K3s.
2. **Public Ingress & TLS Domain Exposure:**  
   Routing external traffic through a public NGINX/Traefik Ingress controller with automated SSL certificates, exposing the store front to public internet traffic.
3. **Live Public Red-Teaming & Threat Injection:**  
   Executing live penetration attacks against the publicly accessible web endpoints (SQLi, reverse shell payload delivery, memory exhaustion) to evaluate Aegis-SRE's real-time eBPF containment speed in a live cloud environment.
4. **Multi-Cluster & Hybrid Cloud Extension:**  
   Extending the Go K8s controller to manage cross-cluster workloads spanning multiple cloud providers (Oracle Cloud ARM A1 ↔ Azure ↔ On-Premises).

---

## 👥 Team Division

| Domain | Krishna | Teammate |
|---|---|---|
| Phase 1–2 | Falco eBPF Rules, Cilium Policies | K3s Setup, Prometheus/Loki |
| Phase 3–4 | MITRE TTP Mapping, Guardrail Logic | Ollama/RAG, Function Calling |
| Phase 5–6 | Security Forensics, Isolation Logic | Go Controller, Reconcile Loop |
| Final | Technical Write-up (Security) | React Dashboard, API |

---

*Aegis-SRE — Because your infrastructure deserves an immune system, not just a pager.*
