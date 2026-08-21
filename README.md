# 🛡️ Aegis-SRE: Autonomous Self-Healing Infrastructure

> *"An Adaptive Immune System for Cloud-Native Environments"*

[![K3s](https://img.shields.io/badge/Kubernetes-K3s-326CE5)](https://k3s.io/)
[![Ollama](https://img.shields.io/badge/LLM-Llama%203.1%208B-green)](https://ollama.com/)
[![Falco](https://img.shields.io/badge/Security-Falco%20%2B%20eBPF-blue)](https://falco.org/)
[![Cilium](https://img.shields.io/badge/Network-Cilium-F8C517)](https://cilium.io/)

---

> 🚀 **Phase 1 Cloud Setup Guide:** Ready to provision the $0/month Oracle Cloud ARM Kubernetes cluster? Follow [`PHASE1_CLOUD_SETUP.md`](file:///c:/dev/aegis-sre/PHASE1_CLOUD_SETUP.md).

## 🧠 What is Aegis-SRE?

**Aegis-SRE** is an autonomous operations platform that acts as an **Adaptive Immune System** for Kubernetes environments. It uses **LLM-driven diagnostics** (Llama 3.1 via Ollama) and **eBPF-powered security** (Falco + Cilium) to automatically distinguish between two fundamentally different types of infrastructure failure:

| Problem Type | Nature | Aegis Response |
|---|---|---|
| 🐛 **Operational Bug** | Memory leak, OOM crash, pod failure | **HEAL** → Restart / Scale |
| 🔴 **Security Attack** | Reverse shell, credential scrape, T1059 | **DEFEND** → Isolate via Cilium |

The core insight: **fixing a hacker with a restart is useless**. Aegis knows the difference.

---

## 🏗️ The "Smart Building" Mental Model

Think of your cloud infrastructure as a **high-rise apartment building**:

- 🌡️ **Prometheus** = Thermometer in every room (detects CPU/RAM heat)
- 📷 **Falco** = Security camera watching for lock-pickers (syscall monitoring)
- 🧠 **Llama 3.1** = Smart Consultant who has read every fire-safety book
- 📋 **Guardrails** = Grumpy manager who vetoes "burn the building down"
- 🤖 **Go Controller** = Robot hand that physically locks the door
- 🔒 **Cilium** = Invisible cage — tenant can't call out or move around
- 📱 **Dashboard** = Boss's phone notification while they sip coffee

---

## 🔄 The Two Healing Paths

### Path A — The SRE Path (Bug / Common Cold)
```
Alert: "OOM Kill on pod checkout-service"
  → LLM: "Memory leak detected, not a threat"
  → Action: {"action": "RESTART", "target": "checkout-service"}
  → Guardrails: ✅ APPROVED
  → Go Controller executes kubectl rollout restart
  → Result: Pod healthy in ~30 seconds
```

### Path B — The Security Path (Attack / Virus)
```
Alert: "Falco: Shell spawned in container (T1059)"
  → LLM: "Active intrusion detected"
  → Action: {"action": "QUARANTINE", "target": "pod-xyz", "reason": "T1059"}
  → Guardrails: ✅ APPROVED
  → Go Controller applies Cilium NetworkPolicy → DROP all traffic
  → Result: Attacker trapped in eBPF cage for forensics
```

---

## 🏛️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│          ORACLE ARM A1 — Always Free                │
│          4 OCPU | 24 GB RAM | K3s Cluster           │
│                                                     │
│  Microservices + Chaos Injection Pods               │
│          ↓                                          │
│  Prometheus + Falco eBPF + Loki (Sensing Layer)     │
│          ↓                                          │
│  Ollama Llama 3.1 8B + RAG Vector DB (Brain)        │
│          ↓                                          │
│  Guardrail Engine → Go K8s Controller (Muscle)      │
│          ↓                                          │
│  Cilium NetworkPolicy (eBPF Isolation Cage)         │
└───────────────────────┬─────────────────────────────┘
                        │ Tailscale VPN
                        ↓
┌─────────────────────────────────────────────────────┐
│          AZURE B1s — Free Tier                      │
│     FastAPI + React + WebSockets Dashboard          │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ Core Tech Stack

| Layer | Technology | Role |
|---|---|---|
| Cluster | K3s on Oracle ARM A1 | Lightweight Kubernetes |
| Metrics | Prometheus + AlertManager | CPU/RAM/Error tracking |
| Security | Falco + eBPF | Kernel syscall monitoring |
| Logs | Loki + Promtail | Structured log aggregation |
| AI Brain | Ollama + Llama 3.1 8B Q4 | LLM inference on-device |
| Memory | Vector DB (RAG) | SRE runbooks + MITRE ATT&CK TTPs |
| Guardrails | Go/Python rule engine | LLM output validation |
| Controller | Go + client-go | Kubernetes reconcile loop |
| Isolation | Cilium NetworkPolicy | eBPF pod network quarantine |
| Dashboard | React + FastAPI + WebSockets | Real-time command center |
| VPN | Tailscale/WireGuard | Secure cross-cloud mesh |

---

## 🔐 Security: MITRE ATT&CK Mapping

| Falco Alert | MITRE TTP | Aegis Response |
|---|---|---|
| Shell spawned in container | T1059 — Command Execution | QUARANTINE |
| Sensitive file read (/etc/shadow) | T1552 — Credential Access | QUARANTINE |
| Network tool launched | T1046 — Network Discovery | QUARANTINE |
| Memory spike + OOM Kill | (Operational) | RESTART |
| CPU throttling loop | (Operational) | SCALE |

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
