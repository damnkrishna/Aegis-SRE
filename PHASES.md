# 📋 Aegis-SRE: Phase Distribution & Work Plan

> Detailed breakdown of all 7 phases — what gets built, who owns it, and what success looks like.

---

## Overview

```
Phase 1 → Infrastructure Foundation (Cloud Lab)
Phase 2 → Sensory System (Observability + eBPF)
Phase 3 → Diagnostic Brain (Ollama + RAG)
Phase 4 → Decision Engine (Function Calling + Guardrails)
Phase 5 → Action Muscle (Go Controller + Cilium)
Phase 6 → Immune Response (Adaptive Remediation Logic)
Phase 7 → Real-Time Command Center (Dashboard)
```

---

## Phase 1 — The Cloud Laboratory

**Goal:** Stand up a production-grade, always-free Kubernetes cluster in the cloud.

### What Gets Built
- K3s cluster deployed on **Oracle ARM A1** (4 OCPU / 24 GB RAM, Always Free tier)
- **Online Boutique** microservice app (or similar) as the target ecosystem
- **Chaos Injection Pods** — manually triggerable failure scenarios (OOM, CPU spike, etc.)
- **Tailscale/WireGuard VPN** overlay connecting Oracle cluster ↔ Azure monitoring VM

### Success Criteria
- [ ] `kubectl get nodes` shows healthy ARM node(s)
- [ ] Online Boutique pods are running and accessible
- [ ] Chaos pods can be triggered on-demand and produce measurable anomalies
- [ ] Oracle cluster and Azure VM can communicate over encrypted tunnel

### Work Division
| Task | Owner |
|---|---|
| K3s cluster provisioning on Oracle | Teammate |
| Tailscale/WireGuard setup + VPN mesh | Teammate |
| Chaos Injection Pod YAML definitions | Krishna |
| Microservice app deployment manifests | Teammate |

---

## Phase 2 — The Sensory System

**Goal:** The cluster must "feel pain" — resource exhaustion and kernel-level threats both detected.

### What Gets Built
- **Prometheus + AlertManager** — scraping metrics from all pods, firing alerts on thresholds
- **Falco + eBPF** — monitoring raw Linux kernel syscalls for security anomalies
- **Loki + Promtail** — streaming structured logs from all pods into a searchable store

### Key Falco Rules (Examples)
```yaml
# Detect reverse shell
- rule: Shell Spawned in Container
  condition: spawned_process and container and shell_procs
  output: "Shell spawned (user=%user.name cmd=%proc.cmdline)"
  priority: WARNING

# Detect credential scraping
- rule: Sensitive File Opened
  condition: open_read and sensitive_files and container
  output: "Sensitive file read (file=%fd.name)"
  priority: ERROR
```

### Success Criteria
- [ ] Prometheus dashboard shows live CPU/RAM/Error metrics
- [ ] AlertManager fires an alert when CPU > 80% for 2 minutes
- [ ] Falco logs appear in Loki when a shell is spawned inside a container
- [ ] Promtail correctly tags logs with pod/namespace labels

### Work Division
| Task | Owner |
|---|---|
| Prometheus + AlertManager setup | Teammate |
| Loki + Promtail deployment | Teammate |
| Falco installation + eBPF mode | Krishna |
| Custom Falco rules (MITRE mapped) | Krishna |
| Cilium initial deployment | Krishna |

---

## Phase 3 — The Diagnostic Brain

**Goal:** The LLM must read alert data and produce a structured diagnosis.

### What Gets Built
- **Ollama** running `llama3.1:8b-instruct-q4_0` directly on the Oracle ARM instance
- **Vector Database** (ChromaDB or Qdrant) seeded with:
  - Kubernetes SRE runbooks
  - MITRE ATT&CK TTPs (T1059, T1552, T1046, etc.)
  - Falco rule documentation
- **RAG Pipeline** — on alert, retrieve top-K relevant docs and inject into LLM prompt context

### LLM Prompt Structure
```
SYSTEM: You are an expert SRE and cybersecurity analyst. 
        Use the provided context to classify the incident.

CONTEXT (from RAG):
  [Retrieved runbook excerpts / MITRE TTP descriptions]

ALERT DATA:
  Prometheus: CPU=98%, Memory=94%
  Falco: Shell spawned in container checkout-service (T1059)
  Logs: [last 50 lines from Loki]

TASK: Classify this incident. Output JSON only:
{
  "category": "BUG" | "ATTACK",
  "root_cause": "...",
  "confidence": 0.0-1.0,
  "action": "RESTART" | "SCALE" | "QUARANTINE" | "ESCALATE",
  "target": "pod-name",
  "reason": "MITRE TTP or runbook reference"
}
```

### Success Criteria
- [ ] Ollama serves responses locally on Oracle ARM in < 5 seconds
- [ ] RAG retrieval returns relevant runbook entries for a given alert type
- [ ] LLM correctly classifies "Shell Spawned" as ATTACK and "OOM Kill" as BUG in test runs
- [ ] JSON output is parseable by the downstream guardrail engine

### Work Division
| Task | Owner |
|---|---|
| Ollama installation + model pull on ARM | Teammate |
| Vector DB setup + document ingestion | Teammate |
| RAG pipeline (retrieval + prompt injection) | Teammate |
| MITRE ATT&CK document curation | Krishna |
| Prompt engineering + test classification runs | Teammate + Krishna |

---

## Phase 4 — The Decision Engine (Strategy + Guardrails)

**Goal:** Validate LLM output before any action touches the cluster.

### What Gets Built
- **LLM Function Calling** — structured JSON action object from the LLM
- **Catastrophic Guard** — a rule-based pre-filter written in Go/Python

### The Guardrail Logic

```python
ALLOWED_ACTIONS = {"RESTART", "SCALE", "QUARANTINE", "ESCALATE"}
BLOCKED_ACTIONS = {"DELETE_NAMESPACE", "DELETE_NODE", "DELETE_CLUSTER"}

MAX_RESTART_FREQUENCY = 3  # per pod per hour

def validate(action_obj):
    if action_obj["action"] in BLOCKED_ACTIONS:
        return REJECT, "Action is on blocklist"
    if action_obj["action"] not in ALLOWED_ACTIONS:
        return REJECT, "Unknown action"
    if action_obj["confidence"] < 0.7:
        return ESCALATE, "Confidence too low for autonomous action"
    return APPROVE, "OK"
```

### Guardrail Decision Table
| LLM Output | Guardrail Decision | Reason |
|---|---|---|
| `RESTART` pod | ✅ APPROVED | Safe, reversible |
| `SCALE` deployment | ✅ APPROVED | Safe, reversible |
| `QUARANTINE` pod | ✅ APPROVED | Safe, forensics-preserving |
| `DELETE_NAMESPACE` | ❌ BLOCKED | Catastrophic, irreversible |
| `confidence: 0.3` | ⚠️ ESCALATE | LLM unsure, human decides |

### Success Criteria
- [x] All blocked actions (`DELETE_NAMESPACE`, `DELETE_NODE`, `PURGE_STORAGE`) are rejected with a logged reason
- [x] Confidence threshold enforcement ($\ge 0.70$) works correctly
- [x] Action objects pass schema validation before reaching the controller
- [x] Frequency limiter prevents restart loops (max 3 restarts per pod per hour)
- [x] Structured JSON decision traces written to `logs/guardrail_audit.jsonl`
- [x] 100% Unit test pass rate (`test/test_guardrails.py`: 6/6 tests OK)

### Work Division & Status
| Task | Owner | Status |
|---|---|---|
| Guardrail rule engine (`src/guardrails/validator.py`) | Krishna | ✅ Completed & Tested |
| Action schema definition (`src/guardrails/action_schema.py`) | Krishna | ✅ Completed |
| MITRE TTP → Action mapping logic | Krishna | ✅ Completed |
| Integration & Unit test suite (`test/test_guardrails.py`) | Krishna | ✅ Completed (6/6 Pass) |
| Structured Audit Logging (`logs/guardrail_audit.jsonl`) | Krishna | ✅ Completed |


---

## Phase 5 — The Muscle (Go Controller + Cilium)

**Goal:** Execute validated actions precisely via the Kubernetes API.

### What Gets Built
- **Go K8s Controller** using `controller-runtime` / `client-go`
  - Watches for validated Action objects (custom CRDs or queue)
  - Reconcile loop: read desired state → compare → execute
- **Cilium NetworkPolicy enforcer**
  - Generates quarantine policies that DROP all ingress/egress for a target pod
  - Uses eBPF — no iptables, no VLANs, kernel-level enforcement

### Quarantine NetworkPolicy (Cilium)
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: quarantine-pod-xyz
spec:
  endpointSelector:
    matchLabels:
      app: pod-xyz
  ingress: []   # No ingress rules = DROP ALL
  egress:  []   # No egress rules  = DROP ALL
```

### The Reconcile Loop
```
Watch Action Queue
  → Read action: {QUARANTINE, pod-xyz}
  → Validate: is pod-xyz still running?
  → Apply CiliumNetworkPolicy to pod-xyz
  → Annotate pod: aegis.io/status=quarantined
  → Emit event to Dashboard via WebSocket
  → Re-verify: is traffic actually blocked?
  → Log result to Loki
```

### Success Criteria
- [x] Go controller compiles and connects to cluster via in-cluster config (`controller/main.go`)
- [x] RESTART action successfully rolls out a pod restart (`RESTART_POD` & `SCALE_DEPLOYMENT`)
- [x] QUARANTINE action applies Cilium policy and verifiably blocks traffic (`CILIUM_QUARANTINE_EBPF`)
- [x] Automated DFIR Security Forensics Capture on threat detection (`logs/forensics_<pod_name>.json`)
- [x] Action Reversibility implemented (`UNQUARANTINE_POD` handler removes eBPF network cages)
- [x] Post-Remediation Active Health Verification loop (`verify_remediation_health`)
- [x] Structured JSON audit logging (`logs/controller_audit.jsonl`)
- [x] 100% Test pass rate across all unit & pipeline suites (`test/test_controller.py` & `test/test_pipeline.py`)

### Work Division & Status
| Task | Owner | Status |
|---|---|---|
| Action Executor Engine (`src/controller/executor.py`) | Krishna | ✅ Completed & Tested |
| eBPF Cilium Policy Generator (`src/controller/cilium_policy.py`) | Krishna | ✅ Completed & Tested |
| Automated DFIR Forensics Engine (`logs/forensics_*.json`) | Krishna | ✅ Completed & Tested |
| Action Reversibility (`UNQUARANTINE_POD` Handler) | Krishna | ✅ Completed & Tested |
| Post-Remediation Health Verification Engine | Krishna | ✅ Completed & Tested |
| Go Controller Scaffold & Reconciler (`controller/`) | Teammate | ✅ Completed |
| Controller REST API Router (`src/controller/api.py`) | Krishna | ✅ Completed |
| Unit & Integration Test Suite (`test/test_controller.py`) | Krishna | ✅ Completed (5/5 Pass) |


---

## Phase 6 — The Immune Response

**Goal:** Define the complete adaptive remediation logic and verification loop.

### The Two Paths in Full

```
┌─────────────────────────────────────────────────────┐
│              INCIDENT DETECTED                      │
│        (Prometheus Alert OR Falco Event)            │
└──────────────────────┬──────────────────────────────┘
                       │
               ┌───────▼───────┐
               │  LLM Triage   │
               └───────┬───────┘
          ┌────────────┴────────────┐
          │ BUG                   ATTACK
          ▼                         ▼
   ┌─────────────┐          ┌─────────────────┐
   │  HEAL Path  │          │  DEFEND Path    │
   │             │          │                 │
   │ → Restart   │          │ → Quarantine    │
   │ → Scale Up  │          │ → Cut network   │
   │ → Tune HPA  │          │ → Preserve pod  │
   └──────┬──────┘          └────────┬────────┘
          │                          │
          └──────────┬───────────────┘
                     ▼
            ┌────────────────┐
            │ VERIFY Action  │
            └───────┬────────┘
          ┌─────────┴────────┐
     Healthy              Still broken
          │                   │
     Log success         ESCALATE to human
```

### Escalation Triggers
- LLM confidence < 0.7
- Same pod restarted 3+ times in 1 hour
- Action taken but metrics still critical after 5 minutes
- Unknown action type returned by LLM

### Success Criteria
- [x] End-to-end Bug path verified: chaos pod → alert → restart → healthy
- [x] End-to-end Attack path verified: shell spawn → alert → quarantine → eBPF traffic blocked
- [x] Rigorous 8-Category Cloud-OpsBench Benchmark Suite implemented (`test/test_chaos_benchmark.py`)
- [x] Verification loop detects failed remediation and escalates (`STATE_ESCALATE_HUMAN`)
- [x] Automated DFIR forensics capture on security threats (`logs/forensics_*.json`)
- [x] Benchmark JSON report generated (`logs/cloud_opsbench_report.json`)
- [x] 100% Test pass rate across all 5 test battery suites (25/25 tests OK)

### Work Division & Status
| Task | Owner | Status |
|---|---|---|
| End-to-End Bug & Attack Path Pipeline (`src/brain/main.py`) | Krishna | ✅ Completed & Tested |
| Rigorous Cloud-OpsBench Benchmark Suite (`test/test_chaos_benchmark.py`) | Krishna | ✅ Completed (8/8 Pass) |
| Post-Remediation Verification Loop & Escalation Workflow | Krishna | ✅ Completed & Tested |
| Security Forensics Snapshotting on Quarantine | Krishna | ✅ Completed & Tested |
| Benchmark Report Generation (`logs/cloud_opsbench_report.json`) | Krishna | ✅ Completed |
| Verification loop logic | Teammate |
| Escalation workflow + notification | Teammate |
| Security forensics dump on quarantine | Krishna |
| End-to-end Bug path integration test | Both |
| End-to-end Attack path integration test | Both |

---

## Phase 7 — The Real-Time Command Center

**Goal:** Visualize the AI's reasoning and cluster state in real time.

### What Gets Built
- **FastAPI backend** on Azure B1s with WebSocket endpoints
- **React frontend** with live panels:
  - Cluster health map (pod status, resource usage)
  - Live LLM reasoning text stream (the "why")
  - Go Controller execution log (the "what happened")
  - Active quarantine list with forensics links
  - Alert history + remediation timeline

### Dashboard Panels
| Panel | Data Source | Update Frequency |
|---|---|---|
| Pod Health Grid | Prometheus API | Every 5s |
| LLM Reasoning Stream | FastAPI WebSocket | Real-time |
| Controller Action Log | WebSocket events | Real-time |
| Active Quarantines | Controller events | Real-time |
| Alert Timeline | AlertManager API | On trigger |
| Falco Event Feed | Loki API | Every 10s |

### Success Criteria
- [x] Dashboard shows live pod states with color coding (🟢 Healthy, 🟡 Degraded, 🔴 Quarantined)
- [x] LLM reasoning text streams to dashboard within 2s of trigger via WebSockets
- [x] Controller execution logs appear alongside LLM reasoning in cyberpunk terminal feed
- [x] Quarantine events visually highlight isolated pods with DFIR process/socket inspection modal
- [x] Human-in-the-Loop (HITL) Escalation & Remediation Control Drawer opens on demand for human review & direct command dispatch
- [x] Interactive Production Chaos Simulation Console triggers end-to-end self-healing live from the UI
- [x] 100% Test pass rate across all 6 test battery suites (30/30 tests OK)

### Work Division & Status
| Task | Owner | Status |
|---|---|---|
| FastAPI backend + WebSocket server (`src/dashboard/server.py`) | Krishna | ✅ Completed & Tested |
| HTML5 / CSS / JS Real-Time Dashboard Frontend (`src/dashboard/static/`) | Krishna | ✅ Completed & Tested |
| Interactive Pod Telemetry Grid & Scorecards | Krishna | ✅ Completed & Tested |
| Live WebSockets Terminal Stream | Krishna | ✅ Completed & Tested |
| eBPF Quarantine & DFIR Forensics Modal Inspector | Krishna | ✅ Completed & Tested |
| Human-in-the-Loop (HITL) Remediation Drawer | Krishna | ✅ Completed & Tested |
| Production Chaos Simulation Console | Krishna | ✅ Completed & Tested |
| Dashboard Integration Test Suite (`test/test_dashboard.py`) | Krishna | ✅ Completed (5/5 Pass) |

---

## 📅 Suggested Timeline

| Week | Phases | Milestone |
|---|---|---|
| Week 1 | Phase 1 | Cluster is live, chaos pods work |
| Week 2 | Phase 2 | Prometheus + Falco both firing alerts |
| Week 3 | Phase 3 | LLM classifies test scenarios correctly |
| Week 4 | Phase 4 | Guardrails block bad actions, approve good ones |
| Week 5 | Phase 5 | Go controller executes RESTART + QUARANTINE |
| Week 6 | Phase 6 | Full end-to-end Bug + Attack paths verified |
| Week 7 | Phase 7 | Dashboard live, streaming real data |
| Week 8 | Buffer | Polish, load testing, write-up |

---

## 🏁 Definition of Done

The project is "done" when:
1. A chaos pod triggers a CPU spike → system restarts the affected service autonomously
2. A simulated reverse shell (Falco test rule) → system quarantines the pod in < 60s
3. Dashboard shows the full reasoning chain for both scenarios
4. Guardrails demonstrably block a `DELETE_NAMESPACE` action injected in testing
5. All components run on zero-cost infrastructure (Oracle Always Free + Azure Free Tier)

---

*Phase Distribution v1.0 — Aegis-SRE*
