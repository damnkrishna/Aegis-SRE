# 🤝 Aegis-SRE: Proposed Project Enhancements & Teammate Review Guide

> **Purpose:** This document presents a set of carefully evaluated, low-risk architectural enhancements drawn from recent 2025/2026 SRE & Cloud Security research papers. 
> These proposals are designed to make **Aegis-SRE more reliable and easier to test without adding unnecessary complexity or deviating from our core tech stack**.

---

## 🎯 Executive Summary for the Team

We analyzed 5 top-tier cloud research papers (published on arXiv between 2025-2026) to see if any concepts could improve Aegis-SRE. 

To ensure we **do not overcomplicate the project** or break our existing timeline:
* ❌ **Rejected:** Complex Graph Neural Networks, deep RL models, and heavy custom operators (which add maintenance overhead).
* ✅ **Selected:** 4 lightweight, zero-dependency improvements that enhance testing, prompt speed, and diagnostic accuracy.

---

## 📋 Summary of Selected Proposals

| Proposal | Inspired By | Target Phase | Implementation Complexity | Primary Benefit |
|---|---|---|---|---|
| **1. Standardized Chaos Test Suite** | *Cloud-OpsBench (2026)* | **Phase 1 & 6** | 🟢 Low (Simple K8s YAMLs) | Allows repeatable end-to-end testing of the entire immune system |
| **2. Metric-to-Text Serializer** | *IBM SRE Anomaly Service (2025)* | **Phase 3** | 🟢 Low (~30 lines of Python) | Reduces LLM prompt size by ~80%, speeding up Ollama inference |
| **3. Topology-Aware Context Bounding** | *Graph-Guided RCA (2026)* | **Phase 3 & 4** | 🟢 Low (K8s API labels query) | Prevents the LLM from hallucinating root causes in unrelated services |
| **4. Explicit State Machine Pipeline** | *SynergyRCA (2025)* | **Phase 4 & 5** | 🟢 Low (Go / Python enum states) | Makes incident progression transparent, auditable, and easy to debug |

---

## 🔬 Deep Dive: Detailed Breakdown, Risk Analysis & Tradeoffs

---

### Proposal 1: Standardized Chaos Test Suite
* **Paper Reference:** *Cloud-OpsBench: A Reproducible Benchmark for Agentic RCA* (`arXiv:2603.00468`)
* **What it is:** A set of 5 pre-configured, triggerable chaos pod manifests saved in `k8s/chaos/`.
* **Why we need it:** To prove that Aegis-SRE actually works during project defense/presentation, we need quick, reproducible failure scenarios that can be triggered on demand.
* **Scenarios to add:**
  1. `chaos-oom.yaml`: Simulates a memory leak in a target pod. *(Resource Chaos)*
  2. `chaos-cpu-spike.yaml`: Triggers CPU throttling (>90% usage). *(Resource Chaos)*
  3. `chaos-500-flood.yaml`: Generates HTTP 500 error spikes. *(Application Chaos)*
  4. `chaos-shell-injection.yaml`: Spawns a shell in a pod to trigger Falco eBPF T1059 rule. *(Security Attack Chaos)*
  5. `chaos-crashloop.yaml`: Triggers container crash loops. *(Application Chaos)*
* **Where it fits:** **Phase 1 (Infra Lab)** & **Phase 6 (Immune Response Verification)**.
* **Tool & Version Compatibility:**
  * ✅ **K3s / Kubernetes v1.28+:** 100% Compatible (Uses standard K8s Deployment YAMLs).
  * ✅ **Prometheus / Falco eBPF:** 100% Compatible (Triggers standard alerts).
* **⚖️ Tradeoffs & Risk Mitigation:**
  * *Resource Chaos (1-3, 5):* **Zero risk**. Isolated to test pods.
  * *Security Attack Chaos (4):* **Requires Blast Radius Control**. Unlike resource chaos, `chaos-shell-injection` simulates an active MITRE T1059 attack technique. 
  * *Mitigation:* Deploy it strictly in a dedicated `aegis-chaos` namespace with zero RBAC secret access, no host path mounts, and restricted egress Cilium NetworkPolicies so it cannot touch host kernel or cluster secrets.

---

### Proposal 2: Configurable Metric-to-Text Serializer
* **Paper Reference:** *IBM LLM Assisted Anomaly Detection Service* (`arXiv:2501.16744`)
* **What it is:** A lightweight helper function inside our Python RAG/LLM engine that condenses raw Prometheus metric JSON arrays into a 3-line structured summary before sending it to Ollama.
* **Example Summary Output:**
  ```text
  [METRIC CONTEXT]
  Target: checkout-service (Namespace: aegis)
  CPU Usage: 94.2% (Status: ELEVATED)
  Memory Usage: 890MB / 1024MB (Status: NEAR OOM)
  Error Rate (5m): 14.2% (Status: HIGH)
  ```
* **Why we need it:** Passing raw Prometheus JSON time-series data into Ollama (Llama 3.1 8B) wastes context tokens. Summarizing it drastically reduces context tokens.
* **Where it fits:** **Phase 3 (Diagnostic Brain)**.
* **Tool & Version Compatibility:**
  * ✅ **Python 3.10+ & Ollama Llama 3.1 8B:** 100% Compatible.
  * ✅ **Prometheus API v1:** 100% Compatible.
* **⚖️ Tradeoffs & Risk Mitigation:**
  * *Performance Figures Note:* The projected 12s ➔ ~2s latency drop and ~80% token reduction are **projected estimates based on paper benchmarks**; we will formally benchmark and report our exact local numbers during Phase 3 testing.
  * *Configurable Thresholds:* Status labels (`ELEVATED`, `NEAR OOM`, `HIGH`) will be stored in a centralized `config.yaml` file (not hardcoded magic numbers) so they can be tuned easily without changing code logic.

---

### Proposal 3: Topology-Aware Context Bounding
* **Paper Reference:** *Auditable Graph-Guided RCA for K8s Incidents* (`arXiv:2606.08590`)
* **What it is:** When an alert fires for a pod, our system fetches only its immediate upstream and downstream microservices (via standard `kubectl get endpoints` / service labels) to include in the LLM prompt.
* **Why we need it:** If microservice `payment-service` fails, the LLM shouldn't waste time investigating `frontend-service` or `email-service`. Bounding the context ensures high diagnostic accuracy.
* **Where it fits:** **Phase 3 (Diagnostic Brain)** & **Phase 4 (Decision Engine)**.
* **Tool & Version Compatibility:**
  * ✅ **K8s API Server / Client-Go / Python Kubernetes SDK:** 100% Compatible.
* **⚖️ Tradeoffs & Risk Mitigation:**
  * *Multi-Hop Cascades Limitation:* Bounding to 1-hop immediate neighbors might miss root causes that are 2+ hops away (e.g. a shared database or config server multi-layers removed).
  * *Fallback Mitigation:* If the LLM produces a **Low Confidence Score (< 0.7)** during 1-hop traversal, the system automatically triggers a fallback policy: *"Expand graph traversal radius by +1 hop and re-fetch evidence."*

---

### Proposal 4: Non-Linear State Machine Pipeline
* **Paper Reference:** *Simplifying RCA in K8s with StateGraph* (`arXiv:2506.02490`)
* **What it is:** Structuring our autonomous controller logic into an explicit state machine with non-linear error/retry states:

```
  ┌─────────────────┐       ┌────────────────────┐       ┌──────────────────┐
  │ 1. ALERT_FIRED  │ ────► │ 2. EVIDENCE_FETCH  │ ────► │ 3. LLM_DIAGNOSE  │
  └─────────────────┘       └────────────────────┘       └────────┬─────────┘
                                      ▲                           │
                                      │ Low Confidence Retry      ▼
                                      └────────────────── ┌──────────────────┐
                                                          │ 4. GUARDRAIL_CHK │
                                                          └────────┬─────────┘
                                                                   │
                                                   ┌───────────────┴──────────────┐
                                                   ▼                              ▼
                                        ┌──────────────────┐           ┌────────────────────┐
                                        │ 5. ACTION_EXEC   │           │ 6. ACTION_REJECTED │
                                        └──────────────────┘           └────────────────────┘
```

* **Why we need it:** Real incidents don't always follow a linear happy path. If Guardrails reject a destructive action or the LLM asks for more logs, an explicit state machine handles branch cases cleanly.
* **Key States Added:**
  * `STATE_ACTION_REJECTED`: Triggered if Guardrail Engine or human SRE vetoes the proposed remediation.
  * `STATE_RETRY_EVIDENCE`: Loop-back edge triggered if diagnostic confidence is low.
* **Where it fits:** **Phase 4 (Decision Engine)**, **Phase 5 (Go Controller)**, & **Phase 7 (Dashboard)**.
* **Tool & Version Compatibility:**
  * ✅ **Go 1.21+ / Python FastAPI / WebSockets:** 100% Compatible.
* **⚖️ Tradeoffs & Risk Mitigation:**
  * *Risk:* Infinite retry loops if evidence remains unclear.
  * *Mitigation:* Cap max retry attempts to `MAX_RETRIES = 2`. If diagnosis is still uncertain after 2 attempts, transition directly to `STATE_ACTION_REJECTED` and escalate to human on-call via Dashboard notification.

---

## 🛠️ Verification Checklist for Teammates

When reviewing these suggestions, please verify:

- [ ] Does this alter our primary goal (SRE Bug vs Security Attack differentiation)? **NO.**
- [ ] Does this require buying paid cloud services or installing heavy new frameworks? **NO.**
- [ ] Are all suggestions compatible with K3s, Prometheus, Falco eBPF, Loki, Ollama, Go, and Cilium? **YES (100% compatible).**
- [ ] Are tradeoffs and mitigations clearly defined for reviewers/panels? **YES.**
- [ ] Can we implement Aegis-SRE Phase by Phase without getting stuck? **YES.**

---

*Document updated with team review feedback. No code changes have been made to existing project files.*
