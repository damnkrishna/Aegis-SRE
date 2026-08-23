# Security Guide: MITRE ATT&CK T1078 — Compromised Service Account Token & Valid Accounts

## Threat Overview
An adversary extracts a valid Kubernetes ServiceAccount token from a compromised pod to authenticate directly to the K8s API server, bypassing network perimeters to steal secrets or deploy malicious workloads.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Unauthorized K8s API Token Use`
- Behavior: Outbound HTTPS request to Kubernetes API server (`kubernetes.default.svc:443`) originating from a non-control-plane microservice container.
- MITRE Tag: `T1078`

## Critical Assessment Rule
> **CRITICAL:** Token theft compromises identity at the cluster RBAC level. Restarting the pod without network quarantine leaves the compromised token active for cluster exploitation.

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Execution:** Instantly apply Cilium eBPF NetworkPolicy isolation to sever API server communication and revoke ServiceAccount token.
