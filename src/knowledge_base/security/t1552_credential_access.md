# Security Guide: MITRE ATT&CK T1552 — Unsecured Credentials & Secret Access

## Threat Overview
An adversary or compromised process attempts to access cluster credentials, Kubernetes service account tokens, or environment variable secrets within a running container.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Sensitive File Read` / `Service Account Token Read`
- Target Path: `/var/run/secrets/kubernetes.io/serviceaccount/token` or `.env` file
- MITRE Tag: `T1552`
- Syscall: `openat`, `read` by non-system utility process.

## Critical Assessment Rule
> **CRITICAL:** Attempting to fix secret scraping with a pod restart (`kubectl rollout restart`) is INEFFECTIVE and DANGEROUS. The attacker will retain compromised tokens or re-scrape secrets on restart.

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Execution:** Apply Cilium eBPF NetworkPolicy that drops ALL ingress and egress network traffic to isolate the pod while preserving memory state for forensic investigation.
