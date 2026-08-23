# Security Guide: MITRE ATT&CK T1046 — Network Service Discovery & Scanning

## Threat Overview
An attacker inside a compromised container attempts internal network scanning (port scanning, service discovery) across the Kubernetes pod network to find vulnerable adjacent microservices.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Network Reconnaissance Detected`
- Binary: `nmap`, `nc`, `netcat`, `masscan`, or custom port scan socket loops.
- MITRE Tag: `T1046`
- Behavior: High volume of outbound TCP SYN connection attempts across `/16` or `/24` pod subnet.

## Critical Assessment Rule
> **CRITICAL:** Network scanning is a clear indicator of post-exploitation lateral movement. Container restart will not stop lateral movement if attacker maintains an external entrypoint.

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Execution:** Apply Cilium eBPF NetworkPolicy that drops ALL ingress and egress network traffic immediately to contain lateral movement.
