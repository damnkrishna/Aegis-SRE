# Security Guide: MITRE ATT&CK T1499 — Endpoint Denial of Service & Memory Bomb

## Threat Overview
An attacker sends maliciously crafted HTTP payloads (e.g. decompression bombs, zip bombs, nested JSON payloads) designed to consume 100% CPU/Memory in a single request and crash microservices.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Rapid Resource Exhaustion Attack`
- Behavior: Exponential spike in process heap allocation within $< 500\text{ms}$ of receiving an HTTP request on a specific endpoint.
- MITRE Tag: `T1499`

## Critical Assessment Rule
> **CRITICAL:** DoS memory bombs target application processing logic. A pod restart will crash again if the attacker sends another payload. Isolate the target pod via Cilium eBPF network quarantine.

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Execution:** Apply Cilium eBPF NetworkPolicy isolation to sever payload origin while preserving process core dump for analysis.
