# Security Guide: MITRE ATT&CK T1059 — Command and Scripting Interpreter

## Threat Overview
An adversary spawns a command shell (`sh`, `bash`, `zsh`) inside a running container to execute arbitrary commands, download malicious payloads, or establish a reverse shell.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Shell Spawned in Container`
- Syscall: `execve`
- Target Process: `/bin/sh`, `/bin/bash`
- MITRE Tag: `T1059`

## Critical Assessment Rule
> **CRITICAL:** Fixing an active attacker with a simple pod restart (`kubectl rollout restart`) is INEFFECTIVE. The attacker will simply re-infect the new container instance. 

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Isolation Mechanism:** Apply a Cilium eBPF NetworkPolicy that drops ALL ingress and egress network traffic to the container while keeping PID alive for forensic analysis.
