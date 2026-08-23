# Security Guide: Unauthorized Cryptomining Binary Execution

## Threat Overview
An attacker exploits a container vulnerability to launch unauthorized cryptomining binaries (`xmrig`, `minerd`) that hijack cluster CPU/GPU resources.

## Detection Signature (Falco eBPF)
- Falco rule: `Aegis Unauthorized Mining Process Execution`
- Behavior: 100% CPU usage combined with outbound connections to mining pool domains/IPs (Stratum protocol).
- Syscall: Execution of unknown binaries outside app path (`/tmp/xmrig`, `/var/tmp/minerd`).

## Critical Assessment Rule
> **CRITICAL:** Cryptomining MUST NOT be treated as a standard CPU high usage operational bug. Scaling or restarting the container without isolation will only consume more cluster resources for the attacker.

## Mandatory Remediation Protocol
- **Category:** `SECURITY_ATTACK`
- **Action:** `QUARANTINE_CILIUM_EBPF`
- **Execution:** Instantly apply Cilium eBPF NetworkPolicy isolation to sever stratum connection and isolate infected pod.
