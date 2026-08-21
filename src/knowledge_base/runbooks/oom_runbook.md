# SRE Runbook: Out Of Memory (OOMKilled - Exit Code 137)

## Problem Overview
An OOMKilled event occurs when a container attempts to consume more memory than allowed by its cgroup memory limit or node memory capacity.

## Symptoms
- Container status changes to `OOMKilled` or exit code `137`.
- Prometheus metric `process_resident_memory_bytes` exceeds limit threshold.
- Memory allocation spikes prior to container crash.

## Root Cause Analysis Steps
1. Inspect recent memory allocation metrics prior to crash.
2. Check application logs for memory leaks or uncollected garbage objects.
3. Distinguish between an application memory leak (operational bug) vs malicious memory exhaustion attack.

## Remediation Protocol
- **Operational Bug:** Trigger Kubernetes `kubectl rollout restart` or temporarily increase container memory limit.
- **Security Attack:** If memory exhaustion is accompanied by unauthorized process execution, isolate container via Cilium eBPF network policy.
