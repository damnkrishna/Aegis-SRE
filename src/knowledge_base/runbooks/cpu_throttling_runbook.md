# SRE Runbook: CPU Throttling & High CPU Usage Spikes

## Problem Overview
CPU throttling occurs when a container attempts to consume more CPU time than its configured cgroup CPU quota allows, leading to latency spikes and request timeouts.

## Symptoms
- Container CPU utilization exceeds 90% threshold (`container_cpu_usage_seconds_total`).
- High cgroup throttling metrics (`container_cpu_cfs_throttled_periods_total`).
- Request latency spikes in application metrics.
- NO Falco security alerts or unexpected binary execution.

## Topology-Aware RCA Guidance
1. Inspect if CPU spike is localized to target pod or cascading from upstream caller microservice.
2. Check thread pool utilization and event loop blocking in application logs.
3. Distinguish between unexpected workload traffic spikes (Operational Bug/Scale issue) vs cryptomining process execution (Security Attack).

## Remediation Protocol
- **Category:** `OPERATIONAL_BUG`
- **Action:** `SCALE` or `TUNE_CPU_LIMITS`
- **Execution:** Trigger Kubernetes `kubectl scale deployment <target>` or issue rolling restart with increased CPU quota.
