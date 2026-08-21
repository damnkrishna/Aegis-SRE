# SRE Runbook: HTTP 500 Internal Server Error Spikes

## Problem Overview
An HTTP 500 spike indicates unhandled application exceptions, unhandled null pointer exceptions, or database connection pool failures.

## Symptoms
- Prometheus metric `http_requests_total{status="500"}` spiking.
- Loki logs showing `level="ERROR"` with unhandled stack traces.
- Elevated request latency.

## Root Cause Analysis Steps
1. Query Loki for log entries containing `unhandled_exception` or `database_error`.
2. Inspect application stack trace to identify failing code path.
3. Verify database connection pool health.

## Remediation Protocol
- **Operational Bug:** Trigger rolling deployment restart (`RESTART_POD`) to clear bad state or clear stale connection pool.
- **Security Attack:** If 500 errors are accompanied by SQL injection attempts or shell execution, trigger Cilium eBPF network quarantine.
