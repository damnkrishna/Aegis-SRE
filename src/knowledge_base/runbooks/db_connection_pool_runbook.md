# SRE Runbook: Database Connection Pool Exhaustion

## Problem Overview
Database connection pool exhaustion occurs when an application service exhausts all available database handles, causing incoming HTTP requests to block and time out.

## Symptoms
- Loki logs showing `TimeoutError: QueuePool limit of size X overflow Y reached` or `Too many connections`.
- Spikes in HTTP 500/504 status codes across dependent services.
- Database connection pool metric at 100% utilization.

## Topology-Aware RCA Guidance
1. Identify downstream database service node and check current active connection counts.
2. Check if connection leaks exist in recent service release (unclosed database transactions).
3. Confirm whether traffic spike is legitimate load vs SQL injection / DOS attack.

## Remediation Protocol
- **Category:** `OPERATIONAL_BUG`
- **Action:** `RESTART`
- **Execution:** Trigger rolling restart of application pod (`kubectl rollout restart deployment <target>`) to release leaked handles and reset pool connections.
