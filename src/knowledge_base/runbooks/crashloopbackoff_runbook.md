# SRE Runbook: Container CrashLoopBackOff & Startup Failures

## Problem Overview
A `CrashLoopBackOff` state indicates that a Kubernetes pod is repeatedly starting, crashing, and restarting.

## Symptoms
- Pod status `CrashLoopBackOff` with non-zero exit code (e.g., exit code 1, 139, 255).
- Liveness or Readiness probe failures in pod events.
- Error logs in Loki indicating missing configuration keys, DB connection failure, or unhandled startup exceptions.

## Topology-Aware RCA Guidance
1. Check if database dependency or configuration server upstream is reachable.
2. Verify environment variable resolution and secret mounts.
3. Distinguish between bad code release/missing dependency (Operational Bug) vs binary tampering/corrupted pod image (Security Incident).

## Remediation Protocol
- **Category:** `OPERATIONAL_BUG`
- **Action:** `RESTART` or `ROLLBACK`
- **Execution:** Trigger Kubernetes deployment rollout restart (`kubectl rollout restart deployment <target>`) or rollback deployment revision.
