# SRE Runbook: Cascading Microservice Dependency Failure & Circuit Breaker Spike

## Problem Overview
A circuit breaker opens when a downstream dependency (e.g. payment gateway, auth service, database) experiences high latency or error rates, causing dependent caller services to fail fast and reject requests.

## Symptoms
- Loki logs showing `CircuitBreakerOpenException` or `FallbackTriggered`.
- Prometheus metric `http_requests_total{status="503"}` spiking on caller service.
- High upstream dependency response latency.

## Topology-Aware RCA Guidance
1. Inspect 1-hop downstream callee service health and latency.
2. Verify if downstream dependency is experiencing CPU/Memory throttling or DB pool exhaustion.
3. Distinguish between downstream service crash (Operational Bug) vs network layer disruption.

## Remediation Protocol
- **Category:** `OPERATIONAL_BUG`
- **Action:** `SCALE` or `RESTART_POD`
- **Execution:** Scale downstream callee deployment replicas to relieve bottleneck load, or execute rolling restart if connection pool is stale.
