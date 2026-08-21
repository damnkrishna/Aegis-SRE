import logging

logger = logging.getLogger("aegis-brain-serializer")

class MetricSerializer:
    """
    Implements Proposal 2 (Metric-to-Text Serializer):
    Compresses raw Prometheus JSON metric time-series data into a concise,
    structured 3-line text summary to reduce LLM prompt tokens by ~80%.
    """
    
    # Configurable status thresholds
    CPU_THRESHOLD_ELEVATED = 80.0
    RAM_THRESHOLD_OOM = 85.0
    ERROR_RATE_HIGH = 10.0

    @classmethod
    def serialize_prometheus_metrics(cls, pod_name: str, raw_metrics: dict) -> str:
        """
        Converts raw Prometheus metrics JSON dictionary into structured text summary.
        """
        total_requests = raw_metrics.get("total_requests", 0)
        error_500_count = raw_metrics.get("error_500_count", 0)
        avg_latency_ms = raw_metrics.get("avg_latency_ms", 0.0)
        memory_mb = raw_metrics.get("memory_mb", 0.0)
        cpu_usage_pct = raw_metrics.get("cpu_usage_pct", 0.0)

        # Calculate error rate percentage
        if total_requests > 0:
            error_rate = (error_500_count / total_requests) * 100.0
        else:
            error_rate = 0.0

        # Assess health status strings
        cpu_status = "ELEVATED" if cpu_usage_pct >= cls.CPU_THRESHOLD_ELEVATED else "NORMAL"
        ram_status = "NEAR OOM" if memory_mb >= cls.RAM_THRESHOLD_OOM else "NORMAL"
        error_status = "HIGH" if error_rate >= cls.ERROR_RATE_HIGH else "NORMAL"

        summary = (
            f"[PROMETHEUS METRIC CONTEXT]\n"
            f"Target Pod: {pod_name}\n"
            f"CPU Usage: {cpu_usage_pct:.1f}% (Status: {cpu_status})\n"
            f"Memory Allocation: {memory_mb:.1f} MB (Status: {ram_status})\n"
            f"HTTP Traffic: {total_requests} Total Requests | 500 Errors: {error_500_count} ({error_rate:.1f}%, Status: {error_status})\n"
            f"Avg Request Latency: {avg_latency_ms:.1f} ms"
        )
        return summary
