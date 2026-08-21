import logging
from src.brain.collector import TelemetryCollector
from src.brain.metric_serializer import MetricSerializer
from src.brain.rag_engine import RAGEngine
from src.brain.llm_client import LLMClient
from src.brain.prompt_templates import SYSTEM_DIAGNOSTIC_PROMPT, USER_EVIDENCE_PROMPT_TEMPLATE

logger = logging.getLogger("aegis-brain-engine")

class DiagnosticEngine:
    """
    Core AI Diagnostic Orchestrator for Phase 3.
    Coordinates Telemetry Collection, Metric Serialization, RAG Retrieval,
    and LLM Inference to generate structured JSON Diagnostic Verdicts.
    """
    def __init__(self):
        self.collector = TelemetryCollector()
        self.rag = RAGEngine()
        self.llm = LLMClient()

    def diagnose_incident(self, pod_name: str = "aegis-target-app", alert_type: str = "HTTP_500_SPIKE") -> dict:
        """
        Executes end-to-end AI diagnosis pipeline for an incident.
        """
        logger.info(f"Starting AI Diagnosis for pod '{pod_name}' (Alert: {alert_type})...")

        # 1. Fetch raw telemetry
        raw_metrics = self.collector.fetch_prometheus_metrics(pod_name)
        loki_logs = self.collector.fetch_loki_logs(pod_name)
        falco_events = self.collector.fetch_falco_alerts(pod_name)

        # 2. Serialize metrics (Proposal 2 - 80% token reduction)
        metric_summary = MetricSerializer.serialize_prometheus_metrics(pod_name, raw_metrics)

        # 3. Retrieve RAG Runbooks
        rag_context = self.rag.search_runbooks(f"{alert_type} {pod_name}")

        # 4. Build User Prompt
        formatted_logs = "\n".join(loki_logs[-10:])
        formatted_falco = "\n".join(falco_events) if falco_events else "No eBPF kernel security alerts detected."

        user_prompt = USER_EVIDENCE_PROMPT_TEMPLATE.format(
            pod_name=pod_name,
            alert_type=alert_type,
            metric_summary=metric_summary,
            loki_logs=formatted_logs,
            falco_events=formatted_falco,
            rag_context=rag_context
        )

        # 5. Generate LLM JSON Verdict
        verdict = self.llm.generate_json_diagnosis(SYSTEM_DIAGNOSTIC_PROMPT, user_prompt)
        logger.info(f"Diagnostic Verdict Generated: {verdict.get('problem_type')} -> {verdict.get('recommended_action')}")
        
        return verdict
