import time
import os
import json
import logging
import requests
from typing import Dict, Any, Optional

from src.guardrails.action_schema import GuardrailDecision

logger = logging.getLogger("aegis-escalation-notifier")


class EscalationNotifier:
    """
    Automated Escalation & Webhook Notification Dispatcher (Phase 6).
    Dispatches rich incident escalation alerts to operators via webhooks/Slack
    and logs immutable records to logs/escalations.jsonl when Guardrails trigger human intervention.
    """

    def __init__(self,
                 log_path: str = "logs/escalations.jsonl",
                 webhook_url: Optional[str] = None):
        self.log_path = log_path
        self.webhook_url = webhook_url or os.getenv("AEGIS_ESCALATION_WEBHOOK", None)

    def dispatch_escalation(self, decision: GuardrailDecision, verdict: dict) -> Dict[str, Any]:
        """
        Formats and dispatches structured escalation payload.
        """
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        target_pod = decision.target_pod
        problem_type = decision.problem_type
        reason = decision.reason
        confidence = decision.confidence
        state = decision.state

        payload = {
            "timestamp": timestamp,
            "incident_id": verdict.get("incident_id", f"INC-ESCALATION-{int(time.time())}"),
            "target_pod": target_pod,
            "problem_type": problem_type,
            "escalation_state": state,
            "confidence_score": confidence,
            "guardrail_reason": reason,
            "ai_root_cause": verdict.get("root_cause", "N/A"),
            "original_recommended_action": decision.original_action,
            "mitre_technique": decision.mitre_technique,
            "operator_action_required": "Manual review and decision confirmation required on Aegis Command Dashboard."
        }

        # 1. Log to local escalations audit file
        self._write_escalation_log(payload)

        # 2. Dispatch Webhook HTTP POST if webhook URL is configured
        webhook_status = "SKIPPED_NO_URL"
        if self.webhook_url:
            webhook_status = self._send_webhook(payload)

        payload["webhook_status"] = webhook_status
        logger.info(f"ESCALATION DISPATCHED for pod '{target_pod}': {reason}")
        return payload

    def _write_escalation_log(self, payload: Dict[str, Any]):
        """Appends escalation payload to logs/escalations.jsonl."""
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as e:
            logger.error(f"Failed to write escalation log: {e}")

    def _send_webhook(self, payload: Dict[str, Any]) -> str:
        """Dispatches HTTP POST request to external Webhook endpoint."""
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=3)
            if resp.status_code in [200, 201, 202]:
                return "SUCCESS"
            else:
                return f"FAILED_HTTP_{resp.status_code}"
        except Exception as e:
            logger.warning(f"Webhook dispatch failed: {e}")
            return "FAILED_EXCEPTION"
