import time
import os
import json
import logging
from typing import Dict, List, Tuple

from src.guardrails.action_schema import (
    ALLOWED_ACTIONS,
    CATASTROPHIC_BLOCKLIST,
    GuardrailDecision,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN,
)

logger = logging.getLogger("aegis-guardrail-validator")

class GuardrailEngine:
    """
    Catastrophic Guardrail & Decision Safety Engine (Phase 4).
    Validates LLM-recommended diagnostic actions before execution.
    """
    def __init__(self,
                 min_confidence_threshold: float = 0.70,
                 max_restarts_per_hour: int = 3):
        self.min_confidence_threshold = min_confidence_threshold
        self.max_restarts_per_hour = max_restarts_per_hour
        # Pod restart history tracking: pod_name -> list of timestamps
        self._restart_history: Dict[str, List[float]] = {}

    def validate_verdict(self, raw_verdict: dict) -> GuardrailDecision:
        """
        Validates raw LLM diagnostic verdict against safety rules.
        """
        target_pod = raw_verdict.get("target_pod", "unknown-pod")
        proposed_action = raw_verdict.get("recommended_action", "ESCALATE").upper()
        problem_type = raw_verdict.get("problem_type", "UNKNOWN")
        confidence = float(raw_verdict.get("confidence", 0.85))
        mitre_technique = raw_verdict.get("mitre_technique", None)

        decision = None

        # 1. Catastrophic Blocklist Check
        if proposed_action in CATASTROPHIC_BLOCKLIST:
            logger.warning(f"GUARDRAIL REJECT: Action '{proposed_action}' is on the CATASTROPHIC BLOCKLIST!")
            decision = GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=f"Action '{proposed_action}' is blocked by catastrophic safety filter.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique
            )

        # 2. Unknown Action Check
        elif proposed_action not in ALLOWED_ACTIONS:
            logger.warning(f"GUARDRAIL REJECT: Action '{proposed_action}' is not in allowed action registry.")
            decision = GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=f"Action '{proposed_action}' is not an allowed autonomous action.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique
            )

        # 3. Low Confidence Gate Check
        elif confidence < self.min_confidence_threshold:
            logger.warning(f"GUARDRAIL ESCALATE: Confidence ({confidence:.2f}) below minimum threshold ({self.min_confidence_threshold:.2f}).")
            decision = GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ESCALATE_HUMAN,
                reason=f"Diagnostic confidence ({confidence:.2f}) is below minimum threshold ({self.min_confidence_threshold:.2f}). Human escalation required.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique
            )

        # 4. Restart Loop Rate-Limiter Check
        elif proposed_action == "RESTART_POD" and not self._check_and_record_restart(target_pod)[0]:
            _, count = self._check_and_record_restart(target_pod)
            logger.warning(f"GUARDRAIL REJECT: Pod '{target_pod}' exceeded restart limit in 1 hour.")
            decision = GuardrailDecision(
                approved=False,
                final_action="ESCALATE",
                state=STATE_ACTION_REJECTED,
                reason=f"Pod '{target_pod}' exceeded restart frequency cap. Escalated to prevent restart loop.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique,
                rate_limit_exceeded=True
            )

        # 5. Security Attack Consistency Check
        elif problem_type == "SECURITY_ATTACK" and proposed_action == "RESTART_POD":
            logger.warning(f"GUARDRAIL OVERRIDE: Restarting pod under active security attack is ineffective. Forcing CILIUM_QUARANTINE_EBPF.")
            decision = GuardrailDecision(
                approved=True,
                final_action="CILIUM_QUARANTINE_EBPF",
                state=STATE_GUARDRAIL_APPROVED,
                reason="Overrode RESTART_POD with CILIUM_QUARANTINE_EBPF because incident is categorized as SECURITY_ATTACK.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique
            )

        # 6. Approved Decision
        else:
            logger.info(f"GUARDRAIL APPROVE: Action '{proposed_action}' passed all safety checks for pod '{target_pod}'.")
            decision = GuardrailDecision(
                approved=True,
                final_action=proposed_action,
                state=STATE_GUARDRAIL_APPROVED,
                reason=f"Action '{proposed_action}' passed all safety and rate-limit guardrails.",
                confidence=confidence,
                original_action=proposed_action,
                target_pod=target_pod,
                problem_type=problem_type,
                mitre_technique=mitre_technique
            )

        self._write_audit_log(decision)
        return decision


    def _write_audit_log(self, decision: GuardrailDecision):
        """Appends structured decision trace to logs/guardrail_audit.jsonl for audit compliance."""
        try:
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, "guardrail_audit.jsonl")
            
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "approved": decision.approved,
                "final_action": decision.final_action,
                "original_action": decision.original_action,
                "target_pod": decision.target_pod,
                "problem_type": decision.problem_type,
                "state": decision.state,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "mitre_technique": decision.mitre_technique,
                "rate_limit_exceeded": decision.rate_limit_exceeded
            }
            
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Error writing guardrail audit log: {e}")

    def _check_and_record_restart(self, pod_name: str) -> Tuple[bool, int]:
        """
        Maintains sliding window of restart timestamps for a pod.
        """
        now = time.time()
        one_hour_ago = now - 3600

        timestamps = self._restart_history.get(pod_name, [])
        # Filter timestamps within last 1 hour
        recent_timestamps = [t for t in timestamps if t >= one_hour_ago]

        if len(recent_timestamps) >= self.max_restarts_per_hour:
            self._restart_history[pod_name] = recent_timestamps
            return False, len(recent_timestamps)

        # Record new restart timestamp
        recent_timestamps.append(now)
        self._restart_history[pod_name] = recent_timestamps
        return True, len(recent_timestamps)

    def reset_rate_limits(self):
        """Resets rate limiting history (for testing)."""
        self._restart_history.clear()

