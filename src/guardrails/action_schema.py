from dataclasses import dataclass, field
from typing import Optional, Set

# Allowed autonomous actions
ALLOWED_ACTIONS: Set[str] = {
    "RESTART_POD",
    "SCALE_DEPLOYMENT",
    "CILIUM_QUARANTINE_EBPF",
    "UNQUARANTINE_POD",
    "ESCALATE"
}

# Catastrophic actions blocklist - NEVER allowed autonomously
CATASTROPHIC_BLOCKLIST: Set[str] = {
    "DELETE_NAMESPACE",
    "DELETE_NODE",
    "PURGE_STORAGE",
    "FLUSH_CLUSTER",
    "DISABLE_SECURITY_LOGGING"
}

# Non-linear State Machine Pipeline states (arXiv:2506.02490 StateGraph RCA)
STATE_ALERT_FIRED = "STATE_ALERT_FIRED"
STATE_EVIDENCE_FETCHED = "STATE_EVIDENCE_FETCHED"
STATE_LLM_DIAGNOSED = "STATE_LLM_DIAGNOSED"
STATE_GUARDRAIL_CHK = "STATE_GUARDRAIL_CHK"
STATE_GUARDRAIL_APPROVED = "STATE_GUARDRAIL_APPROVED"
STATE_ACTION_REJECTED = "STATE_ACTION_REJECTED"
STATE_ESCALATE_HUMAN = "STATE_ESCALATE_HUMAN"

@dataclass
class GuardrailDecision:
    """
    Data model for the validated Guardrail Decision.
    """
    approved: bool
    final_action: str
    state: str
    reason: str
    confidence: float
    original_action: str
    target_pod: str
    problem_type: str
    mitre_technique: Optional[str] = None
    rate_limit_exceeded: bool = False
