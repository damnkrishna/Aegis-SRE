import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any

from src.guardrails.action_schema import GuardrailDecision
from src.controller.executor import ActionExecutor, ActionExecutionResult

logger = logging.getLogger("aegis-controller-api")

router = APIRouter(prefix="/api/v1/controller", tags=["Action Muscle Controller"])
executor = ActionExecutor(dry_run_mode=True)


class DecisionExecutionRequest(BaseModel):
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


@router.get("/health")
async def controller_health():
    return {
        "status": "healthy",
        "service": "aegis-action-muscle-controller",
        "dry_run_mode": executor.dry_run_mode,
        "supported_actions": [
            "RESTART_POD",
            "SCALE_DEPLOYMENT",
            "CILIUM_QUARANTINE_EBPF",
            "UNQUARANTINE_POD",
            "ESCALATE"
        ]
    }


@router.post("/execute", response_model=Dict[str, Any])
async def execute_guardrail_decision(req: DecisionExecutionRequest):
    """
    Receives validated GuardrailDecision payload and dispatches cluster action execution.
    """
    try:
        decision = GuardrailDecision(
            approved=req.approved,
            final_action=req.final_action,
            state=req.state,
            reason=req.reason,
            confidence=req.confidence,
            original_action=req.original_action,
            target_pod=req.target_pod,
            problem_type=req.problem_type,
            mitre_technique=req.mitre_technique,
            rate_limit_exceeded=req.rate_limit_exceeded
        )

        result: ActionExecutionResult = executor.execute_decision(decision)
        return {
            "execution_status": "SUCCESS" if result.success else "FAILED",
            "result": result.to_dict()
        }
    except Exception as e:
        logger.error(f"Error executing controller action: {e}")
        raise HTTPException(status_code=500, detail=str(e))
