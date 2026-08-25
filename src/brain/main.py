import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from src.brain.diagnostic_engine import DiagnosticEngine
from src.guardrails.validator import GuardrailEngine
from src.controller.executor import ActionExecutor
from src.controller.api import router as controller_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis-brain-api")

app = FastAPI(
    title="Aegis-SRE Diagnostic AI Brain, Guardrail & Controller API",
    description="Phases 3, 4 & 5 AI Brain Engine providing automated diagnosis, safety guardrails, and eBPF action execution",
    version="1.2.0"
)

app.include_router(controller_router)

diagnostic_engine = DiagnosticEngine()
guardrail_engine = GuardrailEngine()
action_executor = ActionExecutor(dry_run_mode=True)

class IncidentRequest(BaseModel):
    pod_name: Optional[str] = "aegis-storefront-prod"
    alert_type: Optional[str] = "HTTP_500_SPIKE"

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "aegis-ai-brain-controller",
        "version": "1.2.0",
        "rag_docs_indexed": len(diagnostic_engine.rag.documents),
        "phases_active": ["Phase 3: Diagnostic Brain", "Phase 4: Guardrails", "Phase 5: Action Muscle"]
    }

@app.post("/api/v1/diagnose")
async def diagnose_incident(req: IncidentRequest):
    """
    Triggers automated AI investigation for an incident and returns JSON Diagnostic Verdict.
    """
    try:
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=req.pod_name,
            alert_type=req.alert_type
        )
        return verdict
    except Exception as e:
        logger.error(f"Error during AI diagnosis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/remediate")
async def remediate_incident(req: IncidentRequest):
    """
    Complete End-to-End Autonomous Pipeline (Phases 3 -> 4 -> 5):
    1. AI Brain Diagnoses Incident (LLM + RAG)
    2. Guardrail Engine Validates Safety & Rate Limits
    3. Action Muscle Executes K8s Action / Cilium eBPF Quarantine
    """
    try:
        # Step 1 & 2: AI Brain Diagnosis & Guardrail Validation
        verdict = diagnostic_engine.diagnose_incident(
            pod_name=req.pod_name,
            alert_type=req.alert_type
        )
        decision = verdict.get("decision_object")
        
        # Step 3: Action Muscle Execution
        exec_result = action_executor.execute_decision(decision)

        # Prepare clean JSON response without unserializable object
        verdict_clean = {k: v for k, v in verdict.items() if k != "decision_object"}

        return {
            "pipeline_status": "COMPLETED",
            "verdict": verdict_clean,
            "guardrail_decision": {
                "approved": decision.approved,
                "final_action": decision.final_action,
                "state": decision.state,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "mitre_technique": decision.mitre_technique
            },
            "execution_result": exec_result.to_dict()
        }
    except Exception as e:
        logger.error(f"Error during autonomous remediation pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

