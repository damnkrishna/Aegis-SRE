import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from src.brain.diagnostic_engine import DiagnosticEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis-brain-api")

app = FastAPI(
    title="Aegis-SRE Diagnostic AI Brain API",
    description="Phase 3 AI Brain Engine providing LLM + RAG automated incident diagnosis",
    version="1.0.0"
)

diagnostic_engine = DiagnosticEngine()

class IncidentRequest(BaseModel):
    pod_name: Optional[str] = "aegis-storefront-prod"
    alert_type: Optional[str] = "HTTP_500_SPIKE"

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "aegis-ai-brain",
        "version": "1.0.0",
        "rag_docs_indexed": len(diagnostic_engine.rag.documents)
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
