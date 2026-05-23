from fastapi import APIRouter

from app.models.schemas import AnalyzeRequest, ScanRequest
from app.services.ai_advisor import suggest_attack_vectors
from app.services.scan_pipeline import enrich_scan_with_cves, run_full_scan

router = APIRouter()


@router.get("/")
def home():
    return {
        "message": "ReconTool API running",
        "features": [
            "nmap_scan",
            "nvd_cve_lookup",
            "ai_attack_vectors",
            "auto_exploit_ftp",
        ],
    }


@router.post("/scan")
def scan_endpoint(data: ScanRequest):
    try:
        return run_full_scan(
            data.target,
            enrich_cve=data.enrich_cve,
            ai_analyze=data.ai_analyze,
            auto_exploit=data.auto_exploit,
        )
    except Exception as exc:
        return {"target": data.target, "error": str(exc), "pipeline_log": []}


@router.post("/analyze")
def analyze_endpoint(data: AnalyzeRequest):
    try:
        return {"ai_analysis": suggest_attack_vectors(data.scan_data)}
    except Exception as exc:
        return {"error": str(exc)}


@router.post("/enrich")
def enrich_endpoint(data: AnalyzeRequest):
    try:
        return enrich_scan_with_cves(data.scan_data)
    except Exception as exc:
        return {"error": str(exc)}
