import io
import re
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.core.config import REPORT_AUDITOR_NAME
from app.models.schemas import AnalyzeRequest, ReportRequest, ScanRequest
from app.services.ai_advisor import suggest_attack_vectors
from app.services.report_generator import generate_audit_report
from app.services.report_html import generate_audit_report_html
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
            "audit_report_docx",
            "audit_report_html",
            "auto_step_screenshots",
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


@router.post("/report")
def report_endpoint(data: ReportRequest):
    try:
        scan_data = data.scan_data
        if not scan_data.get("exploitation", {}).get("flag_captured"):
            return {
                "error": "Informe disponible solo cuando se ha capturado una flag.",
            }

        auditor = data.auditor.strip() or REPORT_AUDITOR_NAME
        target = scan_data.get("target", "objetivo")
        safe_target = re.sub(r"[^\w.\-]", "_", str(target))
        date_tag = datetime.now().strftime("%Y%m%d")
        fmt = (data.format or "docx").lower().strip()

        if fmt == "html":
            html_content = generate_audit_report_html(scan_data, auditor=auditor)
            filename = f"informe_pentest_{safe_target}_{date_tag}.html"
            return StreamingResponse(
                io.BytesIO(html_content.encode("utf-8")),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        docx_bytes = generate_audit_report(scan_data, auditor=auditor)
        filename = f"informe_pentest_{safe_target}_{date_tag}.docx"
        return StreamingResponse(
            io.BytesIO(docx_bytes),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        return {"error": str(exc)}
