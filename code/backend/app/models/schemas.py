from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="IP o hostname a escanear")
    enrich_cve: bool = Field(True, description="Consultar CVEs en NVD y base local")
    osint: bool = Field(True, description="OSINT pasivo (web, reverse DNS)")
    full_pipeline: bool = Field(
        False,
        description="Si true, ejecuta recon + ataque en una sola petición (legacy)",
    )
    ai_analyze: bool = Field(False, description="Solo usado con full_pipeline")


class AttackRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado de /api/scan (fase pasiva)")
    ai_analyze: bool = Field(True, description="Análisis IA tras el ataque")


class AnalyzeRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado previo de un escaneo")


class ReportRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado completo del escaneo")
    auditor: str = Field("", description="Nombre del auditor (opcional)")
    format: str = Field("docx", description="docx o html")
