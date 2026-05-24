from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="IP o hostname a escanear")
    enrich_cve: bool = Field(True, description="Consultar CVEs en NVD y base local")
    ai_analyze: bool = Field(True, description="Generar vectores de ataque con IA")
    auto_exploit: bool = Field(
        True,
        description="Probar vectores automáticos (p. ej. FTP anónimo / flag.txt)",
    )


class AnalyzeRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado previo de un escaneo")


class ReportRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado completo del escaneo")
    auditor: str = Field("", description="Nombre del auditor (opcional)")
    format: str = Field(
        "docx",
        description="Formato: docx (Word) o html (Linux/Kali — abrir en Firefox)",
    )
