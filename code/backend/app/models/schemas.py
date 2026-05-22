from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="IP o hostname a escanear")
    enrich_cve: bool = Field(True, description="Consultar CVEs en NVD y base local")
    ai_analyze: bool = Field(True, description="Generar vectores de ataque con IA")


class AnalyzeRequest(BaseModel):
    scan_data: dict = Field(..., description="Resultado previo de un escaneo")
