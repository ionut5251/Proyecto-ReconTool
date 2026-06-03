"""Selección operativa del vector de ataque (IA + heurísticas)."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import httpx

from app.core.config import (
    AI_PROVIDER,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)
from app.services.service_router import detect_attack_vectors

OPERATIONAL_PROMPT = """Eres el motor de decisión ofensiva de ReconTool en auditorías autorizadas.
Recibes resultados de nmap/OSINT y debes elegir UN módulo de explotación automática.

Módulos disponibles (solo si el puerto/servicio aparece en el escaneo):
- telnet_root_blank — Telnet (23): root con contraseña vacía, cat flag.txt
- ftp_anonymous — FTP (21): login anonymous, get flag.txt
- smb_anonymous — SMB (445/139): smbclient -L, recorrer shares/carpetas, buscar flag.txt
- http_enum — HTTP (80/443): enumeración web (sin explotación automática de flag aún)

Reglas:
- Elige el vector con mayor probabilidad de obtener flag según servicios expuestos.
- Si hay SMB (445) con shares accesibles, priorízalo frente a FTP cuando ambos existan.
- No inventes puertos ni servicios.
- No menciones nombres de plataformas de labs.

Responde SOLO JSON válido:
{
  "module_id": "smb_anonymous|ftp_anonymous|telnet_root_blank|http_enum",
  "reason": "breve justificación en español",
  "confidence": "high|medium|low"
}
"""

MODULE_PRIORITY = (
    "telnet_root_blank",
    "smb_anonymous",
    "ftp_anonymous",
    "http_enum",
)


def _open_ports(scan_data: dict) -> set[int]:
    return {
        int(r.get("port", 0))
        for r in scan_data.get("results", [])
        if str(r.get("state", "")).lower() == "open"
    }


def _viable_vectors(scan_data: dict) -> list[dict]:
    plan = scan_data.get("attack_plan") or detect_attack_vectors(scan_data)
    open_ports = _open_ports(scan_data)
    viable: list[dict] = []
    for vec in plan.get("vectors", []):
        port = vec.get("port")
        if port in open_ports:
            viable.append(vec)
        elif vec.get("id") == "smb_anonymous" and open_ports.intersection({445, 139}):
            viable.append(vec)
    return viable


def _fallback_vector(viable: list[dict]) -> dict[str, Any]:
    if not viable:
        return {"vector_id": None, "source": "heuristic", "reason": "Sin vector viable"}
    by_id = {v["id"]: v for v in viable}
    for mid in MODULE_PRIORITY:
        if mid in by_id:
            return {
                "vector_id": mid,
                "source": "heuristic",
                "reason": f"Prioridad heurística: {by_id[mid].get('title', mid)}",
                "confidence": "medium",
            }
    first = viable[0]
    return {
        "vector_id": first["id"],
        "source": "heuristic",
        "reason": first.get("summary", ""),
        "confidence": "low",
    }


def _resolve_provider() -> Optional[str]:
    if AI_PROVIDER == "none":
        return None
    if AI_PROVIDER in ("openai", "ollama"):
        return AI_PROVIDER
    if OPENAI_API_KEY:
        return "openai"
    return "ollama"


def _extract_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group())
    raise ValueError("JSON inválido de IA operativa")


def _ai_pick(scan_data: dict, viable: list[dict]) -> Optional[dict[str, Any]]:
    provider = _resolve_provider()
    if not provider:
        return None

    payload = {
        "target": scan_data.get("target"),
        "open_ports": sorted(_open_ports(scan_data)),
        "services": [
            {
                "port": r.get("port"),
                "service": r.get("service"),
                "product": r.get("product"),
                "version": r.get("version"),
            }
            for r in scan_data.get("results", [])
            if str(r.get("state", "")).lower() == "open"
        ],
        "viable_modules": [{"id": v["id"], "title": v.get("title"), "port": v.get("port")} for v in viable],
    }

    messages = [
        {"role": "system", "content": OPERATIONAL_PROMPT},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
    ]

    try:
        if provider == "openai" and OPENAI_API_KEY:
            url = f"{OPENAI_BASE_URL.rstrip('/')}/chat/completions"
            body = {
                "model": OPENAI_MODEL,
                "temperature": 0.1,
                "messages": messages,
                "response_format": {"type": "json_object"},
            }
            headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
            with httpx.Client(timeout=90.0) as client:
                resp = client.post(url, json=body, headers=headers)
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
        else:
            url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
            body = {"model": OLLAMA_MODEL, "stream": False, "format": "json", "messages": messages}
            with httpx.Client(timeout=120.0) as client:
                resp = client.post(url, json=body)
                resp.raise_for_status()
                content = resp.json().get("message", {}).get("content", "")

        parsed = _extract_json(content)
        module_id = parsed.get("module_id")
        valid_ids = {v["id"] for v in viable}
        if module_id in valid_ids:
            return {
                "vector_id": module_id,
                "source": "ai",
                "reason": parsed.get("reason", ""),
                "confidence": parsed.get("confidence", "medium"),
                "provider": provider,
            }
    except Exception:
        return None
    return None


def resolve_operational_vector(scan_data: dict) -> dict[str, Any]:
    """Elige el módulo de ataque. IA si hay varios vectores; heurística si no."""
    viable = _viable_vectors(scan_data)
    if len(viable) == 1:
        v = viable[0]
        return {
            "vector_id": v["id"],
            "source": "single_port",
            "reason": v.get("summary", ""),
            "confidence": "high",
        }

    ai_choice = _ai_pick(scan_data, viable)
    if ai_choice:
        return ai_choice

    return _fallback_vector(viable)
