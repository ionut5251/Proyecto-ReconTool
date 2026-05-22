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

SYSTEM_PROMPT = """Eres un asistente de red team para laboratorios autorizados (HTB, prácticas universitarias, VMs propias).
Analiza resultados de nmap y CVEs. Sugiere vectores de ataque priorizados y comprobaciones manuales seguras.
No inventes puertos ni servicios que no estén en los datos.
Responde ÚNICAMENTE con JSON válido (sin markdown) con esta forma:
{
  "summary": "resumen breve en español",
  "vectors": [
    {
      "title": "nombre del vector",
      "priority": "high|medium|low",
      "rationale": "por qué aplica",
      "suggested_checks": ["comando o paso 1", "paso 2"],
      "related_ports": [80]
    }
  ],
  "next_steps": ["paso 1", "paso 2"]
}
"""


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
        pass

    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group())
    raise ValueError("La IA no devolvió JSON válido")


def _call_openai(scan_payload: dict) -> dict:
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY no configurada")

    url = f"{OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    body = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(scan_payload, ensure_ascii=False, indent=2),
            },
        ],
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    with httpx.Client(timeout=120.0) as client:
        response = client.post(url, json=body, headers=headers)
        response.raise_for_status()
        data = response.json()

    content = data["choices"][0]["message"]["content"]
    return _extract_json(content)


def _call_ollama(scan_payload: dict) -> dict:
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
    body = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(scan_payload, ensure_ascii=False, indent=2),
            },
        ],
    }

    with httpx.Client(timeout=180.0) as client:
        response = client.post(url, json=body)
        response.raise_for_status()
        data = response.json()

    content = data.get("message", {}).get("content", "")
    return _extract_json(content)


def suggest_attack_vectors(scan_payload: dict) -> dict[str, Any]:
    provider = _resolve_provider()

    if not provider:
        return {
            "enabled": False,
            "message": (
                "IA desactivada. Configura OPENAI_API_KEY o OLLAMA_BASE_URL en .env "
                "(AI_PROVIDER=openai|ollama|auto)."
            ),
        }

    try:
        if provider == "openai":
            analysis = _call_openai(scan_payload)
        else:
            analysis = _call_ollama(scan_payload)

        return {
            "enabled": True,
            "provider": provider,
            "model": OPENAI_MODEL if provider == "openai" else OLLAMA_MODEL,
            "analysis": analysis,
        }
    except Exception as exc:
        return {
            "enabled": False,
            "provider": provider,
            "message": f"No se pudo generar análisis IA: {exc}",
        }
