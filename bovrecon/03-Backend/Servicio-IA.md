# Servicio IA (vectores de ataque)

#recontool #backend #ia #llm

Relacionado: [[Configuracion-env]] · [[Pipeline-de-escaneo]] · [[../07-Futuro/Auditoria-y-trazabilidad-IA]]

---

## Archivo

`code/backend/app/services/ai_advisor.py`

---

## Función principal

`suggest_attack_vectors(scan_payload: dict) -> dict`

Recibe el JSON completo del escaneo (puertos, OS, CVEs) y devuelve:

```json
{
  "enabled": true,
  "provider": "openai" | "ollama",
  "model": "gpt-4o-mini",
  "analysis": {
    "summary": "...",
    "vectors": [...],
    "next_steps": [...]
  }
}
```

Si falla o no hay proveedor:

```json
{ "enabled": false, "message": "..." }
```

---

## Selección de proveedor (`AI_PROVIDER`)

| Valor | Comportamiento |
|-------|----------------|
| `auto` | OpenAI si hay `OPENAI_API_KEY`; si no, Ollama |
| `openai` | Fuerza OpenAI |
| `ollama` | Fuerza Ollama |
| `none` | Desactiva IA |

---

## OpenAI

- Endpoint: `{OPENAI_BASE_URL}/chat/completions`
- Modelo: `OPENAI_MODEL` (default `gpt-4o-mini`)
- `response_format: json_object`
- Timeout: 120 s

---

## Ollama

- Endpoint: `{OLLAMA_BASE_URL}/api/chat`
- Modelo: `OLLAMA_MODEL` (default `llama3.2`)
- `format: json`
- Timeout: 180 s
- Requiere: `ollama serve` y modelo descargado (`ollama pull llama3.2`)

---

## Prompt del sistema

Instruye al modelo a:

- Actuar en **labs autorizados**.
- No inventar puertos/servicios.
- Responder **solo JSON** con `summary`, `vectors`, `next_steps`.

El JSON del scan se envía como mensaje `user` completo.

---

## Parsing de respuesta

`_extract_json()` intenta `json.loads` directo; si falla, extrae el primer `{...}` con regex.

---

## Limitaciones actuales (importante)

| Limitación | Detalle |
|------------|---------|
| **Caja negra** | No se exponen pasos intermedios del razonamiento |
| **Sin tools** | La IA no ejecuta nmap ni otras herramientas |
| **Alucinaciones** | Puede sugerir vectores incorrectos; validar manualmente |
| **Coste/latencia** | OpenAI es de pago; Ollama depende de GPU/RAM |

La visibilidad de pasos está planificada en [[../07-Futuro/Auditoria-y-trazabilidad-IA]].

---

## Probar sin escaneo

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d "{\"scan_data\": { ... }}"
```

---

## Enlaces

- [[Configuracion-env]]
- [[../04-Frontend/Pantallas-UI#Panel IA]]
