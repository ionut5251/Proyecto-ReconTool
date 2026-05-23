# Futuro: auditoría y trazabilidad de la IA

#recontool #futuro #ia #auditoria

Relacionado: [[Informe-Word-auditoria]] · [[../03-Backend/Servicio-IA]] · [[../01-Proyecto/Roadmap#v0.3 — Observabilidad y auditoría]]

---

## Objetivo (pedido del proyecto)

Poder **ver los distintos pasos** que usa la IA para llegar a las conclusiones, no solo el JSON final. Base para:

- Depuración en Kali.
- Confianza en sugerencias de vectores.
- Informe final de auditoría con evidencias.

---

## Estado actual (v0.1)

| Qué hay | Qué falta |
|---------|-----------|
| Entrada: JSON completo del scan | Log de prompts enviados |
| Salida: `ai_analysis.analysis` | Pasos intermedios / chain-of-thought |
| Proveedor y modelo en respuesta | Timestamp por fase |
| Sin persistencia | Historial de sesiones |

La IA es **caja negra**: una llamada LLM → JSON parseado.

---

## Diseño propuesto (v0.3)

### 1. Logger de fases (`scan_audit`)

Estructura sugerida:

```json
{
  "session_id": "uuid",
  "target": "10.10.x.x",
  "started_at": "ISO-8601",
  "phases": [
    { "name": "nmap", "status": "ok", "duration_ms": 120000, "command": "nmap ...", "artifact": "scan_raw.json" },
    { "name": "nvd", "status": "ok", "keywords": ["Apache 2.4.7"], "duration_ms": 31000 },
    { "name": "ai", "status": "ok", "provider": "ollama", "prompt_hash": "...", "duration_ms": 45000 }
  ]
}
```

Guardar en `code/backend/data/sessions/` (gitignored) o SQLite.

### 2. UI — panel “Pasos del análisis”

En `results.html`:

- Timeline vertical: nmap → CVE → IA.
- Expandir cada fase con detalle (comando, nº CVEs, extracto prompt).
- *No* mostrar API keys.

### 3. IA con pasos explícitos

Opciones técnicas:

| Opción | Pros | Contras |
|--------|------|---------|
| Prompt “piensa paso a paso” en JSON | Simple | No es tool-use real |
| OpenAI function calling / tools | Trazable | Más complejo |
| Agente LangChain/LlamaIndex | Escalable | Nueva dependencia |
| Log de respuesta `reasoning` (modelos o1-style) | Rico | No todos los modelos |

Recomendación inicial: **log de fases del pipeline** + prompt/respuesta IA guardados en archivo + UI timeline.

### 4. API nuevos endpoints (borrador)

- `GET /api/sessions` — listar auditorías.
- `GET /api/sessions/{id}` — detalle con fases.

---

## Integración con informe Word

Los `phases[]` y capturas en `pics/` alimentarán [[Informe-Word-auditoria]].

Flujo: scan → audit JSON → plantilla Word (python-docx) + imágenes.

---

## Orden de implementación sugerido

1. Log en disco de cada `run_full_scan` (sin cambiar IA).
2. Endpoint + UI timeline (fases nmap/NVD/IA).
3. Guardar prompt/response IA completos (opcional, censurado).
4. Refinar agente con tools (v0.4+).

---

## Enlaces

- [[Informe-Word-auditoria]]
- [[../04-Frontend/Frontend-overview]]
- [[../05-Operaciones/Despliegue-Kali]]
