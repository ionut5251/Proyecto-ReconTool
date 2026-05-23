# Flujo de datos

#recontool #arquitectura #flujo

Relacionado: [[Arquitectura-general]] · [[../03-Backend/API]] · [[../03-Backend/Pipeline-de-escaneo]]

---

## Flujo principal (usuario escanea una IP)

```mermaid
sequenceDiagram
    participant U as Usuario
    participant F as Frontend
    participant A as API /scan
    participant P as scan_pipeline
    participant N as nmap
    participant C as CVE (local+NVD)
    participant I as ai_advisor

    U->>F: Introduce IP en index.html
    F->>F: Redirige a results.html?target=IP
    F->>A: POST /api/scan {target, enrich_cve, ai_analyze}
    A->>P: run_full_scan()
    P->>N: scan_target()
    N-->>P: {target, results[], os[]}
    P->>C: enrich_scan_with_cves()
    C-->>P: results[] + cve_findings[]
    P->>I: suggest_attack_vectors()
    I-->>P: ai_analysis{}
    P-->>A: JSON completo
    A-->>F: Respuesta
    F->>U: Tabla puertos + panel vectores IA
```

---

## Estructura JSON de respuesta (`POST /api/scan`)

```json
{
  "target": "10.10.x.x",
  "results": [
    {
      "host": "10.10.x.x",
      "port": 80,
      "state": "open",
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.7",
      "extra_info": "",
      "vulnerability": { "cve": "...", "cvss": 10.0, "severity": "Critical", "description": "..." },
      "cve_findings": [
        { "cve": "CVE-....", "cvss": 9.8, "severity": "CRITICAL", "description": "...", "source": "nvd" }
      ]
    }
  ],
  "os": [
    { "name": "Linux 3.x", "accuracy": "90" }
  ],
  "ai_analysis": {
    "enabled": true,
    "provider": "ollama",
    "model": "llama3.2",
    "analysis": {
      "summary": "...",
      "vectors": [ { "title": "...", "priority": "high", "rationale": "...", "suggested_checks": [], "related_ports": [80] } ],
      "next_steps": ["..."]
    }
  }
}
```

En error de nmap: `{ "error": "mensaje" }` sin el resto de campos.

---

## Flujos alternativos

### Solo enriquecer CVE (sin re-escanear)

`POST /api/enrich` con body `{ "scan_data": { ... resultado previo ... } }`

Útil si guardas JSON y quieres actualizar CVEs sin repetir nmap.

### Solo IA (sin re-escanear)

`POST /api/analyze` con el mismo body.

Útil para probar prompts o modelos sin esperar nmap.

---

## Caché y rate limits

| Recurso | Comportamiento |
|---------|----------------|
| NVD | Caché en memoria por keyword; delay ~6.2s sin API key |
| nmap | Sin caché; cada scan es completo |
| IA | Sin caché; cada llamada envía JSON completo del scan |

---

## Datos que NO persisten (v0.1)

- No hay historial en disco.
- No hay sesiones de usuario.
- `.env` no se commitea (solo `.env.example`).

Futuro: [[../07-Futuro/Auditoria-y-trazabilidad-IA]].

---

## Enlaces

- [[../03-Backend/Servicio-nmap]]
- [[../03-Backend/Servicio-CVE-NVD]]
- [[../03-Backend/Servicio-IA]]
