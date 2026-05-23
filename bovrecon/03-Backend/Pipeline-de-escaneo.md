# Pipeline de escaneo

#recontool #backend #pipeline

Relacionado: [[Servicio-nmap]] · [[Servicio-CVE-NVD]] · [[Servicio-IA]] · [[../02-Arquitectura/Flujo-de-datos]]

---

## Archivo central

`code/backend/app/services/scan_pipeline.py`

---

## Funciones

### `run_full_scan(target, enrich_cve=True, ai_analyze=True)`

1. Llama `scan_target(target)` → datos nmap.
2. Si hay `error` en respuesta, retorna sin más pasos.
3. Si `enrich_cve`: `enrich_scan_with_cves(scan_data)`.
4. Si `ai_analyze`: `suggest_attack_vectors(scan_data)` → clave `ai_analysis`.
5. Si no IA: `ai_analysis = { enabled: false, message: "..." }`.

Punto de entrada desde [[API#POST /api/scan]].

---

### `enrich_scan_with_cves(scan_data)`

Por cada fila en `results`:

1. Construye keyword: `build_search_keyword(product, version, service)`.
2. Busca match exacto en base local (`product + version`).
3. Consulta NVD con `lookup_cves(keyword)`.
4. Fusiona en `cve_findings` sin duplicar CVE IDs (`_merge_cve_findings`).
5. Rellena `vulnerability` con el mejor hallazgo disponible.

---

## Orden de prioridad CVE

1. Entrada **local** (`data/vulnerabilities.json`) — curada para labs.
2. Resultados **NVD** por keyword.
3. Si NVD falla, puede aparecer `{ "error": "...", "source": "nvd" }` en la lista.

---

## Modificar el pipeline

| Cambio | Archivo a editar |
|--------|------------------|
| Añadir paso post-nmap | `scan_pipeline.py` |
| Cambiar orden CVE/IA | `run_full_scan()` |
| Nuevo endpoint parcial | `app/api/routes.py` |

Siempre actualizar [[../02-Arquitectura/Flujo-de-datos]] y [[../06-Reglas/Mantenimiento-documentacion]].

---

## Pseudocódigo

```
function run_full_scan(target):
    data = nmap.scan(target)
    if data.error: return data
    if enrich_cve:
        data = merge_local_and_nvd(data)
    if ai_analyze:
        data.ai_analysis = llm.analyze(data)
    return data
```
