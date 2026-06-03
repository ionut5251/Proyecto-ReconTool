# Pipeline de escaneo

#recontool #backend #pipeline

Relacionado: [[Servicio-nmap]] · [[Servicio-CVE-NVD]] · [[Servicio-FTP-exploit]] · [[Servicio-Telnet-exploit]] · [[../02-Arquitectura/Flujo-de-datos]]

---

## Archivo central

`code/backend/app/services/scan_pipeline.py`

---

## Fase 1 — `run_passive_recon(target)`

1. `scan_target(target)` — nmap
2. `enrich_scan_with_cves(scan_data)` — CVE local + NVD
3. `run_passive_osint(target, scan_data)` — reverse DNS, HTTP probe, notas
4. `detect_attack_vectors(scan_data)` → `attack_plan` (FTP / Telnet / HTTP enum)
5. `build_playbook_analysis()` — vectores sin modelo inventado
6. `exploitation.pending = true` — sin atacar aún

Entrada: `POST /api/scan` (default).

---

## Fase 2 — `run_active_attack(scan_data)`

1. `run_exploitation_checks(target, scan_data)` — **solo** el vector principal
2. IA opcional + merge con playbook
3. Si flag: `capture_all_evidence()` — PNG por paso

Entrada: `POST /api/attack`.

---

## Router de vectores

`service_router.py`:

| Puerto/servicio | ID | Lab |
|-----------------|-----|-----|
| 21 / ftp | `ftp_anonymous` | FTP anónimo |
| 23 / telnet | `telnet_root_blank` | Telnet root |
| 445 / 139 smb | `smb_anonymous` | SMB shares |
| 80/443/… | `http_enum` | (futuro) |

`ai_operational.py` elige módulo si hay varios puertos; si no hay IA, prioridad heurística.

`exploit_runner.py` no ejecuta todos los módulos; elige uno según `attack_plan.primary`.

---

## Compatibilidad — `run_full_scan()`

Pasivo + activo en una llamada (`full_pipeline: true` en API).

---

## Pseudocódigo

```
function passive(target):
    data = nmap.scan(target)
    data = cve.enrich(data)
    data.osint = osint.run(target, data)
    data.attack_plan = router.detect(data)
    data.ai_analysis = playbook.build(data)
    return data

function active(scan_data):
    scan_data.exploitation = exploit.run(scan_data)
    scan_data.ai_analysis = ai.or_playbook(scan_data)
    if flag: evidence.capture(scan_data)
    return scan_data
```
