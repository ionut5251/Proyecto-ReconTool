# CLI `recon` (Fase 2)

#recontool #backend #fase2 #cli

Relacionado: [[../Indice|Índice]] · [[../01-Proyecto/Fase2-CLI-e-instalador]] · [[Sesiones-efimeras]] · [[Pipeline-de-escaneo]] · [[Backend-overview]]

---

> **Nueva agregación (Fase 2).** Paquete `code/backend/app/cli/` que añade una interfaz de terminal guiada sobre los servicios existentes. **No** reescribe el backend: lo reutiliza.

---

## Módulos

| Archivo | Responsabilidad |
|---------|-----------------|
| `app/cli/main.py` | Entrypoint `recon` (argparse, flags, avisos). |
| `app/cli/runner.py` | Orquestación interactiva del flujo. |
| `app/cli/session.py` | [[Sesiones-efimeras\|Sesión efímera]] (tempdir, limpieza). |
| `app/cli/ui.py` | Colores ANSI, banner, prompts sí/no y menús. |
| `app/cli/transcript.py` | Transcripción `.md` (comandos usados + hallazgos). |

## Flujo (`runner.run`)

1. Abre una `ReconSession` (ver [[Sesiones-efimeras]]).
2. Recon pasivo: `scan_pipeline.run_passive_recon(target)` → nmap + CVE + OSINT + `attack_plan`.
3. `_show_findings()` imprime puertos, SO, CVEs y web detectada.
4. `_build_options()` + `_recommendation_text()` → menú de vectores con **recomendación** según servicios.
5. Vector elegido:
   - **FTP** → `_run_ftp()` → `ftp_probe.enumerate_ftp_anonymous()`: login anónimo, **lista todo el árbol**, descarga ficheros interesantes al `loot/` de la sesión, detecta la flag y clasifica hallazgos (hash/clave/credencial) con **recomendaciones** (john, ssh…). Ver [[Servicio-FTP-exploit]].
   - Telnet/SMB → `exploit_runner.run_exploitation_checks(target, scan_data, vector_id=…)` con `operational.source = "user"` (la elección del usuario manda; no se llama a la IA operativa).
   - HTTP → `_run_http_enum()`: muestra el playbook y, si hay `ffuf`/`gobuster`/`feroxbuster` + diccionario, ofrece lanzarlo.
6. **Botón de finalizar** (`_finalize_prompt`): una sola pregunta `¿Finalizar y generar el informe? [S/n]`. `s` → cierra y genera el informe; `n` → vuelve a mostrar el menú de vectores a seguir. Por defecto `s` si hubo flag, `n` si no.
7. Informe: `report_generator.generate_audit_report` (.docx) + `transcript.build_transcript` (.md), por defecto al **Escritorio** del usuario real (`_default_report_dir`).
8. Cierre: la sesión se borra.

### Clasificación FTP (helpers puros, testeables)

`classify_filename`, `scan_text_for_secrets` y `build_ftp_recommendations` deciden qué es interesante y qué recomendar. Ojo: en un fichero tipo flag el hex de 32 es la **flag**, no un hash a crackear.

## Reutilización del backend (sin duplicar lógica)

- `app.services.scan_pipeline.run_passive_recon`
- `app.services.service_router.detect_attack_vectors`
- `app.services.exploit_runner.run_exploitation_checks`
- `app.services.playbook_advisor.build_playbook_analysis`
- `app.services.report_generator.generate_audit_report`
- `app.services.step_capture.capture_all_evidence`

Los imports pesados (nmap) son **diferidos** dentro de funciones, para que `recon --help` y `--version` funcionen sin nmap instalado.

## Flags

| Flag | Efecto |
|------|--------|
| `-y`, `--yes` | No interactivo: usa la recomendación. |
| `--no-exploit` | Solo recon. |
| `--report-dir DIR` | Dónde dejar los informes. |
| `--auditor NOMBRE` | Nombre del auditor en el informe. |
| `--no-docx` | Solo transcripción `.md`. |

## Nota sobre privilegios

`recon` instalado se relanza con `sudo` (SYN scan + `-O`). Si se ejecuta el módulo a mano sin root, se avisa de que nmap irá limitado.

---

## Enlaces

- [[../01-Proyecto/Fase2-CLI-e-instalador]]
- [[Sesiones-efimeras]]
- [[Pipeline-de-escaneo]]
