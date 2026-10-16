# Roadmap

#recontool #roadmap #planificacion

Relacionado: [[Vision-y-objetivos]] · [[Entrega-v1-estado]] · [[Fase2-CLI-e-instalador]] · [[../Indice|Índice]]

---

## Leyenda

| Símbolo | Significado |
|---------|-------------|
| ✅ | Hecho |
| 🔄 | En progreso / parcial |
| ⏳ | Planificado |
| ❌ | Descartado / no prioritario |

---

## v0.1 — Base funcional ✅

| Ítem | Estado | Notas |
|------|--------|-------|
| Backend modular | ✅ | |
| Frontend Shodan-like | ✅ | |
| nmap + CVE + IA | ✅ | |
| Documentación bovrecon | ✅ | |

---

## v1.0 — Primera entrega ✅ (Mayo 2025) — Fase 1

| Ítem | Estado | Notas |
|------|--------|-------|
| Pruebas Kali + HTB Fawn | ✅ | Flag + informe |
| FTP auto-exploit | ✅ | [[../03-Backend/Servicio-FTP-exploit]] |
| Informe Word | ✅ | [[../03-Backend/Servicio-informe-Word]] |
| Capturas en informe (manual) | 🔄 | Carpeta `screenshots/` |
| Comando `./recontool` (web) | ✅ | pip + arranque auto |
| Estado entrega documentado | ✅ | [[Entrega-v1-estado]] |

---

## v1.1 — Segunda entrega web ✅

| Ítem | Estado | Notas |
|------|--------|-------|
| UI dos fases + Telnet | ✅ | Pasivo / activo; sin nombres de box en informes |
| Más módulos por servicio | ✅ | SMB, HTTP |
| **IA operativa (sin playbook fijo)** | ✅ | `ai_operational.py` elige FTP/Telnet/SMB |

---

## v2.0 — Fase 2: CLI tipo ADScan 🔄 (en curso)

> Objetivo: ReconTool **instalable** en el equipo y **guiado por terminal**, con sesiones efímeras. Ver [[Fase2-CLI-e-instalador]].

| Ítem | Estado | Notas |
|------|--------|-------|
| **Instalador Linux** (`install.sh`/`uninstall.sh`) | ✅ | [[../05-Operaciones/Instalador-Linux]] |
| **Comando `recon`** en `/usr/local/bin` | ✅ | Se relanza con sudo |
| **CLI guiado interactivo** (`app/cli/`) | ✅ | [[../03-Backend/CLI-recon]] |
| **Sesiones efímeras** (borrón y cuenta nueva) | ✅ | [[../03-Backend/Sesiones-efimeras]] |
| **Transcripción `.md`** (comandos + hallazgos) | ✅ | Junto al `.docx` |
| Reutilización total del backend Fase 1 | ✅ | No se duplica lógica |
| Fuzzing web automático integrado en informe | ⏳ | Ahora guiado (ffuf/gobuster si están) |
| Cotejar requisitos del **PDF del enunciado** | ⏳ | PDF aún por revisar — se verá paso a paso |
| Punto 3: limpieza final del repo + README | 🔄 | README reescrito; push lo hace el usuario |

---

## v0.3 — Observabilidad ⏳

Ver notas en [[../07-Futuro/Auditoria-y-trazabilidad-IA]].

---

## Enlaces

- [[Entrega-v1-estado]]
- [[Fase2-CLI-e-instalador]]
- [[../06-Reglas/Mantenimiento-documentacion]]
