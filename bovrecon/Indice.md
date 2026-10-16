# ReconTool — Índice maestro (bóveda bovrecon)

> **Punto de entrada** para humanos e IA. Toda la lógica del proyecto vive aquí enlazada como una red de notas.

#recontool #indice #moc

---

## Qué es este repositorio

**ReconTool** es un pentester automatizado en desarrollo (Máster Ciberseguridad + IA): reconocimiento tipo Shodan casero, CVEs y sugerencia de vectores con IA. Objetivo a largo plazo: apoyo en labs autorizados (HTB, VMs propias) hacia obtención de flags, con auditoría documentada.

> **Fases.** **Fase 1** = web FastAPI + UI dos fases + informe Word (entregada, ver [[01-Proyecto/Entrega-v1-estado]]). **Fase 2** = herramienta tipo ADScan: instalable en el equipo y guiada por terminal (en curso, ver [[01-Proyecto/Fase2-CLI-e-instalador]]).

- Repositorio Git: `https://github.com/ionut5251/Proyecto-ReconTool.git`
- Código: carpeta `code/`
- Documentación viva: **esta bóveda** (`bovrecon/`)

---

## Mapa rápido

| Área | Nota principal |
|------|----------------|
| Visión y objetivos | [[01-Proyecto/Vision-y-objetivos]] |
| Roadmap y fases | [[01-Proyecto/Roadmap]] |
| **Estado entrega v1 (Fase 1)** | [[01-Proyecto/Entrega-v1-estado]] |
| **Informe Práctica 1 (Word)** | [[01-Proyecto/Entrega-practica1-informe]] |
| **🆕 Fase 2 — CLI e instalador** | [[01-Proyecto/Fase2-CLI-e-instalador]] |
| **🆕 Changelog P1 → P3** | [[01-Proyecto/Changelog-P1-a-P3]] |
| Arquitectura | [[02-Arquitectura/Arquitectura-general]] |
| Flujo scan → CVE → IA | [[02-Arquitectura/Flujo-de-datos]] |
| Árbol de archivos | [[02-Arquitectura/Mapa-del-repositorio]] |
| Backend | [[03-Backend/Backend-overview]] |
| API REST | [[03-Backend/API]] |
| **🆕 CLI `recon` (Fase 2)** | [[03-Backend/CLI-recon]] |
| **🆕 Sesiones efímeras (Fase 2)** | [[03-Backend/Sesiones-efimeras]] |
| FTP auto-exploit (Fawn) | [[03-Backend/Servicio-FTP-exploit]] |
| Telnet auto-exploit (Meow) | [[03-Backend/Servicio-Telnet-exploit]] |
| SMB auto-exploit | [[03-Backend/Servicio-SMB-exploit]] |
| IA operativa (vector) | `ai_operational.py` |
| Flujo pasivo / activo | [[03-Backend/Pipeline-de-escaneo]] |
| Informe Word | [[03-Backend/Servicio-informe-Word]] |
| Capturas automáticas | [[03-Backend/Servicio-capturas-automaticas]] |
| Frontend UI | [[04-Frontend/Frontend-overview]] |
| Instalar y ejecutar | [[05-Operaciones/Instalacion-y-ejecucion]] |
| **🆕 Instalador Linux (Fase 2)** | [[05-Operaciones/Instalador-Linux]] |
| Probar en Kali | [[05-Operaciones/Despliegue-Kali]] |
| Git y commits | [[05-Operaciones/Git-y-flujo-de-trabajo]] |
| Qué tocar / qué no | [[06-Reglas/Que-tocar-y-que-no]] |
| Actualizar docs | [[06-Reglas/Mantenimiento-documentacion]] |
| Futuro: trazas IA + Word | [[07-Futuro/Auditoria-y-trazabilidad-IA]] |
| **🔮 Futuro: memoria IA + biblioteca de comandos** | [[07-Futuro/Memoria-IA-y-biblioteca-comandos]] |

---

## Estado actual (snapshot)

### Fase 1 — web (entregada)

| Componente | Estado |
|------------|--------|
| Escaneo nmap | ✅ Operativo |
| Base CVE local | ✅ `data/vulnerabilities.json` |
| Consulta NVD | ✅ Con rate-limit |
| IA vectores | ✅ OpenAI / Ollama vía `.env` |
| **FTP anónimo + flag (Fawn)** | ✅ `ftp_probe.py` |
| **Telnet root vacío + flag (Meow)** | ✅ `telnet_probe.py` |
| **SMB anónimo + flag** | ✅ `smb_probe.py` |
| **IA operativa (elección vector)** | ✅ `ai_operational.py` |
| **UI dos fases (OSINT → ataque)** | ✅ `results.html` + `/api/attack` |
| **Informe Word (.docx)** | ✅ |
| **Informe HTML (Kali)** | ✅ Firefox |
| **Capturas auto por paso** | ✅ Pillow |
| Comando `./recontool` (web) | ✅ Arranque automático Kali |
| Frontend estilo Shodan | ✅ `index.html` + `results.html` |

### Fase 2 — CLI tipo ADScan (en curso)

| Componente | Estado |
|------------|--------|
| **Instalador Linux** `install.sh` / `uninstall.sh` | ✅ [[05-Operaciones/Instalador-Linux]] |
| **Comando `recon`** (instala en `/usr/local/bin`) | ✅ |
| **CLI guiado interactivo** `app/cli/` | ✅ [[03-Backend/CLI-recon]] |
| **Sesiones efímeras** (borrón y cuenta nueva) | ✅ [[03-Backend/Sesiones-efimeras]] |
| **Transcripción `.md`** (comandos + hallazgos) | ✅ |
| Fuzzing web automático en informe | ⏳ Guiado por ahora |
| Cotejo con PDF del enunciado | ⏳ PDF pendiente de revisar |

Última actualización: **inicio de Fase 2 — instalador + CLI de sesión efímera**.

---

## Para una IA que retoma el proyecto

1. Leer [[01-Proyecto/Vision-y-objetivos]] y [[06-Reglas/Que-tocar-y-que-no]].
2. Revisar [[02-Arquitectura/Flujo-de-datos]] y [[03-Backend/API]].
3. Para la Fase 2: [[01-Proyecto/Fase2-CLI-e-instalador]], [[03-Backend/CLI-recon]] y [[03-Backend/Sesiones-efimeras]].
4. Consultar [[01-Proyecto/Roadmap]] antes de implementar features nuevas.
5. Tras cualquier cambio de código: [[06-Reglas/Mantenimiento-documentacion]].

---

## Estructura de la bóveda

```
bovrecon/
├── Indice.md                    ← estás aquí
├── 01-Proyecto/
├── 02-Arquitectura/
├── 03-Backend/
├── 04-Frontend/
├── 05-Operaciones/
├── 06-Reglas/
└── 07-Futuro/
```

---

## Enlaces relacionados

- [[Bienvenido]] — nota inicial de Obsidian (redirige aquí)
- [[06-Reglas/Convenciones-de-codigo]]
- [[03-Backend/Configuracion-env]]
