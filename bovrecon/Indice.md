# ReconTool — Índice maestro (bóveda bovrecon)

> **Punto de entrada** para humanos e IA. Toda la lógica del proyecto vive aquí enlazada como una red de notas.

#recontool #indice #moc

---

## Qué es este repositorio

**ReconTool** es un pentester automatizado en desarrollo (Máster Ciberseguridad + IA): reconocimiento tipo Shodan casero, CVEs y sugerencia de vectores con IA. Objetivo a largo plazo: apoyo en labs autorizados (HTB, VMs propias) hacia obtención de flags, con auditoría documentada.

- Repositorio Git: `https://github.com/ionut5251/Proyecto-ReconTool.git`
- Código: carpeta `code/`
- Documentación viva: **esta bóveda** (`bovrecon/`)

---

## Mapa rápido

| Área | Nota principal |
|------|----------------|
| Visión y objetivos | [[01-Proyecto/Vision-y-objetivos]] |
| Roadmap y fases | [[01-Proyecto/Roadmap]] |
| Arquitectura | [[02-Arquitectura/Arquitectura-general]] |
| Flujo scan → CVE → IA | [[02-Arquitectura/Flujo-de-datos]] |
| Árbol de archivos | [[02-Arquitectura/Mapa-del-repositorio]] |
| Backend | [[03-Backend/Backend-overview]] |
| API REST | [[03-Backend/API]] |
| FTP auto-exploit (Fawn) | [[03-Backend/Servicio-FTP-exploit]] |
| Informe Word | [[03-Backend/Servicio-informe-Word]] |
| Frontend UI | [[04-Frontend/Frontend-overview]] |
| Instalar y ejecutar | [[05-Operaciones/Instalacion-y-ejecucion]] |
| Probar en Kali | [[05-Operaciones/Despliegue-Kali]] |
| Git y commits | [[05-Operaciones/Git-y-flujo-de-trabajo]] |
| Qué tocar / qué no | [[06-Reglas/Que-tocar-y-que-no]] |
| Actualizar docs | [[06-Reglas/Mantenimiento-documentacion]] |
| Futuro: trazas IA + Word | [[07-Futuro/Auditoria-y-trazabilidad-IA]] |

---

## Estado actual (snapshot)

| Componente | Estado |
|------------|--------|
| Escaneo nmap | ✅ Operativo |
| Base CVE local | ✅ `data/vulnerabilities.json` |
| Consulta NVD | ✅ Con rate-limit |
| IA vectores | ✅ OpenAI / Ollama vía `.env` |
| **FTP anónimo + flag (Fawn)** | ✅ `ftp_probe.py` |
| **Informe Word (.docx)** | ✅ Tras capturar flag |
| Frontend estilo Shodan | ✅ `index.html` + `results.html` |
| Trazabilidad pasos IA | ⏳ Planificado — [[07-Futuro/Auditoria-y-trazabilidad-IA]] |
| Informe Word + capturas | ⏳ Planificado — [[07-Futuro/Informe-Word-auditoria]] |
| Pruebas serias en Kali | ⏳ Siguiente fase operativa |

Última reorganización documentada en commit: *frontend Shodan, CVEs NVD e IA de vectores*.

---

## Para una IA que retoma el proyecto

1. Leer [[01-Proyecto/Vision-y-objetivos]] y [[06-Reglas/Que-tocar-y-que-no]].
2. Revisar [[02-Arquitectura/Flujo-de-datos]] y [[03-Backend/API]].
3. Consultar [[01-Proyecto/Roadmap]] antes de implementar features nuevas.
4. Tras cualquier cambio de código: [[06-Reglas/Mantenimiento-documentacion]].

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
