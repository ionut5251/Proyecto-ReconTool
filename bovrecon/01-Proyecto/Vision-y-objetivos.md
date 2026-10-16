# Visión y objetivos del proyecto

#recontool #proyecto #vision

Relacionado: [[../Indice|Índice]] · [[Roadmap]] · [[Fase2-CLI-e-instalador]] · [[../02-Arquitectura/Arquitectura-general]]

---

## Idea central

Construir un **asistente de red team automatizado** que, ante una IP/hostname autorizado:

1. **Reconozca** servicios (nmap, estilo recon Shodan local).
2. **Enriquezca** con vulnerabilidades (base local + NVD).
3. **Sugiera vectores** de ataque mediante IA (solo orientación en lab).
4. **Guíe al usuario** paso a paso y **audite** cada acción con evidencias exportables.

No sustituye el criterio del pentester: acelera recon y priorización en entornos de práctica.

---

## Contexto académico

- Máster de **Ciberseguridad e IA**.
- Práctica alineada con metodología de clase (nmap como herramienta base).
- Uso ético: solo objetivos con **permiso explícito** (HTB, VMs universidad, red propia).

---

## Objetivos por fase

### Fase 1 (v0.1–v1.1) — ✅ entregada

- API FastAPI modular.
- UI web inspirada en Shodan (búsqueda IP → pantalla resultados).
- Pipeline: nmap → CVE → IA → explotación FTP/Telnet/SMB → informe Word.

Ver [[../03-Backend/Pipeline-de-escaneo]] y [[Entrega-v1-estado]].

### Fase 2 (v2.0) — 🔄 en curso — herramienta tipo ADScan

- **Instalable** en el equipo (`install.sh` → comando `recon`), como un programa más.
- **Uso guiado por terminal**: recomienda y pregunta el vector según servicios.
- **Sesiones efímeras**: sin cuentas ni base de datos; borrón y cuenta nueva por ejecución.
- **Informe + transcripción** con comandos usados e información obtenida.

Ver [[Fase2-CLI-e-instalador]], [[../03-Backend/CLI-recon]] y [[../05-Operaciones/Instalador-Linux]].

### Fase futura — producto

- **Trazabilidad**: ver pasos internos de la IA ([[../07-Futuro/Auditoria-y-trazabilidad-IA]]).
- Fuzzing web automático integrado en el informe.
- Automatización progresiva hacia flags en máquinas tipo HackTheBox (siempre en lab).

---

## Qué NO es ReconTool

- No es Shodan ni escanea Internet arbitrariamente.
- Solo actúa contra objetivos con permiso explícito.
- No almacena credenciales ni datos de terceros: las sesiones son efímeras.

---

## Métricas de éxito (personales)

- [x] Escaneo estable en Kali contra máquina HTB easy.
- [x] CVEs relevantes en ≥1 servicio detectado.
- [x] IA/heurística devuelve ≥2 vectores accionables y coherentes con el scan.
- [ ] Fase 2: instalar con `install.sh` y completar un `recon <ip>` guiado con informe.
- [x] Documentación bovrecon permite retomar el proyecto en &lt;30 min sin máquina local.

---

## Referencias internas

- [[Roadmap]]
- [[Fase2-CLI-e-instalador]]
- [[../06-Reglas/Que-tocar-y-que-no]]
- [[../02-Arquitectura/Flujo-de-datos]]
