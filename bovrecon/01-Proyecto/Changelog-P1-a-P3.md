# Changelog — de la Práctica 1 a la Práctica 3

#recontool #proyecto #changelog #fase2

Relacionado: [[../Indice|Índice]] · [[Fase2-CLI-e-instalador]] · [[Entrega-v1-estado|Fase 1 — estado]] · [[Roadmap]]

---

> Nota para la **memoria (apartado "Punto de partida")**: aquí se registran, estilo
> changelog, los aspectos **mejorados respecto a la Práctica 1**. Formato: `Añadido`
> / `Cambiado` / `Pendiente`.

---

## Punto de partida — Práctica 1 (Fase 1)

Lo que ya existía y se entregó:

- Aplicación **web** (FastAPI + frontend estilo Shodan, UI en dos fases pasiva/activa).
- Pipeline **nmap → CVE (local + NVD) → OSINT → IA/heurística → explotación**.
- Módulos de explotación automática: FTP anónimo, Telnet root vacío, SMB anónimo.
- **Informe Word (.docx) y HTML** con capturas automáticas.
- Arranque con `./recontool` (levanta el servidor web).

---

## Práctica 3 (Fase 2) — mejoras

### Añadido

- **Instalador Linux** (`install.sh` / `uninstall.sh`): instala dependencias del
  sistema, copia a `/opt/recontool` con venv propio y deja el comando `recon`. → [[../05-Operaciones/Instalador-Linux]]
- **Comando `recon`** y **CLI guiado interactivo** (`app/cli/`). → [[../03-Backend/CLI-recon]]
- **Sesiones efímeras** ("borrón y cuenta nueva", sin cuentas ni BD). → [[../03-Backend/Sesiones-efimeras]]
- **Transcripción `.md`** del informe con los **comandos usados** e info obtenida.
- **FTP enriquecido**: listado completo del árbol, descarga de ficheros interesantes,
  detección de **hashes / claves privadas / credenciales** y **recomendaciones** de
  escalada (john, ssh…). En flag.txt el hex de 32 se trata como flag, no como hash.
- **Botón de finalizar** en el CLI (`¿Finalizar y generar el informe? [S/n]`).
- **Informe por defecto al Escritorio** del usuario (Kali), configurable con `--report-dir`.
- **Pruebas automatizadas** (`tests/` con pytest) y **`.gitignore`** ampliado.
- **README** reescrito con instalación, uso y resultado final.

### Cambiado

- La **interfaz principal** pasa de web a **CLI** tipo ADScan. La web de la Fase 1 se
  mantiene disponible (reutiliza el mismo backend).

### Decisiones de diseño (ver [[Fase2-CLI-e-instalador#Decisiones de diseño — motor IA y herramientas (pendiente de implementar)]])

- Motor IA por defecto: **Ollama local** (gratis, offline, sin secretos). OpenAI opcional.
- Futuro "elige tu IA" (estilo Cursor), incluido Claude vía **API key** (no la suscripción del chat).
- La IA podrá lanzar herramientas locales **con confirmación del usuario** y
  **auto-instalación** bajo demanda (`¿Instalar JohnTheRipper? [s/n]`).

### Pendiente (para cerrar la Práctica 3)

- Triaje de vectores conversacional con IA (núcleo ADScan).
- Ejecución de herramientas por la IA con confirmación.
- Apartado de **seguridad** (STRIDE, gestión de secretos, validación de entradas, deps).
- **Matriz de trazabilidad** de requisitos (cuando esté el vídeo).
- **Memoria** técnica (PDF) y **vídeo** de demostración.

---

## Enlaces

- [[Fase2-CLI-e-instalador]]
- [[Roadmap]]
- [[../Indice|Índice]]
