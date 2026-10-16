# Fase 2 — CLI, instalador y sesiones efímeras

#recontool #proyecto #fase2 #cli

Relacionado: [[../Indice|Índice]] · [[Roadmap]] · [[Entrega-v1-estado|Fase 1 — estado]] · [[../05-Operaciones/Instalador-Linux]] · [[../03-Backend/CLI-recon]] · [[../03-Backend/Sesiones-efimeras]]

---

> **Nota de fases.** Lo entregado hasta ahora (web FastAPI + UI dos fases + informe Word) es la **Fase 1** — ver [[Entrega-v1-estado]]. Esta nota recoge la **Fase 2**: convertir ReconTool en una herramienta tipo **ADScan**, instalable en el equipo y guiada por terminal. Cada apartado indica los **cambios realizados / nuevas agregaciones**.

---

## Objetivo de la Fase 2

Que ReconTool se **instale como un programa** del sistema y se use desde terminal:

```bash
sudo ./install.sh        # se instala en /opt/recontool + comando `recon`
recon 10.10.10.1         # recon guiado -> vectores -> informe
```

El CLI reutiliza **todo el backend de la Fase 1** (nmap, CVE, OSINT, módulos FTP/Telnet/SMB, informe). La web sigue disponible; el CLI pasa a ser la interfaz principal.

---

## Nuevas agregaciones (Fase 2 — iteración 1)

| Componente | Archivo(s) | Estado |
|------------|-----------|--------|
| Instalador Linux | `install.sh`, `uninstall.sh` (raíz) | ✅ |
| Comando `recon` | `/usr/local/bin/recon` (lo crea el instalador) | ✅ |
| Paquete CLI | `code/backend/app/cli/` | ✅ |
| Sesión efímera | `app/cli/session.py` | ✅ |
| Flujo interactivo guiado | `app/cli/runner.py` | ✅ |
| UI de terminal (colores/prompts) | `app/cli/ui.py` | ✅ |
| Transcripción de sesión (.md) | `app/cli/transcript.py` | ✅ |
| Entrypoint `recon` | `app/cli/main.py` | ✅ |

Ver detalle en [[../05-Operaciones/Instalador-Linux]], [[../03-Backend/CLI-recon]] y [[../03-Backend/Sesiones-efimeras]].

---

## Modelo "borrón y cuenta nueva"

- Sin cuentas ni base de datos de usuarios: cada equipo que instala ReconTool **es** su propia instancia.
- Cada ejecución de `recon` abre una **sesión efímera** en un directorio temporal.
- Al terminar se entrega el **informe** (y una transcripción `.md`) a una carpeta persistente (`./recontool-informes/`) y la sesión **se borra**.
- Volver a escanear la misma IP arranca de cero: el programa no recuerda nada de la ejecución anterior.

Detalle: [[../03-Backend/Sesiones-efimeras]].

---

## Flujo guiado (ejemplo)

1. `recon 10.10.10.1` → recon pasivo (nmap + CVE + OSINT).
2. ReconTool muestra puertos/servicios/SO/CVEs encontrados.
3. Según lo abierto, **recomienda** y pregunta:
   - solo puerto 80 → *"¿lanzo un FUZZ de directorios?"*
   - web + FTP → *"¿FTP anónimo primero o fuzz web? Mi recomendación…"*
4. Ejecuta el vector elegido (reutiliza `ftp_probe` / `telnet_probe` / `smb_probe`; web guiado con `ffuf`/`gobuster` si están instalados).
5. Entrega `informe_pentest_*.docx` + `transcripcion_*.md` con **comandos usados e información conseguida**.
6. Cierra y borra la sesión.

---

## Nuevas agregaciones (Fase 2 — iteración 2: FTP guiado)

Foco en máquinas Linux fáciles con FTP:

- `ftp_probe.enumerate_ftp_anonymous()`: login anónimo, **listado completo del árbol**, descarga de ficheros interesantes al `loot/` de la sesión.
- Clasificación de hallazgos y **recomendaciones de escalada**: hash → `john`/`hashcat` (con modo según `$6$`/`$1$`/`$2y$`…), clave privada → `ssh -i` / `ssh2john`, credenciales → reutilizar en servicios abiertos.
- **Flag** detectada y mostrada por pantalla; en ficheros tipo flag el hex de 32 se trata como flag, no como hash.
- **Botón de finalizar** en el CLI → genera el informe.
- Informe por defecto al **Escritorio** del usuario (en Kali), configurable con `--report-dir`.

> Enunciado: la Práctica 3 ("del prototipo al producto") exige instalable desde cero, flujos completos de principio a fin, apartado de seguridad, pruebas con matriz de trazabilidad, memoria PDF y vídeo. La parte instalable + flujo FTP completo cubre el núcleo "funcional"; el resto (seguridad, pruebas, memoria, vídeo) se irá cerrando paso a paso.

## Pendiente para próximas iteraciones (tras revisar el PDF del enunciado)

- Cotejar requisitos concretos del PDF de la práctica (aún por revisar).
- Fuzzing web automático integrado en el informe `.docx` (ahora es guiado/manual).
- Más módulos por servicio y refinado de las preguntas interactivas.
- Punto 3 completo: empaquetado/publicación y limpieza final del repo.

---

## Enlaces

- [[Roadmap]]
- [[../06-Reglas/Que-tocar-y-que-no]]
- [[../02-Arquitectura/Arquitectura-general]]
