# Sesiones efímeras (Fase 2)

#recontool #backend #fase2 #sesiones

Relacionado: [[../Indice|Índice]] · [[CLI-recon]] · [[../01-Proyecto/Fase2-CLI-e-instalador]]

---

> **Nueva agregación (Fase 2).** Modelo "borrón y cuenta nueva" implementado en `app/cli/session.py`. Evita base de datos de usuarios y credenciales: cada ejecución es autónoma y no deja estado.

---

## Idea

- La **instalación en el equipo** es la instancia única: no hay login ni cuentas.
- Cada `recon <ip>` crea una **sesión efímera** en un directorio temporal (`/tmp/recontool-XXXX`).
- Dentro de la sesión viven: capturas (`screenshots/`), descargas (`loot/`) y el registro de comandos.
- Al terminar: se entrega el **informe** a una carpeta persistente y la sesión **se destruye** (`shutil.rmtree`).
- Volver a lanzar sobre la misma IP **no recuerda nada**: empieza de cero.

## Clase `ReconSession`

| Miembro | Función |
|---------|---------|
| `dir` / `screenshots` / `loot` | Rutas de la sesión temporal. |
| `scan_data` | Resultado acumulado del pipeline. |
| `commands` | Lista de comandos ejecutados (para la transcripción). |
| `log_command(cmd, note)` | Registra un comando. |
| `cleanup()` | Borra la sesión. |
| context manager | `with ReconSession(target) as s:` garantiza el borrado. |

### Capturas dentro de la sesión

`_redirect_screenshots()` reapunta `SCREENSHOTS_DIR` a la sesión. Como los módulos
ya importados hacen `from app.core.config import SCREENSHOTS_DIR`, se reasigna el
nombre en cada módulo afectado (`config`, `step_capture`, `report_generator`), no
solo en `config`. Así las evidencias no ensucian `data/screenshots/` y se borran
con la sesión.

## Qué sobrevive

Solo lo que se escribe fuera de la sesión (por defecto en el **Escritorio** del usuario real):

- `~/Desktop/informe_pentest_<ip>_<fecha>.docx`
- `~/Desktop/transcripcion_<ip>_<fecha>.md`

El Escritorio se resuelve con `SUDO_USER` (al ejecutarse con sudo) → `Desktop`/`Escritorio`; se puede forzar otra carpeta con `--report-dir`. Los informes se devuelven al usuario real (`SUDO_UID`/`SUDO_GID`).

---

## Enlaces

- [[CLI-recon]]
- [[../01-Proyecto/Fase2-CLI-e-instalador]]
- [[Servicio-capturas-automaticas]]
