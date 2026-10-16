# Futuro — Memoria de IA y biblioteca de comandos

#recontool #futuro #ia #memoria

Relacionado: [[../Indice|Índice]] · [[../01-Proyecto/Fase2-CLI-e-instalador]] · [[Auditoria-y-trazabilidad-IA]]

---

> Idea para más adelante (aún no implementado). Dos "cerebros" complementarios que
> harían que ReconTool decida como ADScan y además **aprenda**.

## 1. Memoria de conocimiento (a partir de writeups)

- Alimentar el sistema con **writeups de máquinas Tier 1/2** (y propias).
- De ahí se construye un **árbol de decisión** por servicio/puerto.
- Tras el nmap, la IA cruza los puertos detectados con esa memoria:
  *"han salido 21, 22 y 80; en máquinas parecidas, con 80 suele funcionar esto
  primero; probamos, vemos el resultado y seguimos"*.
- Es la versión "con cerebro" del actual `service_router` (hoy un árbol fijo).

## 2. Memoria de uso / estadística (biblioteca de comandos)

- La propia app **guarda los comandos** que se usan y aprende por **frecuencia**.
- Ejemplo: si en 10/12 máquinas se tiró `gobuster` antes que otra cosa, priorizarlo;
  si cierto **orden** de pasos funciona mejor, subirlo en la recomendación.
- Encaja con lo que ya hacemos: hoy registramos los comandos en la transcripción;
  esto sería "subirlos" a una **biblioteca local** que se va nutriendo.

## Notas de implementación (cuando toque)

- Local y sin cuentas: una carpeta/JSON o **SQLite** como biblioteca; nada de servicios externos.
- Se activa con el **motor de IA** (Ollama local / BYO-model, incl. Claude vía API key).
- Mantener el marco ético: solo labs autorizados.
- Suma para el apartado de IA de la memoria de la Práctica 3.

---

## Carpetas reservadas para el futuro

- **`tools/`** — utilidades de **comprobación e instalación de dependencias**. Al
  instalar en una Kali "virgen", comprobar si ya están `nmap`, `smbclient`, `ffuf`,
  `john`, etc., y si falta alguno **instalarlo pidiendo permiso** al usuario (s/n).
- **`docs/`** — repositorio de **writeups** de máquinas de los que el motor de IA
  sacará patrones de ataque/enumeración (ver la sección 1 de esta nota).
- **`bovrecon/`** — documentación viva (Obsidian). No es imprescindible para
  ejecutar el programa y **no se instala**; vive en el repo como documentación.

---

## Enlaces

- [[../01-Proyecto/Roadmap]]
- [[../01-Proyecto/Fase2-CLI-e-instalador]]
