# Roadmap

#recontool #roadmap #planificacion

Relacionado: [[Vision-y-objetivos]] · [[../Indice|Índice]] · [[../07-Futuro/Auditoria-y-trazabilidad-IA]]

---

## Leyenda

| Símbolo | Significado |
|---------|-------------|
| ✅ | Hecho |
| 🔄 | En progreso |
| ⏳ | Planificado |
| ❌ | Descartado / no prioritario |

---

## v0.1 — Base funcional ✅

| Ítem | Estado | Notas |
|------|--------|-------|
| Monolito → módulos backend | ✅ | `app/api`, `app/services`, `app/core` |
| Frontend Shodan-like | ✅ | [[../04-Frontend/Frontend-overview]] |
| nmap `-sS -sV -O --open` | ✅ | [[../03-Backend/Servicio-nmap]] |
| CVE local JSON | ✅ | [[../03-Backend/Servicio-CVE-NVD#Base local]] |
| NVD API 2.0 | ✅ | [[../03-Backend/Servicio-CVE-NVD]] |
| IA OpenAI / Ollama | ✅ | [[../03-Backend/Servicio-IA]] |
| Documentación bovrecon | 🔄 | Esta bóveda |
| Commit + push GitHub | ✅ | Ver [[../05-Operaciones/Git-y-flujo-de-trabajo]] |

---

## v0.2 — Operaciones Kali ⏳

| Ítem | Estado | Notas |
|------|--------|-------|
| `git clone` en Kali | ⏳ | [[../05-Operaciones/Despliegue-Kali]] |
| venv limpio en Kali (no symlink F:) | ⏳ | Evitar venv roto de Windows |
| Pruebas scanme.nmap.org | ⏳ | Objetivo público permitido |
| Prueba máquina HTB easy | ⏳ | Con VPN activa |
| Ajuste flags nmap si hace falta | ⏳ | `-sS` requiere root |
| Ollama local en Kali | ⏳ | `AI_PROVIDER=ollama` |

---

## v0.3 — Observabilidad y auditoría ⏳

| Ítem | Estado | Notas |
|------|--------|-------|
| Log estructurado por fase (nmap, NVD, IA) | ⏳ | [[../07-Futuro/Auditoria-y-trazabilidad-IA]] |
| UI: panel “pasos de la IA” | ⏳ | Mostrar reasoning / tool calls |
| Historial de escaneos en disco | ⏳ | JSON o SQLite |
| Export informe Markdown | ⏳ | Paso previo a Word |
| Export informe Word + imágenes | ⏳ | [[../07-Futuro/Informe-Word-auditoria]] |

---

## v0.4+ — Pentest asistido ⏳

| Ítem | Estado | Notas |
|------|--------|-------|
| Wrappers herramientas (gobuster, enum4linux…) | ⏳ | Solo bajo confirmación |
| Agentes IA con herramientas | ⏳ | Alto riesgo; diseño cuidadoso |
| Modo “solo recon” sin IA | ⏳ | Flag ya existe en API |
| Autenticación API | ⏳ | Si se expone fuera de localhost |

---

## Orden recomendado de trabajo

1. Completar documentación bovrecon (ahora).
2. Kali: instalar, probar, depurar.
3. Trazabilidad IA (v0.3).
4. Informe Word (v0.3–v0.4).

No saltar a explotación automática antes de recon fiable.

---

## Enlaces

- [[Vision-y-objetivos]]
- [[../06-Reglas/Mantenimiento-documentacion]]
