# Futuro: informe Word de auditoría

#recontool #futuro #informe #word

Relacionado: [[Auditoria-y-trazabilidad-IA]] · [[../01-Proyecto/Vision-y-objetivos]]

---

## Objetivo

Al finalizar un engagement de lab, generar un **documento Word** (.docx) que incluya:

1. Resumen ejecutivo del recon.
2. Tabla de puertos y servicios.
3. CVEs identificados (local + NVD).
4. Vectores sugeridos por IA.
5. **Pasos realizados** con timestamps.
6. **Capturas de pantalla** (UI, terminal, pruebas manuales).

Carpeta prevista para imágenes: `pics/` en la raíz del repo (actualmente vacía).

---

## Estado actual

- No hay generación de documentos.
- `pics/` reservada para assets de informe.
- Datos solo en respuesta HTTP JSON (no persistidos).

---

## Stack propuesto

| Componente | Librería / herramienta |
|------------|------------------------|
| Plantilla Word | `python-docx` |
| Datos | JSON de sesión de auditoría (ver [[Auditoria-y-trazabilidad-IA]]) |
| Imágenes | PNG/JPG en `pics/{session_id}/` |
| Export | Endpoint `POST /api/report` o script CLI |

---

## Estructura del informe (borrador)

1. Portada — ReconTool, target, fecha, autor (alumno).
2. Alcance y autorización — disclaimer lab/HTB.
3. Metodología — nmap flags, fuentes CVE, modelo IA.
4. Hallazgos técnicos — tablas auto-generadas.
5. Análisis IA — vectores y recomendaciones.
6. Cronología — fases del pipeline.
7. Anexos — capturas numeradas.

---

## Flujo de trabajo usuario

1. Completar scan en UI.
2. Subir o auto-guardar capturas en `pics/`.
3. Clic “Exportar informe” → descarga `.docx`.
4. Revisión manual antes de entregar en máster.

---

## Consideraciones

- No incluir secretos (`.env`, API keys) en el Word.
- Censar IPs reales si el informe sale del lab (usar placeholders).
- Versionar plantillas `.docx` opcionales en `docs/templates/` (futuro).

---

## Dependencias roadmap

Bloqueado en parte por [[Auditoria-y-trazabilidad-IA]] (necesita logs de sesión).

Ver [[../01-Proyecto/Roadmap]].

---

## Enlaces

- [[Auditoria-y-trazabilidad-IA]]
- [[../02-Arquitectura/Mapa-del-repositorio#pics]]
