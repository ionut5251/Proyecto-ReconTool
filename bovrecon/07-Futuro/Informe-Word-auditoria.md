# Informe Word de auditoría

#recontool #informe #word

Relacionado: [[../03-Backend/Servicio-informe-Word]] · [[Auditoria-y-trazabilidad-IA]] · [[../03-Backend/Servicio-FTP-exploit]]

---

## Estado: ✅ implementado (v0.2)

Al capturar una **flag**, la UI muestra el botón **Descargar informe Word (.docx)**.

---

## Contenido del informe

Estructura inspirada en `informe_pentest.docx` (ejemplo académico):

1. Portada — objetivo, puertos, fecha, riesgo, auditor, clasificación
2. Índice
3. Resumen ejecutivo
4. Metodología y alcance (tabla fases/herramientas)
5. Desarrollo de la auditoría — pasos nmap, CVE, FTP, IA
6. Cronología del pipeline
7. Tabla de vulnerabilidades
8. Recomendaciones
9. Flag obtenida

---

## API

`POST /api/report` con body:

```json
{ "scan_data": { ... resultado de /api/scan ... }, "auditor": "Opcional" }
```

Solo genera informe si `exploitation.flag_captured === true`.

---

## Configuración

En `.env`:

```env
REPORT_AUDITOR_NAME=Tu Nombre — Máster Ciberseguridad
```

---

## Próximas mejoras

- Capturas de pantalla embebidas (`pics/`)
- Plantilla `.docx` personalizable
- Informe parcial sin flag (solo recon)

Ver [[Auditoria-y-trazabilidad-IA]].
