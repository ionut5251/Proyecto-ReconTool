# Informe Word de auditoría

#recontool #informe #word

Relacionado: [[../03-Backend/Servicio-informe-Word]] · [[Auditoria-y-trazabilidad-IA]]

---

## Estado: ✅ implementado (v1) · 🔄 capturas manuales

Al capturar una **flag**, la UI permite **Descargar informe Word (.docx)**.

---

## Evidencias gráficas (importante para el máster y clientes)

El informe del ejemplo académico incluye **fotos en cada paso**. ReconTool v1 soporta esto así:

### Carpeta de capturas

```
code/backend/data/screenshots/<IP>/
├── 01_nmap.png      ← pantallazo escaneo / tabla puertos
├── 02_cve.png       ← CVEs (opcional si aplica)
├── 03_exploit.png   ← FTP / pasos explotación
├── 04_ia.png        ← panel IA (opcional)
└── 99_flag.png      ← flag en pantalla
```

La IP usa formato sanitizado (ej. `10.10.10.123` → carpeta `10.10.10.123`).

### Flujo recomendado

1. Ejecutar scan y hacer capturas durante el proceso (web, terminal, FTP).
2. Guardar PNG en la carpeta anterior **antes** de pulsar descargar informe.
3. Regenerar informe → las imágenes se incrustan con pie "Figura N".
4. Si falta una imagen → placeholder naranja indicando qué archivo añadir.

### Segunda entrega (planificado)

- Captura automática de la UI al completar cada fase del pipeline
- Subida drag-and-drop desde la web
- Menos texto, más figuras (informe orientado a cliente)

---

## Contenido textual del informe

Portada, índice, resumen, metodología, pasos, CVEs, recomendaciones, flag.

Ver [[../03-Backend/Servicio-informe-Word]].

---

## Enlaces

- [[../01-Proyecto/Entrega-v1-estado]]
- [[Auditoria-y-trazabilidad-IA]]
