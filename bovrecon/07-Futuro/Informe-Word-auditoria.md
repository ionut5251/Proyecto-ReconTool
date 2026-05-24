# Informe Word de auditoría

#recontool #informe #word #html

Relacionado: [[../03-Backend/Servicio-informe-Word]] · [[../03-Backend/Servicio-capturas-automaticas]]

---

## Estado: ✅ implementado

Dos formatos de descarga tras capturar flag:

| Botón | Formato | Uso |
|-------|---------|-----|
| Informe Word | `.docx` | Entregar en Windows / Word |
| Informe Linux | `.html` | Abrir en **Firefox** en Kali — sin transferir archivos |

---

## Capturas automáticas ✅

Ya **no** hace falta copiar PNG a mano. ReconTool genera evidencias por paso al completar el scan (ver [[../03-Backend/Servicio-capturas-automaticas]]).

Se incrustan en Word y HTML.

---

## Abrir HTML en Kali

```bash
firefox ~/Downloads/informe_pentest_10.x.x.x_YYYYMMDD.html
```

O doble clic desde el gestor de archivos. Imágenes incluidas en el mismo archivo.

---

## Segunda entrega (reservado)

- Capturas reales de pantalla UI (Playwright)
- Export PDF nativo
- Subida drag-and-drop de fotos extra

---

## Enlaces

- [[../01-Proyecto/Entrega-v1-estado]]
- [[../03-Backend/API#POST /api/report]]
