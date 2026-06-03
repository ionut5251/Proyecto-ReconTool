# Informe Práctica 1 — Ciberseguridad con IA

Documentación de entrega académica para el Máster Evolve (Módulo Ciberseguridad Avanzada).

## Archivo principal

- **`Informe_Practica1_ReconTool.docx`** — informe Word listo para revisión y exportación a PDF.

## Regenerar el informe

```powershell
cd code\backend
python -m pip install python-docx Pillow httpx
python ..\..\tools\generate_practica1_informe.py
```

Editar antes de regenerar (opcional):

- `tools/generate_practica1_informe.py` → variable `AUTHOR`
- Sustituir `assets/evolve-logo.png` por el logo oficial de Evolve si tienes el archivo
- Añadir capturas reales en `assets/` y referenciarlas en el script

## Estructura (según enunciado PDF)

| Sección | Estado |
|---------|--------|
| 1. Portada | ✅ Logo Evolve + ReconTool |
| 2. Índice | ✅ |
| 3. Resumen ejecutivo | ✅ ~1 página |
| 4. Problema y justificación | ✅ |
| 5. Arquitectura + diagrama | ✅ PNG generado |
| 6. Proceso de desarrollo | ✅ + mockups UI |
| 7. Guía de despliegue | ✅ local/Kali + plan Hetzner |
| 8. Manual de uso | ✅ esqueleto (completar capturas) |
| 9. Conclusiones | ✅ |
| 10. Road map Práctica 2 | ⏳ placeholder (completar tú) |

## Nota sobre despliegue

El enunciado pide Hetzner; el informe documenta el despliegue **local/Kali** actual y un plan de migración a VPS por limitación económica.

## Punto 8 del enunciado

Corresponde al **manual de uso**: cómo buscar una IP, interpretar fases 1 y 2, descargar informes, etc.
