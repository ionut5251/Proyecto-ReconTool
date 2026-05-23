# Mantenimiento de la documentación (bovrecon)

#recontool #documentacion #obsidian #reglas

Relacionado: [[Que-tocar-y-que-no]] · [[../Indice|Índice]] · [[../05-Operaciones/Git-y-flujo-de-trabajo]]

---

## Principio

La bóveda **bovrecon** es la red neuronal lógica del proyecto: debe reflejar el código **en todo momento** y permitir retomar el trabajo sin la máquina local.

---

## Cuándo actualizar

| Evento | Acción |
|--------|--------|
| Nuevo servicio / archivo | Crear nota en `03-Backend/` o sección adecuada + enlace en [[../Indice]] |
| Cambio API | Actualizar [[../03-Backend/API]] y [[../02-Arquitectura/Flujo-de-datos]] |
| Cambio UI | Actualizar [[../04-Frontend/Pantallas-UI]] |
| Nueva variable `.env` | Actualizar [[../03-Backend/Configuracion-env]] y `.env.example` |
| Feature planificada | Añadir a [[../01-Proyecto/Roadmap]] y `07-Futuro/` |
| Prueba Kali | Anotar hallazgos en [[../05-Operaciones/Despliegue-Kali]] o nota de sesión |
| Eliminar código | Borrar o archivar nota; quitar wikilinks rotos |

---

## Convenciones Obsidian

### Wikilinks

Usar rutas relativas de bóveda:

```markdown
[[03-Backend/API]]
[[../Indice|Índice]]
```

### Tags sugeridos

`#recontool` en todas las notas principales. Tags de área: `#backend`, `#frontend`, `#api`, `#ia`, `#cve`, `#roadmap`, `#futuro`.

### MOC (Map of Content)

El hub central es [[../Indice]] — cualquier nota nueva debe enlazarse desde ahí o desde un overview de su carpeta.

---

## Estructura de carpetas bovrecon

| Carpeta | Contenido |
|---------|-----------|
| `01-Proyecto/` | Visión, roadmap, glosario |
| `02-Arquitectura/` | Diagramas, flujos, mapa repo |
| `03-Backend/` | Servicios, API, config |
| `04-Frontend/` | UI |
| `05-Operaciones/` | Install, Kali, git |
| `06-Reglas/` | Reglas de equipo / IA |
| `07-Futuro/` | Features no implementadas |

No crear documentación larga fuera de `bovrecon/` salvo `README.md` raíz mínimo.

---

## Commit de documentación

Preferible **mismo commit** que el código si el cambio es pequeño.

Si solo docs:

```
docs(bovrecon): describir servicio X y actualizar índice
```

Siempre `git push` tras documentar hitos importantes.

---

## Vista grafo en Obsidian

Abrir vault: carpeta `bovrecon/` del repo.

- Nodo central esperado: **Indice**
- Clusters: Backend, Arquitectura, Futuro

Si el grafo está desconectado, faltan wikilinks — añadir enlaces "Relacionado:" al inicio de cada nota.

---

## Para IA en Cursor / otro IDE

Al iniciar sesión, pedir o leer:

1. `bovrecon/Indice.md`
2. `bovrecon/06-Reglas/Que-tocar-y-que-no.md`
3. Nota específica del área a modificar

---

## Enlaces

- [[Que-tocar-y-que-no]]
- [[Convenciones-de-codigo]]
