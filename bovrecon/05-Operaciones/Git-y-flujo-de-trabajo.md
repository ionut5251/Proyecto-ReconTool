# Git y flujo de trabajo

#recontool #git #operaciones

Relacionado: [[../06-Reglas/Mantenimiento-documentacion]] · [[../Indice|Índice]]

---

## Remoto

```
origin  https://github.com/ionut5251/Proyecto-ReconTool.git
```

Rama principal: `main`.

La ruta local del clon (Escritorio vs `F:/Master`) **no afecta** al remoto.

---

## Qué se commitea

| Incluir | Excluir (.gitignore) |
|---------|----------------------|
| `code/` fuente | `code/backend/venv/` |
| `bovrecon/**/*.md` | `code/backend/.env` |
| `.env.example` | `__pycache__/`, `*.pyc` |
| `requirements.txt` | `*.log` |

La carpeta `bovrecon/.obsidian/` puede commitearse (config del vault) o ignorarse si prefieres settings personales — actualmente **se commitea** con el vault.

---

## Flujo recomendado

1. Desarrollar cambio en código.
2. Actualizar notas en `bovrecon/` (misma PR mental).
3. Probar localmente.
4. Commit descriptivo en español o inglés claro.
5. `git push origin main`

---

## Mensajes de commit (ejemplos)

- `docs: ampliar bóveda bovrecon con arquitectura API`
- `feat: log de fases nmap/NVD/IA`
- `fix: throttle NVD en scans multi-puerto`

---

## Hitos ya en remoto

| Commit (aprox.) | Contenido |
|-----------------|-----------|
| `85dbd84` | Servicios iniciales |
| `c114956` | Reorganización, frontend Shodan, NVD, IA |

---

## Sincronizar Kali

```bash
git pull origin main
```

Siempre `pip install -r requirements.txt` tras pull si cambió `requirements.txt`.

---

## Enlaces

- [[../06-Reglas/Mantenimiento-documentacion]]
- [[Instalacion-y-ejecucion]]
