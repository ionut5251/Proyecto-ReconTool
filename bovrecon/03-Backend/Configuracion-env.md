# Configuración (.env)

#recontool #backend #configuracion

Relacionado: [[Backend-overview]] · [[Servicio-IA]] · [[Servicio-CVE-NVD]]

---

## Ubicación

- Plantilla (commitear): `code/backend/.env.example`
- Secreto (NO commitear): `code/backend/.env`

Cargado por `python-dotenv` en `app/core/config.py` al importar el módulo.

---

## Variables

### NVD

| Variable | Default | Descripción |
|----------|---------|-------------|
| `NVD_API_KEY` | vacío | Clave opcional NIST |
| `NVD_RESULTS_PER_QUERY` | `5` | Máx CVEs por búsqueda |
| `NVD_REQUEST_DELAY_SEC` | `6.2` | Espera entre requests sin key |

### IA

| Variable | Default | Descripción |
|----------|---------|-------------|
| `AI_PROVIDER` | `auto` | `auto`, `openai`, `ollama`, `none` |
| `OPENAI_API_KEY` | vacío | Clave API OpenAI |
| `OPENAI_MODEL` | `gpt-4o-mini` | Modelo chat |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Compatible Azure/LocalAI |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Servidor Ollama |
| `OLLAMA_MODEL` | `llama3.2` | Modelo local |

### Código (no env)

| Constante | Archivo | Valor |
|-----------|---------|-------|
| `NMAP_ARGUMENTS` | `config.py` | Ver [[Servicio-nmap]] |
| `VULNERABILITIES_DB_PATH` | `config.py` | `data/vulnerabilities.json` |

---

## Setup rápido

```bash
cd code/backend
cp .env.example .env
# Editar .env con editor
```

### Solo recon sin IA (ahorra tiempo)

En petición API: `"ai_analyze": false`

O en `.env`: `AI_PROVIDER=none`

### Kali con Ollama

```env
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2
```

---

## Seguridad

- **Nunca** commitear `.env`.
- Rotar claves si se filtran.
- No subir capturas de pantalla con API keys a `pics/` sin censurar.

---

## Enlaces

- [[../05-Operaciones/Instalacion-y-ejecucion]]
- [[../05-Operaciones/Despliegue-Kali]]
