# Instalación y ejecución

#recontool #operaciones #setup

Relacionado: [[Despliegue-Kali]] · [[../03-Backend/Configuracion-env]] · [[../Indice|Índice]]

---

## Requisitos previos

- Python 3.10+
- nmap instalado y en PATH
- Git (opcional, para clonar)
- Privilegios elevados si usas `-sS` y `-O` (ver [[../03-Backend/Servicio-nmap]])

---

## Windows (desarrollo actual)

### 1. Clonar o abrir copia local

```powershell
cd "C:\Users\Darth\Desktop\Proyecto ReconTool\code\backend"
```

### 2. Entorno virtual

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Aviso:** Si el `venv` apunta a `F:\Master\...` (copia antigua), recrear venv en el escritorio:
> `Remove-Item -Recurse venv` y repetir `python -m venv venv`.

### 3. Configuración

```powershell
copy .env.example .env
# Editar .env
```

### 4. Ejecutar (terminal como Administrador recomendado)

```powershell
python run.py
```

### 5. Abrir navegador

`http://127.0.0.1:8000`

Probar con `scanme.nmap.org` (servicio público de prueba de nmap).

---

## Linux / Kali (resumen)

Ver guía completa: [[Despliegue-Kali]].

```bash
cd ~/Proyecto-ReconTool
git pull
chmod +x recontool
./recontool
```

El script `recontool` crea venv si falta, ejecuta `pip install -r requirements.txt` y arranca el servidor.

> No uses `sudo python run.py` — ver [[Despliegue-Kali#6. Arrancar ReconTool]].

---

## Comprobar API sin UI

```bash
curl http://127.0.0.1:8000/api/
```

---

## Problemas frecuentes

| Problema | Solución |
|----------|----------|
| `ModuleNotFoundError: No module named 'nmap'` | Usar `sudo ./venv/bin/python run.py` o `./start-kali.sh`, **no** `sudo python run.py`. Luego `pip install -r requirements.txt` dentro del venv |
| `ModuleNotFoundError: httpx` | `./venv/bin/pip install -r requirements.txt` |
| Scan vacío / error permisos | Ejecutar como root/admin o cambiar a `-sT` en config (menos sigiloso) |
| IA deshabilitada | Configurar `.env` — [[../03-Backend/Configuracion-env]] |
| NVD muy lento | Obtener `NVD_API_KEY` o `enrich_cve: false` en API |

---

## Enlaces

- [[Git-y-flujo-de-trabajo]]
- [[Despliegue-Kali]]
