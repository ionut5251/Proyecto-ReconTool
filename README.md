# Proyecto ReconTool

Pentester automatizado en desarrollo (recon tipo Shodan local + CVEs + vectores IA) para labs autorizados (HTB, prácticas universitarias).

## Documentación

La documentación viva del proyecto está en la bóveda Obsidian **`bovrecon/`**.

**Punto de entrada:** [bovrecon/Indice.md](bovrecon/Indice.md)

## Ejecución rápida

```bash
cd code/backend
python -m venv venv
source venv/bin/activate   # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
python run.py
```

**Kali (un comando):**

```bash
cd ~/Proyecto-ReconTool && git pull && chmod +x recontool && ./recontool
```

O sin chmod: `bash recontool`

Instala dependencias y arranca el servidor. Ver [bovrecon/05-Operaciones/Despliegue-Kali.md](bovrecon/05-Operaciones/Despliegue-Kali.md).

Abrir http://127.0.0.1:8000

Flujo UI: recon pasivo → **Proceder con ataque activo** → flag e informes.

Módulos activos: FTP, Telnet, **SMB** (`smbclient`). IA operativa elige vector si hay varios servicios.

Branding: verde oscuro `#1a5c38` en botones; logo centrado en home.

## Repositorio

https://github.com/ionut5251/Proyecto-ReconTool.git
