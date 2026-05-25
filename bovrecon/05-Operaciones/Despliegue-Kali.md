# Despliegue en Kali Linux

#recontool #operaciones #kali #htb

Relacionado: [[Instalacion-y-ejecucion]] · [[../01-Proyecto/Roadmap#v0.2 — Operaciones Kali]] · [[../03-Backend/Servicio-nmap]]

---

## Por qué Kali para pruebas serias

| Aspecto | Windows dev | Kali lab |
|---------|-------------|----------|
| nmap `-sS` / `-O` | Requiere admin, a veces problemático | Nativo con sudo |
| VPN Hack The Box | Configuración extra | OpenVPN integrado en flujo habitual |
| Herramientas pentest | Limitadas | Completas para fases futuras |
| Ollama local | Posible | Recomendado para IA sin coste API |

**Recomendación:** desarrollar UI/API en Windows; **ejecutar escaneos contra HTB desde Kali**.

---

## Pasos de despliegue

### 1. Obtener código

```bash
git clone https://github.com/ionut5251/Proyecto-ReconTool.git
cd Proyecto-ReconTool
git pull
```

### 2. Abrir bóveda documentación (opcional)

Abrir carpeta `bovrecon/` como vault en Obsidian en Kali (o leer MD en GitHub).

Punto de entrada: [[../Indice|Indice.md]].

### 3. Backend

```bash
cd code/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
```

Configuración típica HTB + Ollama:

```env
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2
```

### 4. Ollama (opcional)

```bash
# Si no está instalado, seguir documentación oficial de Ollama para Linux
ollama serve &
ollama pull llama3.2
```

### 5. VPN HTB

Conectar VPN **antes** de escanear IP de máquina HTB (10.10.x.x).

Verificar:

```bash
ping -c 2 10.10.x.x
```

### 6. Arrancar ReconTool

> Si ves `permission denied: ./recontool` → falta permiso de ejecución. Usa `bash recontool` (abajo).

**Comando recomendado (copia tal cual):**

```bash
cd ~/Proyecto-ReconTool
git pull
chmod +x recontool
bash recontool
```

(`bash recontool` funciona aunque falle `./recontool` sin chmod.)

Esto hace automáticamente:

1. Crear `venv` si no existe  
2. `pip install -r requirements.txt` (actualiza dependencias)  
3. Comprobar/instalar `nmap`  
4. Arrancar con `sudo ./venv/bin/python run.py`  

> **NO uses** `sudo ./recontool` ni `sudo python run.py` — el script ya gestiona sudo por dentro.

**Errores frecuentes:**

| Error | Qué hacer |
|-------|-----------|
| `permission denied: ./recontool` | `chmod +x recontool` o `bash recontool` |
| `sudo: ./recontool: command not found` | `cd ~/Proyecto-ReconTool` + `git pull` + `bash recontool` |
| `ModuleNotFoundError: nmap` | Usar `bash recontool`, no `sudo python run.py` |

**Manual (alternativa):**

```bash
cd ~/Proyecto-ReconTool/code/backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python run.py
```

Abrir en navegador de Kali: `http://127.0.0.1:8000`

### 7. Acceso desde host Windows (opcional)

Si Kali es VM y quieres ver la UI desde Windows:

```bash
# En Kali, uvicorn ya escucha 127.0.0.1 — cambiar host a 0.0.0.0 en run.py solo para lab
# O túnel SSH desde Windows:
ssh -L 8000:127.0.0.1:8000 user@IP_KALI
```

Luego en Windows: `http://127.0.0.1:8000`

---

## Checklist de prueba en lab

- [ ] `GET /api/` responde
- [ ] Scan `scanme.nmap.org` devuelve puertos
- [ ] `cve_findings` no vacío en al menos un servicio con versión
- [ ] `ai_analysis.enabled === true` con Ollama/OpenAI
- [ ] Máquina HTB: solo IP del lab con VPN activa
- [ ] Anotar incidencias en notas Obsidian o issues GitHub

---

## Depuración post-Kali

Documentar en bóveda:

1. Tiempos reales de scan.
2. Falsos positivos CVE.
3. Calidad de vectores IA.
4. Cambios de flags nmap necesarios.

Actualizar [[../01-Proyecto/Roadmap]] según hallazgos.

---

## Enlaces

- [[Instalacion-y-ejecucion]]
- [[../03-Backend/Configuracion-env]]
- [[../07-Futuro/Auditoria-y-trazabilidad-IA]]
