# Servicio nmap

#recontool #backend #nmap

Relacionado: [[Pipeline-de-escaneo]] · [[Configuracion-env]] · [[../05-Operaciones/Despliegue-Kali]]

---

## Archivo

`code/backend/app/services/nmap_scanner.py`

---

## Argumentos de escaneo

Definidos en `app/core/config.py`:

```
-sS -sV -O --open -Pn -n -T4
```

| Flag | Significado |
|------|-------------|
| `-sS` | SYN scan (requiere privilegios elevados en muchos SO) |
| `-sV` | Detección de versión de servicios |
| `-O` | Detección de sistema operativo |
| `--open` | Solo puertos abiertos |
| `-Pn` | No ping previo (útil si ICMP bloqueado) |
| `-n` | Sin resolución DNS |
| `-T4` | Timing agresivo |

Para cambiar flags: editar `NMAP_ARGUMENTS` en `config.py` y documentar aquí.

---

## Salida por puerto

Cada elemento de `results[]`:

| Campo | Origen nmap |
|-------|-------------|
| `host` | IP del host |
| `port` | Número de puerto |
| `state` | `open`, `filtered`, etc. |
| `service` | Nombre servicio (`http`, `ssh`…) |
| `product` | Producto detectado |
| `version` | Versión detectada |
| `extra_info` | `extrainfo` de nmap |
| `vulnerability` | Lookup local en scan (luego pipeline enriquece) |

Además `os[]` con `name` y `accuracy` de `osmatch`.

---

## Requisitos del sistema

- **nmap instalado** y en PATH.
- En **Windows**: ejecutar terminal como Administrador para `-sS` y `-O`.
- En **Kali**: normalmente con `sudo python run.py` o usuario con capabilities.

---

## Errores frecuentes

| Síntoma | Causa probable |
|---------|----------------|
| `nmap program was not found` | nmap no instalado / no en PATH |
| Scan vacío | Target caído, firewall, o sin puertos abiertos |
| OS vacío | `-O` necesita root; fingerprint insuficiente |

---

## Mejoras futuras

- Perfiles: `quick` vs `full` (distintos argumentos).
- Escaneo por rangos de puertos configurable.
- Log de comando nmap ejecutado (trazabilidad).

Ver [[../07-Futuro/Auditoria-y-trazabilidad-IA]].
