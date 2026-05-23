# Visión y objetivos del proyecto

#recontool #proyecto #vision

Relacionado: [[../Indice|Índice]] · [[Roadmap]] · [[../02-Arquitectura/Arquitectura-general]]

---

## Idea central

Construir un **asistente de red team automatizado** que, ante una IP/hostname autorizado:

1. **Reconozca** servicios (nmap, estilo recon Shodan local).
2. **Enriquezca** con vulnerabilidades (base local + NVD).
3. **Sugiera vectores** de ataque mediante IA (solo orientación en lab).
4. *(Futuro)* **Registre y audite** cada paso con evidencias exportables a Word.

No sustituye el criterio del pentester: acelera recon y priorización en entornos de práctica.

---

## Contexto académico

- Máster de **Ciberseguridad e IA**.
- Práctica alineada con metodología de clase (nmap como herramienta base).
- Uso ético: solo objetivos con **permiso explícito** (HTB, VMs universidad, red propia).

---

## Objetivos por fase

### Fase actual (v0.1) — ✅ en curso

- API FastAPI modular.
- UI web inspirada en Shodan (búsqueda IP → pantalla resultados).
- Pipeline: nmap → CVE → IA.

Ver [[../03-Backend/Pipeline-de-escaneo]].

### Fase siguiente — operativa

- Despliegue y pruebas en **Kali** con VPN HTB.
- Depuración de falsos positivos CVE y tiempos de escaneo.
- Ver [[../05-Operaciones/Despliegue-Kali]].

### Fase futura — producto

- **Trazabilidad**: ver pasos internos de la IA ([[../07-Futuro/Auditoria-y-trazabilidad-IA]]).
- **Informe**: auditoría en Word con capturas ([[../07-Futuro/Informe-Word-auditoria]]).
- Automatización progresiva hacia flags en máquinas tipo HackTheBox (siempre en lab).

---

## Qué NO es ReconTool

- No es Shodan ni escanea Internet arbitrariamente.
- No explota automáticamente sin supervisión (aún).
- No almacena credenciales ni datos de terceros en el repo.

---

## Métricas de éxito (personales)

- [ ] Escaneo estable en Kali contra máquina HTB easy.
- [ ] CVEs relevantes en ≥1 servicio detectado.
- [ ] IA devuelve ≥2 vectores accionables y coherentes con el scan.
- [ ] Documentación bovrecon permite retomar el proyecto en &lt;30 min sin máquina local.

---

## Referencias internas

- [[Roadmap]]
- [[../06-Reglas/Que-tocar-y-que-no]]
- [[../02-Arquitectura/Flujo-de-datos]]
