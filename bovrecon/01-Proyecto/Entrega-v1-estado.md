# Entrega v1 — Estado del proyecto (Fase 1)

#recontool #entrega #v1 #fase1

Relacionado: [[Roadmap]] · [[Fase2-CLI-e-instalador|Fase 2 — CLI e instalador]] · [[../Indice|Índice]] · [[../07-Futuro/Informe-Word-auditoria]]

---

> **Esta nota documenta la Fase 1** (aplicación web). La evolución tipo ADScan (instalable + CLI guiado) está en [[Fase2-CLI-e-instalador]].

---

## Alcance entregado (primera entrega)

| Funcionalidad | Estado |
|---------------|--------|
| UI estilo Shodan (búsqueda IP + resultados) | ✅ |
| Escaneo nmap modular | ✅ |
| CVE local + NVD | ✅ |
| IA / playbook vectores | ✅ |
| FTP anónimo automático (HTB Fawn) | ✅ Probado en Kali |
| Captura flag en web | ✅ |
| Informe Word (.docx) | ✅ |
| Informe HTML (Kali / Firefox) | ✅ |
| Evidencias gráficas automáticas | ✅ [[../03-Backend/Servicio-capturas-automaticas]] |
| Comando único arranque `./recontool` | ✅ |
| Documentación bóveda Obsidian | ✅ |

---

## Continuado en la Fase 2

Lo que aquí quedaba "reservado" se retoma en la Fase 2 ([[Fase2-CLI-e-instalador]]):

- Instalación en el equipo como programa (`install.sh` + comando `recon`).
- Uso guiado por terminal con sesiones efímeras (borrón y cuenta nueva).
- Informe + transcripción con comandos usados e información conseguida.
- Pendiente: fuzzing web automático en el informe y cotejo con el PDF del enunciado.

Ver [[Roadmap#v2.0 — Fase 2: CLI tipo ADScan 🔄 (en curso)]].

---

## Cómo demostrar la entrega (Fase 1 — web)

1. Kali + VPN HTB
2. `./recontool` desde la raíz del repo
3. Escanear máquina lab (ej. Fawn)
4. Ver flag + descargar informe Word
5. (Opcional) Añadir capturas en `data/screenshots/<IP>/` y regenerar informe

---

## Enlaces

- [[../05-Operaciones/Despliegue-Kali]]
- [[Fase2-CLI-e-instalador]]
- [[../03-Backend/Servicio-FTP-exploit]]
