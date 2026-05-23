# Entrega v1 — Estado del proyecto

#recontool #entrega #v1

Relacionado: [[Roadmap]] · [[../Indice|Índice]] · [[../07-Futuro/Informe-Word-auditoria]]

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
| Evidencias gráficas en informe | 🔄 Manual (carpeta screenshots) |
| Comando único arranque `./recontool` | ✅ |
| Documentación bóveda Obsidian | ✅ |

---

## Reservado para segunda entrega

- Capturas automáticas durante el scan (sin copiar PNG a mano)
- Más módulos de explotación (otras máquinas HTB easy)
- Trazabilidad IA paso a paso en UI
- Informe más visual (menos texto, más figuras embebidas auto)
- Posible export PDF

Ver [[Roadmap#v0.3 — Observabilidad y auditoría]].

---

## Cómo demostrar la entrega

1. Kali + VPN HTB
2. `./recontool` desde la raíz del repo
3. Escanear máquina lab (ej. Fawn)
4. Ver flag + descargar informe Word
5. (Opcional) Añadir capturas en `data/screenshots/<IP>/` y regenerar informe

---

## Comando de arranque

```bash
cd ~/Proyecto-ReconTool
git pull
chmod +x recontool
./recontool
```

Instala dependencias y arranca solo — no hace falta `pip install` manual cada vez.

---

## Enlaces

- [[../05-Operaciones/Despliegue-Kali]]
- [[../03-Backend/Servicio-informe-Word#Capturas / evidencias gráficas]]
- [[../03-Backend/Servicio-FTP-exploit]]
