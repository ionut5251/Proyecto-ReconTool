from typing import Any

from app.services.ftp_probe import manual_ftp_playbook, run_exploitation_checks


def build_playbook_analysis(target: str, scan_data: dict, exploitation: dict) -> dict[str, Any]:
    results = scan_data.get("results", [])
    open_ports = [int(r["port"]) for r in results if str(r.get("state", "")).lower() == "open"]
    vectors: list[dict] = []

    if 21 in open_ports:
        vectors.append(
            {
                "title": "FTP anónimo (estilo HTB Fawn)",
                "priority": "high",
                "rationale": (
                    "Puerto 21/FTP abierto. En labs HTB es habitual login anonymous "
                    "con acceso de lectura a flag.txt en el directorio raíz."
                ),
                "suggested_checks": manual_ftp_playbook(target),
                "related_ports": [21],
            }
        )

    if exploitation.get("flag_captured"):
        summary = "Flag capturada automáticamente vía FTP anónimo."
    elif 21 in open_ports:
        summary = (
            "Recon completado. Vector principal: FTP anónimo en puerto 21 "
            "(misma ruta que HTB Fawn: ls → get flag.txt)."
        )
    else:
        summary = "Recon completado. Revisa puertos abiertos y vectores sugeridos."

    next_steps = exploitation.get("playbook_steps") or []
    if not next_steps and vectors:
        next_steps = vectors[0].get("suggested_checks", [])

    return {
        "enabled": True,
        "provider": "playbook",
        "model": "htb-fawn-ftp",
        "analysis": {
            "summary": summary,
            "vectors": vectors,
            "next_steps": next_steps,
        },
    }


def merge_ai_with_playbook(
    ai_result: dict,
    playbook: dict,
    exploitation: dict,
) -> dict:
    if exploitation.get("flag_captured"):
        flags = exploitation.get("flags", [])
        flag_lines = [f"{f['filename']}: {f['content']}" for f in flags]
        playbook_analysis = playbook.get("analysis", {})
        playbook_analysis["summary"] = (
            "Flag obtenida por explotación automática (FTP anónimo). "
            + " | ".join(flag_lines)
        )
        return playbook

    if ai_result.get("enabled") and ai_result.get("analysis", {}).get("vectors"):
        return ai_result

    return playbook
