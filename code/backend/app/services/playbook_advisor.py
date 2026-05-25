from typing import Any

from app.services.ftp_probe import manual_ftp_playbook
from app.services.service_router import detect_attack_vectors
from app.services.telnet_probe import manual_telnet_playbook


def build_playbook_analysis(target: str, scan_data: dict, exploitation: dict) -> dict[str, Any]:
    plan = scan_data.get("attack_plan") or detect_attack_vectors(scan_data)
    vectors_out: list[dict] = []

    for v in plan.get("vectors", []):
        checks: list[str] = []
        vid = v.get("id")
        if vid == "ftp_anonymous":
            checks = manual_ftp_playbook(target)
        elif vid == "telnet_root_blank":
            checks = manual_telnet_playbook(target)

        vectors_out.append(
            {
                "title": v.get("title", "Vector"),
                "priority": v.get("priority", "high"),
                "rationale": v.get("summary", ""),
                "suggested_checks": checks,
                "related_ports": [v.get("port")] if v.get("port") else [],
            }
        )

    primary = plan.get("primary")
    if exploitation.get("flag_captured"):
        summary = "Flag capturada en fase de ataque activo."
    elif primary:
        summary = plan.get("message", "Recon pasivo completado.")
    else:
        summary = "Recon pasivo completado. Sin vector automático mapeado."

    next_steps = exploitation.get("playbook_steps") or []
    if not next_steps and vectors_out:
        next_steps = vectors_out[0].get("suggested_checks", [])

    return {
        "enabled": True,
        "provider": "playbook",
        "analysis": {
            "summary": summary,
            "vectors": vectors_out,
            "next_steps": next_steps,
            "attack_plan": plan,
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
        analysis = dict(playbook.get("analysis", {}))
        analysis["summary"] = "Flag obtenida: " + " | ".join(flag_lines)
        out = dict(playbook)
        out["analysis"] = analysis
        return out

    if ai_result.get("enabled") and ai_result.get("analysis", {}).get("vectors"):
        merged = dict(ai_result)
        if "model" in merged and not merged.get("model"):
            del merged["model"]
        return merged

    return playbook
