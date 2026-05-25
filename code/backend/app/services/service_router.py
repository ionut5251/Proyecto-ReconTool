"""Detecta el vector de ataque correcto según puertos/servicios abiertos."""

from __future__ import annotations

from typing import Any, Optional


def _open_rows(scan_data: dict) -> list[dict]:
    return [
        r
        for r in scan_data.get("results", [])
        if str(r.get("state", "")).lower() == "open"
    ]


def _has_port(scan_data: dict, port: int) -> bool:
    return any(int(r.get("port", 0)) == port for r in _open_rows(scan_data))


def _has_service(scan_data: dict, name: str) -> bool:
    name = name.lower()
    return any(name in str(r.get("service", "")).lower() for r in _open_rows(scan_data))


def detect_attack_vectors(scan_data: dict) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []

    if _has_port(scan_data, 21) or _has_service(scan_data, "ftp"):
        vectors.append(
            {
                "id": "ftp_anonymous",
                "port": 21,
                "service": "ftp",
                "title": "FTP — login anónimo",
                "priority": "high",
                "summary": "Puerto 21/FTP: probar anonymous y descargar flag.txt.",
            }
        )

    if _has_port(scan_data, 23) or _has_service(scan_data, "telnet"):
        vectors.append(
            {
                "id": "telnet_root_blank",
                "port": 23,
                "service": "telnet",
                "title": "Telnet — root sin contraseña",
                "priority": "high",
                "summary": "Puerto 23/Telnet: probar root con contraseña vacía y leer flag.txt.",
            }
        )

    for port in (80, 443, 8080, 8443):
        if _has_port(scan_data, port) or _has_service(scan_data, "http"):
            vectors.append(
                {
                    "id": "http_enum",
                    "port": port,
                    "service": "http",
                    "title": "HTTP — enumeración web",
                    "priority": "medium",
                    "summary": f"Puerto {port}: fuzzing directorios, títulos, tecnologías.",
                }
            )
            break

    primary: Optional[dict] = None
    if vectors:
        open_ports = {int(r.get("port", 0)) for r in _open_rows(scan_data)}
        for vec in vectors:
            if vec.get("port") in open_ports:
                primary = vec
                break
        if primary is None:
            primary = vectors[0]

    return {
        "primary": primary,
        "vectors": vectors,
        "recommended_action": primary["id"] if primary else None,
        "message": (
            f"Vector principal detectado: {primary['title']}"
            if primary
            else "Sin vector automático conocido para estos puertos."
        ),
    }


def get_primary_vector_id(scan_data: dict) -> Optional[str]:
    plan = scan_data.get("attack_plan") or detect_attack_vectors(scan_data)
    primary = plan.get("primary")
    return primary.get("id") if primary else None
