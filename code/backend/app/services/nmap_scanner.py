import nmap

from app.core.config import NMAP_ARGUMENTS
from app.services.vuln_db import load_vulnerabilities_db

scanner = nmap.PortScanner()
vulnerabilities_db = load_vulnerabilities_db()


def scan_target(target: str) -> dict:
    scanner.scan(target, arguments=NMAP_ARGUMENTS)

    results = []
    os_info = []

    for host in scanner.all_hosts():
        if "osmatch" in scanner[host]:
            for osmatch in scanner[host]["osmatch"]:
                os_info.append(
                    {
                        "name": osmatch["name"],
                        "accuracy": osmatch["accuracy"],
                    }
                )

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in ports:
                port_data = scanner[host][proto][port]
                service = port_data["name"]
                state = port_data["state"]
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                extrainfo = port_data.get("extrainfo", "")

                full_service = f"{product} {version}".strip()
                vulnerability = vulnerabilities_db.get(full_service)

                results.append(
                    {
                        "host": host,
                        "port": port,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "extra_info": extrainfo,
                        "vulnerability": vulnerability,
                    }
                )

    return {
        "target": target,
        "results": results,
        "os": os_info,
    }
