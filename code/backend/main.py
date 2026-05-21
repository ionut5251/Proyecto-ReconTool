from fastapi import FastAPI
from pydantic import BaseModel
import nmap
import json
# dsa
app = FastAPI()

scanner = nmap.PortScanner()

with open("vulnerabilities.json", "r") as file:
    vulnerabilities_db = json.load(file)

class ScanRequest(BaseModel):
    target: str

@app.get("/")
def home():
    return {"message": "ReconTool API running"}

@app.post("/scan")
def scan_target(data: ScanRequest):

    target = data.target

    try:

        scanner.scan(
            target,
            arguments='-sS -sV -O --open -Pn -n -T4'
        )

        results = []

        os_info = []

        for host in scanner.all_hosts():

            if 'osmatch' in scanner[host]:

                for osmatch in scanner[host]['osmatch']:

                    os_info.append({
                        "name": osmatch['name'],
                        "accuracy": osmatch['accuracy']
                    })

            for proto in scanner[host].all_protocols():

                ports = scanner[host][proto].keys()

                for port in ports:

                    service = scanner[host][proto][port]['name']

                    state = scanner[host][proto][port]['state']

                    product = scanner[host][proto][port].get('product', '')

                    version = scanner[host][proto][port].get('version', '')

                    extrainfo = scanner[host][proto][port].get('extrainfo', '')

                    full_service = f"{product} {version}".strip()

                    vulnerability = vulnerabilities_db.get(full_service, None)

                    results.append({
                        "host": host,
                        "port": port,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "extra_info": extrainfo,
                        "vulnerability": vulnerability
                    })

        return {
            "target": target,
            "results": results,
            "os": os_info
        }

    except Exception as e:
        return {
            "error": str(e)
        }