# json_scan_loader.py
#
# Lee un archivo JSON de escaneo y lo convierte al formato
# que usa el modelo ScanResult (open_ports y vulnerabilities).

import json


def load_scan_from_json(path):
    """
    Devuelve (open_ports, vulnerabilities) a partir de un JSON
    con estructura similar a:
    {
      "hosts": [
        {
          "ip": "192.168.1.10",
          "services": [
            {
              "port": 22,
              "service": "ssh",
              "vulnerabilities": [
                {
                  "severity": "high",
                  "description": "..."
                }
              ]
            }
          ]
        }
      ]
    }
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return [], []

    hosts = data.get("hosts", [])
    open_ports = []
    vulns = []

    for host in hosts:
        ip = host.get("ip", "unknown")
        services = host.get("services", [])

        for svc in services:
            port = svc.get("port")
            service_name = svc.get("service", "unknown")

            # Añadimos puerto abierto
            if port is not None:
                open_ports.append({
                    "host": ip,
                    "port": int(port),
                    "service": service_name,
                })

            # Vulnerabilidades asociadas a ese servicio
            for v in svc.get("vulnerabilities", []):
                sev = (v.get("severity") or "").lower()
                desc = v.get("description") or ""
                cve = v.get("cve")

                vuln_entry = {
                    "host": ip,
                    "port": int(port) if port is not None else None,
                    "service": service_name,
                    "severity": sev,
                    "description": desc,
                }
                if cve:
                    vuln_entry["cve"] = cve

                vulns.append(vuln_entry)

    return open_ports, vulns
