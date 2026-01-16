from model5 import run_model_5

# ---- Mock Inputs ----

port_scan_results = [
    {"port": 80, "service": "http"},
    {"port": 22, "service": "ssh"}
]

technology_results = [
    {
        "technology": "Apache HTTP Server",
        "version": "2.4.49",
        "cves": [
            {"cve": "CVE-2021-41773"}
        ]
    },
    {
        "technology": "OpenSSH",
        "version": "8.2p1",
        "cves": []
    }
]

http_anomaly_result = {
    "status": "suspicious",
    "signals": ["directory_listing", "path_traversal"]
}

# ---- Run Model 5 ----

result = run_model_5(
    port_scan_results=port_scan_results,
    technology_results=technology_results,
    http_anomaly_result=http_anomaly_result
)

# ---- Pretty Print ----

import json
print(json.dumps(result, indent=2))
