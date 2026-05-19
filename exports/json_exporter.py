import os
import json
import uuid
import datetime
from typing import List, Dict

def clean_dict_fields(items: List[Dict]) -> List[Dict]:
    """
    Clean lists of dicts to be fully JSON serializable, turning ObjectIds and datetimes into strings.
    """
    cleaned = []
    for item in items:
        clean_item = {}
        for k, v in item.items():
            if k == "_id":
                clean_item[k] = str(v)
            elif isinstance(v, datetime.datetime):
                clean_item[k] = v.isoformat() + "Z"
            else:
                clean_item[k] = v
        cleaned.append(clean_item)
    return cleaned

def generate_json_export(
    web_exploits: List[Dict],
    tech_cves: List[Dict],
    traffic_anomalies: List[Dict],
    target: str
) -> str:
    """
    Generate structured machine-readable JSON vulnerability export separated into three distinct arrays.
    """
    scan_id = None
    all_findings = web_exploits + tech_cves + traffic_anomalies
    for vuln in all_findings:
        if vuln.get("scan_id"):
            scan_id = str(vuln.get("scan_id"))
            break
        if vuln.get("report_id"):
            scan_id = str(vuln.get("report_id"))
            break

    if not scan_id:
        scan_id = uuid.uuid4().hex[:8]

    generated_at = datetime.datetime.utcnow().isoformat() + "Z"

    # Compute severity distribution
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    def add_sev(sev_str):
        if not sev_str:
            return
        s = str(sev_str).lower()
        if "critical" in s:
            severity_distribution["critical"] += 1
        elif "high" in s:
            severity_distribution["high"] += 1
        elif "medium" in s:
            severity_distribution["medium"] += 1
        else:
            severity_distribution["low"] += 1

    for w in web_exploits:
        add_sev(w.get("severity"))
    for t in tech_cves:
        add_sev(t.get("severity"))

    summary = {
        "total_findings": len(web_exploits) + len(tech_cves) + len(traffic_anomalies),
        "web_exploit_count": len(web_exploits),
        "technology_cve_count": len(tech_cves),
        "traffic_anomaly_count": len(traffic_anomalies),
        "severity_distribution": severity_distribution
    }

    report_data = {
        "target": target,
        "generated_at": generated_at,
        "tool": "ReconX",
        "engine_version": "2.0.0",
        "scan_id": scan_id,
        "summary": summary,
        "web_exploit_findings": clean_dict_fields(web_exploits),
        "technology_cve_findings": clean_dict_fields(tech_cves),
        "traffic_anomaly_findings": clean_dict_fields(traffic_anomalies)
    }

    # Save to reports directory
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = f"reconx_export_{scan_id}.json"
    file_path = os.path.join(reports_dir, filename)
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return filename

