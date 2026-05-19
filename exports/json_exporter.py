import os
import json
import uuid
import datetime
from typing import List, Dict

_GENERIC_NAMES = frozenset({"web service", "unknown", "n/a", ""})
_GENERIC_VERSIONS = frozenset({"unknown", "n/a", ""})


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


def _clean_tech_cves(tech_cves: List[Dict]) -> List[Dict]:
    """
    Deduplicate, filter generic entries, and inject NVD references.

    Rules applied (in order):
    1. Skip entries where both service_name and technology_stack are generic placeholders.
    2. Skip entries where version is unknown/missing.
    3. Deduplicate by (service_name, version, cve_id); keep first occurrence.
    4. Inject https://nvd.nist.gov/vuln/detail/<cve_id> as the first reference for real CVE IDs.
    """
    seen: set = set()
    result: List[Dict] = []

    for entry in tech_cves:
        svc = str(entry.get("service_name") or "").lower().strip()
        stack = str(entry.get("technology_stack") or "").lower().strip()
        ver = str(entry.get("version") or "").lower().strip()
        cve_id = str(entry.get("cve_id") or "").strip()

        # 1. Drop generic/incomplete entries
        name_key = svc or stack
        if name_key in _GENERIC_NAMES:
            continue
        if ver in _GENERIC_VERSIONS:
            continue

        # 2. Dedup
        dedup_key = (name_key, ver, cve_id.upper())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # 3. Work on a copy so we don't mutate the caller's data
        entry = dict(entry)

        # 4. Inject NVD reference
        if cve_id.upper().startswith("CVE-"):
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            refs = list(entry.get("references") or [])
            if nvd_url not in refs:
                refs.insert(0, nvd_url)
            entry["references"] = refs

        result.append(entry)

    return result


def generate_json_export(
    web_exploits: List[Dict],
    tech_cves: List[Dict],
    traffic_anomalies: List[Dict],
    target: str
) -> str:
    """
    Generate structured machine-readable JSON vulnerability export separated into three distinct arrays.
    Summary counts are computed AFTER deduplication.
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

    # Deduplicate and filter tech CVEs before anything else
    tech_cves = _clean_tech_cves(tech_cves)

    # Compute severity distribution AFTER deduplication
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def add_sev(sev_str: str) -> None:
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
