import os
import uuid
import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse

from exports.burp_exporter import generate_burp_export
from exports.markdown_exporter import generate_markdown_report
from exports.json_exporter import generate_json_export

def derive_severity_from_cvss(cvss: float) -> str:
    """
    Derives severity strictly from CVSS scores.
    """
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"

def urlparse_safe(url: str) -> Dict[str, str]:
    if not url:
        return {"host": "", "path": "/"}
    try:
        parsed = urlparse(url)
        return {
            "host": parsed.netloc.split(":")[0],
            "path": parsed.path or "/"
        }
    except Exception:
        return {"host": "", "path": "/"}

def classify_and_segregate_findings(scan_results: Dict[str, Any], target: str) -> tuple:
    """
    Normalizes findings and splits them into web exploits, technology CVEs, and traffic anomalies.
    """
    web_exploits = []
    tech_cves = []
    traffic_anomalies = []
    seen = set()

    # 1. Gather from Model 6 Risk Scorer Results
    model6_results = scan_results.get("model6", []) or []
    for rec in model6_results:
        cve_id = rec.get("cve_id") or "N/A"
        subdomain = rec.get("subdomain") or target
        key = (cve_id, subdomain)
        
        if key in seen:
            continue
        seen.add(key)

        title = rec.get("title") or rec.get("cve_id") or f"Vulnerability in {rec.get('service_name', 'Web Service')}"
        desc = rec.get("description") or ""
        cwe = rec.get("cwe_id") or rec.get("cwe") or ""
        
        # Check if authentic request context is present
        has_auth_context = False
        headers = rec.get("headers") or rec.get("request_headers")
        body = rec.get("body") or rec.get("request_body")
        method = rec.get("method") or rec.get("request_method") or "GET"

        if headers and len(headers) > 0:
            has_auth_context = True

        # Check finding category
        is_web = False
        text = f"{title} {cve_id} {desc} {cwe}".lower()
        web_indicators = [
            "sql injection", "sqli", "cwe-89",
            "cross-site scripting", "xss", "cwe-79",
            "server-side request forgery", "ssrf", "cwe-918",
            "open redirect", "cwe-601",
            "auth bypass", "authentication bypass", "authorization bypass", "cwe-287",
            "file upload", "directory traversal", "command injection", "remote code execution", "rce"
        ]
        if any(ind in text for ind in web_indicators):
            is_web = True

        if is_web and has_auth_context:
            web_exploits.append({
                "finding_type": "web_exploit",
                "title": title,
                "cve_id": cve_id,
                "severity": rec.get("risk_level") or rec.get("severity") or "Low",
                "target": target,
                "host": subdomain,
                "endpoint": rec.get("endpoint") or "/",
                "url": rec.get("url") or f"http://{subdomain}/",
                "http_method": method,
                "request_headers": headers if isinstance(headers, dict) else {"Host": subdomain},
                "request_body": body or "",
                "proof_of_concept": rec.get("proof_of_concept") or f"{method} {rec.get('endpoint', '/')} HTTP/1.1",
                "description": desc,
                "impact": rec.get("impact") or "An attacker could exploit this web vulnerability to compromise the system.",
                "remediation": rec.get("remediation") or "Review source code for input filtering and encoding constraints.",
                "references": rec.get("references") or []
            })
        else:
            cvss = float(rec.get("cvss_score") or rec.get("cvss") or 0.0)
            severity = derive_severity_from_cvss(cvss)
            
            tech_cves.append({
                "finding_type": "technology_cve",
                "title": title,
                "severity": severity,
                "target": target,
                "host": subdomain,
                "service_name": rec.get("service_name") or rec.get("technology_stack") or "Web Service",
                "technology_stack": rec.get("technology_stack") or rec.get("service_name") or "Web Service",
                "version": rec.get("version") or "Unknown",
                "cve_id": cve_id,
                "cvss_score": cvss,
                "cwe": cwe,
                "description": desc,
                "impact": rec.get("impact") or "Vulnerable stack version detected.",
                "remediation": rec.get("remediation") or "Update technology stack version.",
                "references": rec.get("references") or []
            })

    # 2. Gather from Technology Fingerprints (Model 3 results) if not already added
    tech_fingerprints = scan_results.get("technology_fingerprints", []) or []
    for tech_res in tech_fingerprints:
        url = tech_res.get("url")
        parsed_url = urlparse_safe(url)
        subdomain = parsed_url.get("host") or target
        
        for tech in tech_res.get("technologies", []) or []:
            for cve in tech.get("cves", []) or []:
                cve_id = cve.get("cve") or "N/A"
                key = (cve_id, subdomain)
                
                if key in seen:
                    continue
                seen.add(key)
                
                title = f"Vulnerable Service: {tech.get('technology')} ({cve_id})"
                desc = cve.get("description") or ""
                cwe = cve.get("cwe") or ""
                
                # Check for authentic context
                headers = cve.get("headers") or cve.get("request_headers")
                body = cve.get("body") or cve.get("request_body")
                method = cve.get("method") or cve.get("request_method") or "GET"
                has_auth_context = headers and len(headers) > 0

                is_web = False
                text = f"{title} {cve_id} {desc} {cwe}".lower()
                web_indicators = [
                    "sql injection", "sqli", "cwe-89",
                    "cross-site scripting", "xss", "cwe-79",
                    "server-side request forgery", "ssrf", "cwe-918",
                    "open redirect", "cwe-601",
                    "auth bypass", "authentication bypass", "authorization bypass", "cwe-287",
                    "file upload", "directory traversal", "command injection", "remote code execution", "rce"
                ]
                if any(ind in text for ind in web_indicators):
                    is_web = True

                if is_web and has_auth_context:
                    web_exploits.append({
                        "finding_type": "web_exploit",
                        "title": title,
                        "cve_id": cve_id,
                        "severity": cve.get("severity") or "Low",
                        "target": target,
                        "host": subdomain,
                        "endpoint": parsed_url.get("path") or "/",
                        "url": url or f"http://{subdomain}/",
                        "http_method": method,
                        "request_headers": headers if isinstance(headers, dict) else {"Host": subdomain},
                        "request_body": body or "",
                        "proof_of_concept": cve.get("proof_of_concept") or f"{method} {parsed_url.get('path', '/')} HTTP/1.1",
                        "description": desc,
                        "impact": "Exploitation can lead to access bypass, database extraction, or remote execution.",
                        "remediation": "Apply vendor recommendations and sanitize input flows.",
                        "references": cve.get("references") or []
                    })
                else:
                    cvss = float(cve.get("cvss") or 0.0)
                    severity = derive_severity_from_cvss(cvss)
                    
                    tech_cves.append({
                        "finding_type": "technology_cve",
                        "title": title,
                        "severity": severity,
                        "target": target,
                        "host": subdomain,
                        "service_name": tech.get("technology") or "Web Service",
                        "technology_stack": tech.get("technology") or "Web Service",
                        "version": tech.get("version") or "Unknown",
                        "cve_id": cve_id,
                        "cvss_score": cvss,
                        "cwe": cwe,
                        "description": desc,
                        "impact": "Exposure to known public vulnerabilities on this technology stack.",
                        "remediation": "Upgrade component stack or disable unused services.",
                        "references": cve.get("references") or []
                    })

    # 3. Gather from HTTP Anomalies (Model 4 results)
    http_anomalies = scan_results.get("http_anomalies", []) or []
    for anom in http_anomalies:
        subdomain = anom.get("subdomain") or target
        anom_res = anom.get("model4_result", {})
        status = anom_res.get("status")
        
        if status == "suspicious":
            key = ("HTTP-ANOMALY", subdomain)
            if key in seen:
                continue
            seen.add(key)
            
            traffic_data = anom_res.get("traffic_data") or {}
            score = anom_res.get("anomaly_score") or 0.0
            justification = anom_res.get("justification") or f"Classification triggered by Isolation Forest anomaly score of {score}."
            
            traffic_anomalies.append({
                "finding_type": "traffic_anomaly",
                "target": target,
                "host": subdomain,
                "packet_count": traffic_data.get("packet_count") or 0,
                "syn_count": traffic_data.get("tcp_syn_count") or 0,
                "ip_count": traffic_data.get("unique_ips") or 0,
                "anomaly_score": score,
                "classification": "suspicious",
                "explanation": justification
            })

    return web_exploits, tech_cves, traffic_anomalies

def gather_vulnerabilities(scan_results: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
    """
    Extracts and normalizes vulnerabilities, excluding anomalies from the vulnerability index.
    """
    web_exploits, tech_cves, _ = classify_and_segregate_findings(scan_results, target)
    return web_exploits + tech_cves

def run_export_pipeline(scan_results: Dict[str, Any], target: str, scan_id: str) -> Dict[str, Any]:
    """
    Orchestrates the gathering of findings and execution of Markdown, JSON and Burp Suite exporters.
    """
    web_exploits, tech_cves, traffic_anomalies = classify_and_segregate_findings(scan_results, target)
    
    # Enrich with scan_id
    for w in web_exploits:
        w["scan_id"] = scan_id
    for t in tech_cves:
        t["scan_id"] = scan_id
    for ta in traffic_anomalies:
        ta["scan_id"] = scan_id

    # 1. Trigger Markdown export (always enabled)
    markdown_file = generate_markdown_report(web_exploits, tech_cves, traffic_anomalies, target)
    
    # 2. Trigger JSON export (always enabled)
    json_file = generate_json_export(web_exploits, tech_cves, traffic_anomalies, target)
    
    # 3. Trigger Burp export (conditionally enabled: only if web_exploits are present)
    burp_file = generate_burp_export(web_exploits, target)
    
    burp_available = burp_file is not None
    burp_reason = None
    if not burp_available:
        burp_reason = "No replayable web exploit findings available."

    return {
        "vulnerabilities": web_exploits + tech_cves,
        "report_files": {
            "burp": burp_file,
            "markdown": markdown_file,
            "json": json_file
        },
        "export_status": {
            "burp_available": burp_available,
            "burp_reason": burp_reason
        }
    }

