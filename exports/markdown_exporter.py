import os
import uuid
import datetime
from typing import List, Dict

def generate_markdown_report(
    web_exploits: List[Dict],
    tech_cves: List[Dict],
    traffic_anomalies: List[Dict],
    target: str
) -> str:
    """
    Generate HackerOne-style Markdown vulnerability report partitioned into three distinct sections.
    Does NOT synthesize fake request contexts.
    Saves the file to reports/reconx_report_<scan_id>.md and returns the filename.
    """
    # Extract scan_id from findings if present
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

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    md = []
    md.append(f"# ReconX Security Assessment Report: {target}\n")
    
    # Executive Summary
    md.append("## Executive Summary")
    md.append(f"**Target Host:** {target}")
    md.append(f"**Generated At:** {generated_at}")
    md.append(f"**Web Exploits Identified:** {len(web_exploits)}")
    md.append(f"**Technology Stack CVEs:** {len(tech_cves)}")
    md.append(f"**Traffic Anomalies Logged:** {len(traffic_anomalies)}\n")

    # --- SECTION 1: Web Exploit Findings ---
    md.append("## 1. Web Exploit Findings")
    md.append("This section documents verified web application exploits that contain authentic, replayable HTTP request contexts captured during scan execution.")
    md.append("")
    
    if not web_exploits:
        md.append("*No replayable web exploit findings were detected during this scan.*")
        md.append("")
    else:
        for i, vuln in enumerate(web_exploits, 1):
            title = vuln.get("title") or "Web Exploit"
            sev = str(vuln.get("severity") or "Low").capitalize()
            host = vuln.get("host") or target
            endpoint = vuln.get("endpoint") or "/"
            url = vuln.get("url") or "N/A"
            method = vuln.get("http_method") or "GET"
            headers = vuln.get("request_headers") or {}
            body = vuln.get("request_body") or ""
            
            md.append(f"### 1.{i} [{sev}] {title}")
            if vuln.get("cve_id"):
                md.append(f"- **CVE Identifier:** `{vuln.get('cve_id')}`")
            md.append(f"- **Target URL:** {url}")
            md.append(f"- **Method:** `{method}`")
            md.append(f"- **Affected Host:** `{host}`")
            md.append(f"- **Endpoint Path:** `{endpoint}`")
            md.append("")
            md.append(f"**Description:**\n{vuln.get('description', 'N/A')}\n")
            md.append(f"**Impact:**\n{vuln.get('impact', 'N/A')}\n")
            md.append(f"**Remediation:**\n{vuln.get('remediation', 'N/A')}\n")
            
            # Reconstruct raw request context from headers
            headers_str = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            raw_req = f"{method} {endpoint} HTTP/1.1\r\n{headers_str}\r\n{body}"
            
            md.append("**Proof of Concept (Captured Request):**")
            md.append(f"```http\n{raw_req.strip()}\n```\n")

            if vuln.get("references"):
                md.append("**References:**")
                for ref in vuln.get("references", []):
                    md.append(f"- {ref}")
                md.append("")

    # --- SECTION 2: Technology CVE Findings ---
    md.append("## 2. Technology CVE Findings")
    md.append("This section lists fingerprinted technology stack elements matching public CVE databases. These are security intelligence findings, not active exploit request payloads.")
    md.append("")

    if not tech_cves:
        md.append("*No technology stack CVEs were fingerprinted during this scan.*")
        md.append("")
    else:
        for i, vuln in enumerate(tech_cves, 1):
            title = vuln.get("title") or "Technology CVE"
            sev = str(vuln.get("severity") or "Low").capitalize()
            cve_id = vuln.get("cve_id") or "N/A"
            cvss = vuln.get("cvss_score") or 0.0
            tech_stack = vuln.get("technology_stack") or "N/A"
            version = vuln.get("version") or "N/A"
            
            md.append(f"### 2.{i} [{sev}] {title}")
            md.append(f"- **CVE Identifier:** `{cve_id}`")
            md.append(f"- **CVSS v3 Score:** `{cvss}`")
            md.append(f"- **Technology Component:** `{tech_stack}` (Version: `{version}`)")
            md.append(f"- **CWE Classification:** `{vuln.get('cwe', 'N/A')}`")
            md.append("")
            md.append(f"**Description:**\n{vuln.get('description', 'N/A')}\n")
            md.append(f"**Impact:**\n{vuln.get('impact', 'N/A')}\n")
            md.append(f"**Remediation:**\n{vuln.get('remediation', 'N/A')}\n")

            references = vuln.get("references") or []
            if cve_id != "N/A" and f"https://nvd.nist.gov/vuln/detail/{cve_id}" not in references:
                references = list(references) + [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

            if references:
                md.append("**References:**")
                for ref in references:
                    md.append(f"- {ref}")
                md.append("")

    # --- SECTION 3: Traffic Anomaly Findings ---
    md.append("## 3. Traffic Anomaly Findings")
    md.append("This section documents behavioral deviations in network traffic flow metrics identified using unsupervised machine learning. These findings represent intelligence observations, not exploit pathways.")
    md.append("")

    if not traffic_anomalies:
        md.append("*No traffic anomalies were detected during this scan.*")
        md.append("")
    else:
        for i, anom in enumerate(traffic_anomalies, 1):
            host = anom.get("host") or target
            score = anom.get("anomaly_score") or 0.0
            
            md.append(f"### 3.{i} Traffic Anomaly on Host `{host}`")
            md.append(f"- **Anomaly Classifier Score:** `{score}`")
            md.append(f"- **Metrics Logged:**")
            md.append(f"  - Packet Count: `{anom.get('packet_count', 0)}`")
            md.append(f"  - TCP SYN Count: `{anom.get('syn_count', 0)}`")
            md.append(f"  - Unique Source IPs: `{anom.get('ip_count', 0)}`")
            md.append("")
            md.append(f"**Mathematical Justification:**\n{anom.get('explanation', 'N/A')}\n")

    # Join the lines with clean breaks
    content = "\n".join(md)

    # Save to reports directory
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = f"reconx_report_{scan_id}.md"
    file_path = os.path.join(reports_dir, filename)
    with open(file_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    return filename

