import os
import uuid
import datetime
from typing import List, Dict

_GENERIC_NAMES = frozenset({"web service", "unknown", "n/a", ""})
_GENERIC_VERSIONS = frozenset({"unknown", "n/a", ""})


def _clean_tech_cves(tech_cves: List[Dict]) -> List[Dict]:
    """
    Deduplicate and filter generic/incomplete technology CVE entries.
    Mirrors the logic in json_exporter so both outputs stay consistent.

    Rules:
    1. Skip entries where service_name/technology_stack are generic placeholders.
    2. Skip entries where version is unknown/missing.
    3. Deduplicate by (service_name, version, cve_id).
    4. Apply fallback description when none is provided.
    """
    seen: set = set()
    result: List[Dict] = []

    for entry in tech_cves:
        svc = str(entry.get("service_name") or "").lower().strip()
        stack = str(entry.get("technology_stack") or "").lower().strip()
        ver = str(entry.get("version") or "").lower().strip()
        cve_id = str(entry.get("cve_id") or "").strip()

        name_key = svc or stack
        if name_key in _GENERIC_NAMES:
            continue
        if ver in _GENERIC_VERSIONS:
            continue

        dedup_key = (name_key, ver, cve_id.upper())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        entry = dict(entry)

        # Fallback description — never leave blank
        if not str(entry.get("description") or "").strip():
            entry["description"] = "No public description available."

        result.append(entry)

    return result


def _service_remediation(vuln: Dict) -> str:
    """
    Generate service-aware remediation text based on the detected technology.
    Returns a specific action rather than a generic placeholder.
    """
    svc = str(vuln.get("service_name") or vuln.get("technology_stack") or "").lower()
    ver = str(vuln.get("version") or "").strip()
    cve_id = str(vuln.get("cve_id") or "").strip()
    ver_clause = f" {ver}" if ver else ""

    if "php" in svc:
        return (
            f"Upgrade PHP{ver_clause} to a release that addresses {cve_id}. "
            "Disable dangerous functions (exec, shell_exec, passthru, system) in php.ini "
            "and set expose_php = Off."
        )
    if "apache" in svc or "httpd" in svc:
        return (
            f"Patch Apache HTTP Server{ver_clause} to the latest stable release that resolves {cve_id}. "
            "Disable unused modules (mod_status, mod_info) and enforce AllowOverride None on root directories."
        )
    if "nginx" in svc:
        return (
            f"Upgrade nginx{ver_clause} to a patched release for {cve_id}. "
            "Set server_tokens off in nginx.conf and restrict access to sensitive location blocks."
        )
    if "openssl" in svc or ("ssl" in svc and "version" in svc):
        return (
            f"Upgrade OpenSSL{ver_clause} to the latest stable release patching {cve_id}. "
            "Regenerate TLS certificates after updating and disable deprecated cipher suites."
        )
    if "wordpress" in svc or svc.startswith("wp"):
        return (
            f"Update WordPress core{ver_clause} and all active plugins to versions that patch {cve_id}. "
            "Restrict wp-admin access by IP and enable two-factor authentication."
        )
    if "mysql" in svc:
        return (
            f"Upgrade MySQL{ver_clause} to a release that resolves {cve_id}. "
            "Restrict database user privileges and block external access to port 3306."
        )
    if "mariadb" in svc:
        return (
            f"Upgrade MariaDB{ver_clause} to a patched release for {cve_id}. "
            "Apply the principle of least privilege to all database accounts."
        )
    if "openssh" in svc or svc == "ssh":
        return (
            f"Upgrade OpenSSH{ver_clause} to a version that addresses {cve_id}. "
            "Disable password authentication, enforce key-based login, and restrict PermitRootLogin."
        )
    if "jquery" in svc or ("javascript" in svc and "lib" in svc):
        return (
            f"Update {vuln.get('service_name') or 'the JavaScript library'}{ver_clause} to a version "
            f"that patches {cve_id}. Use Subresource Integrity (SRI) hashes for all CDN-hosted assets."
        )
    if "iis" in svc or "microsoft" in svc:
        return (
            f"Apply the Microsoft security update for {cve_id} via Windows Update or WSUS. "
            "Review IIS handler mappings and disable unused HTTP methods."
        )

    # Generic fallback — still includes the component name and CVE
    name = vuln.get("service_name") or vuln.get("technology_stack") or "this component"
    return (
        f"Apply the vendor security update for {name}{ver_clause} that addresses {cve_id}. "
        "Consult the NVD advisory for specific fix versions and review the vendor's hardening guide."
    )


def generate_markdown_report(
    web_exploits: List[Dict],
    tech_cves: List[Dict],
    traffic_anomalies: List[Dict],
    target: str
) -> str:
    """
    Generate HackerOne-style Markdown vulnerability report partitioned into three distinct sections.
    Does NOT synthesize fake request contexts.
    Summary counts are computed AFTER deduplication.
    Saves the file to reports/reconx_report_<scan_id>.md and returns the filename.
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

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Deduplicate and filter tech CVEs BEFORE building the executive summary
    tech_cves = _clean_tech_cves(tech_cves)

    md = []
    md.append(f"# ReconX Security Assessment Report: {target}\n")

    # Executive Summary — counts reflect deduplicated data
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

            desc = str(vuln.get("description") or "No public description available.")
            md.append(f"**Description:**\n{desc}\n")
            md.append(f"**Impact:**\n{vuln.get('impact', 'N/A')}\n")
            md.append(f"**Remediation:**\n{vuln.get('remediation', 'N/A')}\n")

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
            tech_stack = vuln.get("technology_stack") or vuln.get("service_name") or "N/A"
            version = vuln.get("version") or "N/A"

            md.append(f"### 2.{i} [{sev}] {title}")
            md.append(f"- **CVE Identifier:** `{cve_id}`")
            md.append(f"- **CVSS v3 Score:** `{cvss}`")
            md.append(f"- **Technology Component:** `{tech_stack}` (Version: `{version}`)")
            md.append(f"- **CWE Classification:** `{vuln.get('cwe', 'N/A')}`")
            md.append("")

            # Full description — never truncated, fallback already applied by _clean_tech_cves
            desc = str(vuln.get("description") or "No public description available.")
            md.append(f"**Description:**\n{desc}\n")
            md.append(f"**Impact:**\n{vuln.get('impact', 'N/A')}\n")

            # Service-aware remediation; fall back to stored value only if it is specific enough
            stored_rem = str(vuln.get("remediation") or "").strip()
            generic_placeholders = {
                "update technology stack version.",
                "upgrade component stack or disable unused services.",
                ""
            }
            if stored_rem.lower() in generic_placeholders:
                remediation_text = _service_remediation(vuln)
            else:
                remediation_text = stored_rem
            md.append(f"**Remediation:**\n{remediation_text}\n")

            # Ensure NVD reference is present
            references = list(vuln.get("references") or [])
            if cve_id != "N/A" and cve_id.upper().startswith("CVE-"):
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                if nvd_url not in references:
                    references.insert(0, nvd_url)

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

    content = "\n".join(md)

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = f"reconx_report_{scan_id}.md"
    file_path = os.path.join(reports_dir, filename)
    with open(file_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    return filename
