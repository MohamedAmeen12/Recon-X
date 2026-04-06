import os
import pdfkit
from jinja2 import Template
from datetime import datetime

# Path to wkhtmltopdf executable
def get_pdfkit_config():
    """
    Search for wkhtmltopdf executable and return pdfkit configuration.
    """
    possible_paths = [
        r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\wkhtmltopdf\bin\wkhtmltopdf.exe'
    ]
    
    # Also check if it's in the PATH
    import shutil
    path_in_env = shutil.which("wkhtmltopdf")
    if path_in_env:
        return pdfkit.configuration(wkhtmltopdf=path_in_env)

    for path in possible_paths:
        if os.path.exists(path):
            return pdfkit.configuration(wkhtmltopdf=path)
            
    return None

config = get_pdfkit_config()

def generate_html_report(scan_results, domain, username, scan_id):
    """
    Generates a high-end, modern dashboard-style HTML report for PDF export.
    Syncs ALL data from the website scan report into the PDF.
    """
    # --- 1. DATA EXTRACTION ---
    subdomains = scan_results.get("raw_docs", []) or []
    vulns_m6 = scan_results.get("model6", []) or []
    recommendations = scan_results.get("recommendations", []) or []
    clusters = scan_results.get("clusters", []) or []
    tech_fingerprints = scan_results.get("technology_fingerprints", []) or []
    anomalies = scan_results.get("http_anomalies", []) or []
    model5 = scan_results.get("model5", {}) or {}
    if not isinstance(model5, dict): model5 = {}
    model5_strategies = model5.get("strategies", []) or []

    # Defensive cleaning for nested fields
    for c in clusters:
        if not c.get("examples"): c["examples"] = []
    
    for t in tech_fingerprints:
        if not t.get("technologies"): t["technologies"] = []
        for tech in t["technologies"]:
            if not tech.get("cves"): tech["cves"] = []

    for a in anomalies:
        if not a.get("model4_result"): a["model4_result"] = {"status": "unknown", "traffic_data": {}}
        if not a["model4_result"].get("traffic_data"): a["model4_result"]["traffic_data"] = {}

    for strat in model5_strategies:
        if not strat.get("attack_chain"): strat["attack_chain"] = []
        if not strat.get("exploit_db_reference"): strat["exploit_db_reference"] = []

    # Metrics
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns_m6:
        sev = str(v.get("risk_level", v.get("severity", ""))).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    total_vulns = len(vulns_m6)
    critical_count = severity_counts["CRITICAL"]
    high_count = severity_counts["HIGH"]
    
    # Risk Score
    risk_score = min(100, (critical_count * 25 + high_count * 10 + severity_counts["MEDIUM"] * 5) / (max(1, len(subdomains) / 2)))
    risk_score = round(risk_score, 1)

    # Ports for dashboard
    ports = []
    for host in scan_results.get("hosts", []) or []:
        for p in host.get("ports", []) or []:
            ports.append(p)

    # --- 2. RECOMMENDATION GROUPING (Same Logic for Card Consistency) ---
    findings_by_service = {}
    for rec in recommendations:
        service = rec.get("service", "General Infrastructure")
        if service not in findings_by_service:
            findings_by_service[service] = []
        findings_by_service[service].append(rec)

    grouped_findings = []
    for service, service_recs in findings_by_service.items():
        patterns = {}
        for rec in service_recs:
            exp = rec.get("explanation", "Finding identified during analysis.")
            pattern_key = exp[:80].lower().strip()
            if pattern_key not in patterns:
                patterns[pattern_key] = {
                    "display_title": f"{service} Vulnerabilities",
                    "explanation": exp,
                    "attacker_perspective": rec.get("attacker_perspective", "Potential for exploitation exists."),
                    "remediation": rec.get("remediation", []),
                    "severity": str(rec.get("severity", "LOW")).upper(),
                    "cvss": rec.get("cvss_score", 0),
                    "cve_ids": [],
                    "instances": [],
                    "impact": f"Unauthorized access or service disruption via {service} layer."
                }
            if rec.get("attacker_perspective") and len(rec.get("attacker_perspective")) < 120:
                patterns[pattern_key]["impact"] = rec.get("attacker_perspective")
            cve = rec.get("cve_id", "N/A")
            if cve != "N/A" and cve not in patterns[pattern_key]["cve_ids"]:
                patterns[pattern_key]["cve_ids"].append(cve)
            inst = f"{rec.get('host', 'N/A')}:{rec.get('port', 'N/A')}"
            if inst not in patterns[pattern_key]["instances"]:
                patterns[pattern_key]["instances"].append(inst)
        
        for p in patterns.values():
            if len(p["cve_ids"]) > 1: p["display_title"] = f"Multiple {service} Issues ({len(p['cve_ids'])} CVEs)"
            elif p["cve_ids"]: p["display_title"] = f"{p['cve_ids'][0]}"
            grouped_findings.append(p)

    grouped_findings.sort(key=lambda x: ({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0)), reverse=True)

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1e293b; background: #ffffff; margin: 0; padding: 0; line-height: 1.5; font-size: 10pt; }
            .clearfix:after { content: ""; display: table; clear: both; }
            .page-break { page-break-after: always; }
            
            /* Cover Page */
            .cover { height: 950pt; background: #111827; color: white; text-align: center; padding-top: 150pt; box-sizing: border-box; border-left: 20pt solid #3b82f6; }
            .cover h1 { font-size: 40pt; font-weight: 800; margin: 0; letter-spacing: -1pt; }
            .cover p { font-size: 14pt; color: #3b82f6; text-transform: uppercase; letter-spacing: 4pt; font-weight: 600; margin-top: 15pt; }
            .cover-meta { margin-top: 350pt; font-size: 11pt; color: #9ca3af; }
            .cover-meta b { color: white; display: block; font-size: 13pt; margin-top: 5pt; margin-bottom: 20pt; }

            /* Header Section */
            .report-header { background: #111827; color: white; padding: 25pt 40pt; box-sizing: border-box; border-left: 10pt solid #3b82f6; }
            .report-header h2 { margin: 0; font-size: 18pt; }
            .report-header p { margin: 3pt 0 0 0; color: #3b82f6; font-size: 9pt; font-weight: 700; text-transform: uppercase; }

            /* Dashboard */
            .dashboard { padding: 30pt 40pt; background: #f9fafb; border-bottom: 1px solid #e5e7eb; }
            .card-wrapper { width: 23%; float: left; margin-right: 2%; box-sizing: border-box; }
            .card-wrapper:last-child { margin-right: 0; }
            .metric-card { background: white; padding: 15pt 10pt; border-radius: 8pt; border: 1px solid #e5e7eb; text-align: center; }
            .metric-card .val { font-size: 22pt; font-weight: 800; display: block; color: #111827; }
            .metric-card .lbl { font-size: 7pt; color: #6b7280; text-transform: uppercase; font-weight: 700; margin-top: 4pt; display: block; }
            .acc-red { border-top: 3pt solid #ef4444; }
            .acc-blue { border-top: 3pt solid #3b82f6; }

            /* Content Sections */
            .container { padding: 40pt; }
            .section-title { font-size: 18pt; font-weight: 800; color: #111827; margin-bottom: 20pt; border-bottom: 2pt solid #3b82f6; display: inline-block; padding-bottom: 4pt; }
            
            /* Tables */
            table { width: 100%; border-collapse: collapse; margin-bottom: 20pt; font-size: 9pt; }
            th { text-align: left; background: #f3f4f6; padding: 8pt 12pt; color: #4b5563; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e5e7eb; }
            td { padding: 8pt 12pt; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
            
            /* Badges */
            .badge { padding: 2pt 6pt; border-radius: 4pt; font-size: 8pt; font-weight: 700; color: white; display: inline-block; }
            .bg-red { background: #ef4444; }
            .bg-orange { background: #f97316; }
            .bg-yellow { background: #eab308; }
            .bg-green { background: #10b981; }
            .bg-blue { background: #3b82f6; }

            /* Cards */
            .glass-card { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10pt; padding: 15pt; margin-bottom: 20pt; page-break-inside: avoid; }
            .card-title { font-size: 11pt; font-weight: 700; color: #111827; margin-bottom: 10pt; display: block; }
            
            /* Cluster Items */
            .cluster-item { padding: 6pt 0; border-bottom: 1px dashed #f3f4f6; }
            .cluster-item:last-child { border-bottom: 0; }
            
            /* Anomaly Cards */
            .anomaly-grid { width: 32%; float: left; margin-right: 1.33%; box-sizing: border-box; }
            .anomaly-grid:last-child { margin-right: 0; }

            /* Attack Path Section */
            .path-step { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10pt 15pt; border-radius: 6pt; display: inline-block; font-weight: 700; font-size: 9pt; margin-right: 10pt; }
            .path-arrow { color: #3b82f6; font-weight: bold; margin-right: 10pt; }

            @page { margin: 0; }
        </style>
    </head>
    <body>
        <div class="cover">
            <h1>THREAT INTELLIGENCE</h1>
            <p>Integrated Vulnerability Audit</p>
            <div class="cover-meta">
                TARGET DOMAIN<b>{{ domain }}</b>
                REPORT GENERATED<b>{{ date }}</b>
                AUDIT IDENTIFIER<b>RX-{{ scan_id[:12].upper() }}</b>
            </div>
        </div>

        <div class="report-header">
            <h2>Executive Overview</h2>
            <p>Unified Assessment Dashboard</p>
        </div>

        <div class="dashboard clearfix">
            <div class="card-wrapper"><div class="metric-card"><span class="val">{{ subdomains|length }}</span><span class="lbl">Subdomains</span></div></div>
            <div class="card-wrapper"><div class="metric-card"><span class="val">{{ total_vulns }}</span><span class="lbl">Verifiable Vulns</span></div></div>
            <div class="card-wrapper"><div class="metric-card acc-red"><span class="val">{{ critical_count }}</span><span class="lbl">Critical Risks</span></div></div>
            <div class="card-wrapper"><div class="metric-card acc-blue"><span class="val">{{ risk_score }}%</span><span class="lbl">Global Risk Score</span></div></div>
        </div>

        <div class="container" style="padding-bottom: 0;">
            <h3 class="section-title">Network Topology Clusters</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Logical grouping of assets based on shared infrastructure and service patterns.</p>
            
            <div class="clearfix">
                {% for c in clusters %}
                <div style="width: 48%; float: left; margin-right: 2%; margin-bottom: 20pt;">
                    <div class="glass-card" style="margin-bottom: 0;">
                        <span class="card-title">Cluster {{ c.cluster_id }} ({{ c.size }} Nodes)</span>
                        <div style="max-height: 200pt; overflow: hidden;">
                            {% for sub in c.examples[:10] %}
                            <div class="cluster-item">
                                <span style="font-weight: 600;">{{ sub }}</span>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                {% if loop.index is divisibleby 2 %}<div class="clearfix"></div>{% endif %}
                {% endfor %}
            </div>
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 20pt; padding-bottom: 0;">
            <h3 class="section-title">Technology Fingerprinting</h3>
            {% for t in tech_fingerprints %}
            <div class="glass-card">
                <span class="card-title" style="color: #3b82f6;">{{ t.url }}</span>
                <table>
                    <thead>
                        <tr><th>Technology</th><th>Version</th><th>Vulnerabilities</th></tr>
                    </thead>
                    <tbody>
                        {% for tech in t.technologies %}
                        <tr>
                            <td><b>{{ tech.technology }}</b></td>
                            <td>{{ tech.version or 'Unknown' }}</td>
                            <td>
                                {% if tech.cves %}
                                    {% for cve in tech.cves[:3] %}
                                    <div style="margin-bottom: 2pt;">
                                        <span class="badge bg-red" style="font-size: 7pt;">{{ cve.cve }}</span>
                                        <span style="font-size: 7pt; color: #6b7280;">(CVSS {{ cve.cvss }})</span>
                                    </div>
                                    {% endfor %}
                                {% else %}
                                    <span style="color: #10b981; font-weight: 700;">SECURE</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endfor %}
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 20pt; padding-bottom: 0;">
            <h3 class="section-title">Traffic Anomaly Analysis</h3>
            <div class="clearfix">
                {% for a in anomalies %}
                <div class="anomaly-grid">
                    <div class="glass-card" style="border-left: 4pt solid {% if a.model4_result.status == 'suspicious' %}#ef4444{% else %}#10b981{% endif %};">
                        <span class="card-title" style="font-size: 9pt;">{{ a.subdomain }}</span>
                        <div style="font-size: 8pt; color: #6b7280;">
                            Status: <b style="color: {% if a.model4_result.status == 'suspicious' %}#ef4444{% else %}#10b981{% endif %};">{{ a.model4_result.status|upper }}</b><br>
                            Unique IPs: <b>{{ a.model4_result.traffic_data.unique_ips }}</b><br>
                            SYN Count: <b>{{ a.model4_result.traffic_data.tcp_syn_count }}</b>
                        </div>
                    </div>
                </div>
                {% if loop.index is divisibleby 3 %}<div class="clearfix"></div>{% endif %}
                {% endfor %}
            </div>
        </div>

        <div class="container" style="padding-top: 20pt;">
            <h3 class="section-title">Exploitation Intelligence</h3>
            {% for strat in model5_strategies %}
            <div class="glass-card">
                <span class="badge bg-red" style="float: right;">{{ strat.evidence_status }}</span>
                <span class="card-title">{{ strat.cve_id }}</span>
                <p style="font-size: 9pt; font-style: italic; color: #4b5563; margin-bottom: 10pt;">"{{ strat.explanation }}"</p>
                
                <h4 style="font-size: 8pt; margin-bottom: 5pt; color: #6b7280;">PREDICTED ATTACK PATH</h4>
                <div class="clearfix" style="margin-bottom: 10pt;">
                    {% for step in strat.attack_chain %}
                    <span class="path-step">{{ step }}</span>
                    {% if not loop.last %}<span class="path-arrow">→</span>{% endif %}
                    {% endfor %}
                </div>

                {% if strat.exploit_db_reference %}
                <h4 style="font-size: 8pt; margin-bottom: 5pt; color: #6b7280;">EXPLOIT-DB INTELLIGENCE</h4>
                <ul style="font-size: 8pt; color: #3b82f6; padding-left: 15pt;">
                    {% for ref in strat.exploit_db_reference %}
                    <li><a href="{{ ref.url }}" style="color: #3b82f6;">{{ ref.title }}</a></li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 20pt;">
            <h3 class="section-title">Verifiable Vulnerability Index</h3>
            <table>
                <thead>
                    <tr><th>CVE ID</th><th>Service/URL</th><th>Port</th><th>CVSS</th><th>Risk</th></tr>
                </thead>
                <tbody>
                    {% for v in vulns_m6 %}
                    <tr>
                        <td style="font-weight: 700; color: #3b82f6;">{{ v.cve_id or 'N/A' }}</td>
                        <td>{{ v.service or 'System' }}</td>
                        <td>{{ v.port or 'N/A' }}</td>
                        <td><b>{{ v.cvss or 'N/A' }}</b></td>
                        <td><span class="badge {% if v.risk_level == 'Critical' %}bg-red{% elif v.risk_level == 'High' %}bg-orange{% elif v.risk_level == 'Medium' %}bg-yellow{% else %}bg-green{% endif %}">{{ v.risk_level }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="container" style="padding-top: 0;">
            <h3 class="section-title">Actionable Remediation Roadmap</h3>
            {% for find in grouped_findings %}
            <div class="glass-card" style="border-left: 4pt solid {% if find.severity == 'CRITICAL' %}#ef4444{% elif find.severity == 'HIGH' %}#f97316{% else %}#eab308{% endif %};">
                <span class="card-title">{{ find.display_title }}</span>
                <p style="font-size: 9pt; margin-bottom: 10pt;">{{ find.explanation[:200] }}...</p>
                <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10pt; border-radius: 6pt;">
                    <h5 style="margin: 0 0 5pt 0; color: #166534; font-size: 8pt;">REMEDIATION PLAN</h5>
                    <ul style="font-size: 8pt; color: #14532d; margin: 0; padding-left: 15pt;">
                        {% for step in find.remediation %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    
    template = Template(html_template)
    return template.render(
        username=username,
        domain=domain,
        date=datetime.now().strftime("%B %d, %Y"),
        scan_id=scan_id,
        subdomains=subdomains,
        ports=ports,
        total_vulns=total_vulns,
        critical_count=critical_count,
        risk_score=risk_score,
        grouped_findings=grouped_findings,
        clusters=clusters,
        tech_fingerprints=tech_fingerprints,
        anomalies=anomalies,
        model5=model5,
        model5_strategies=model5_strategies,
        vulns_m6=vulns_m6
    )

def generate_pdf_report(html_file_path):
    """
    Converts the HTML file to PDF using wkhtmltopdf.
    """
    output_pdf = html_file_path.replace(".html", ".pdf")
    options = {
        'page-size': 'A4',
        'margin-top': '0mm', 'margin-right': '0mm', 'margin-bottom': '0mm', 'margin-left': '0mm',
        'encoding': "UTF-8", 'no-outline': None, 'enable-local-file-access': None, 'quiet': None
    }
    if not config: return None
    try:
        pdfkit.from_file(html_file_path, output_pdf, configuration=config, options=options)
        return output_pdf
    except Exception as e:
        print(f"[!] ERROR during PDF generation: {str(e)}")
        return None
