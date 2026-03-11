import os
import pdfkit
from jinja2 import Template
from datetime import datetime

# Path to wkhtmltopdf executable
WKHTMLTOPDF_PATH = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)

def generate_html_report(scan_results, domain, username, scan_id):
    """
    Generates a professional HTML report using Jinja2 with Nessus-style layout.
    """
    
    # 1. FIX MODEL 2 PORT EXTRACTION (Requested Implementation)
    ports = []
    for host in scan_results.get("hosts", []) or []:
        for port in host.get("ports", []) or []:
            ports.append({
                "port": port.get("port"),
                "service": port.get("service"),
                "version": port.get("version", "Unknown"),
                "host": host.get("domain")
            })

    # Safely extract other data
    subdomains = scan_results.get("raw_docs", []) or []
    vulns = scan_results.get("model6", []) or []
    technologies = scan_results.get("technology_fingerprints", []) or []
    recommendations = scan_results.get("recommendations", []) or []
    
    # Severity counts
    critical_count = sum(1 for v in vulns if v and str(v.get("risk_level", v.get("severity", ""))).upper() == "CRITICAL")
    high_count = sum(1 for v in vulns if v and str(v.get("risk_level", v.get("severity", ""))).upper() == "HIGH")
    medium_count = sum(1 for v in vulns if v and str(v.get("risk_level", v.get("severity", ""))).upper() == "MEDIUM")
    low_count = sum(1 for v in vulns if v and str(v.get("risk_level", v.get("severity", ""))).upper() == "LOW")
    
    # Path to logo
    logo_path = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "logo.png"))
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
            
            body { 
                font-family: 'Inter', 'Helvetica', 'Arial', sans-serif; 
                color: #1e293b; 
                line-height: 1.6; 
                margin: 0; 
                padding: 0; 
                background-color: #fcfcfd;
                word-spacing: normal;
                letter-spacing: normal;
            }

            p { white-space: normal; }
            
            /* Cover Page Style - Center Horizontally and Vertically */
            .cover-page { 
                height: 100vh; 
                display: flex; 
                flex-direction: column; 
                justify-content: center; 
                align-items: center; 
                text-align: center; 
                page-break-after: always; 
                background: white;
            }
            .logo { width: 120px; margin-bottom: 25px; }
            .report-type { 
                background: #1d4ed8; 
                color: white; 
                padding: 8px 20px; 
                border-radius: 50px; 
                font-weight: bold; 
                letter-spacing: 2px; 
                margin-bottom: 20px;
                font-size: 12px;
            }
            .report-title { font-size: 28px; font-weight: bold; color: #0f172a; margin-bottom: 40px; }
            .report-meta { 
                font-size: 16px; 
                line-height: 1.8;
                color: #64748b;
            }
            
            /* General Layout */
            .content-page { padding: 40px 60px; }
            h1 { 
                color: #1d4ed8; 
                font-size: 24px; 
                font-weight: bold;
                border-bottom: 2px solid #1d4ed8; 
                padding-bottom: 10px; 
                margin-top: 30px; 
                margin-bottom: 20px;
                text-transform: uppercase;
            }
            h3 { color: #334155; font-size: 18px; margin-top: 25px; margin-bottom: 15px; }
            
            /* Summary Cards */
            .summary-container { 
                display: table; 
                width: 100%; 
                margin: 20px 0;
                border-spacing: 15px 0;
            }
            .summary-card { 
                display: table-cell;
                background: white; 
                border: 1px solid #e2e8f0; 
                padding: 20px; 
                border-radius: 8px; 
                text-align: center; 
                box-shadow: 0 2px 8px rgba(0,0,0,0.04);
                width: 33%;
            }
            .summary-card .count { font-size: 32px; font-weight: bold; color: #1d4ed8; }
            .summary-card .label { font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase; }
            
            /* Tables */
            table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; }
            th, td { border: 1px solid #e2e8f0; padding: 12px; text-align: left; }
            th { background-color: #f8fafc; font-weight: bold; color: #334155; font-size: 12px; text-transform: uppercase; }
            td { font-size: 13px; color: #475569; }
            
            /* Badges */
            .badge { 
                display: inline-block; 
                padding: 4px 10px; 
                border-radius: 4px; 
                font-weight: bold; 
                font-size: 11px; 
                color: white; 
                text-transform: uppercase; 
            }
            .badge-critical { background-color: #ef4444; }
            .badge-high { background-color: #f97316; }
            .badge-medium { background-color: #eab308; }
            .badge-low { background-color: #22c55e; }
            .badge-unknown { background-color: #94a3b8; }
            
            /* Compact Vulnerability Blocks */
            .vuln-block {
                border-bottom: 1px solid #e2e8f0;
                padding: 20px 0;
                margin-bottom: 10px;
            }
            .vuln-block:last-child { border-bottom: none; }
            .vuln-block-header { 
                font-size: 18px; 
                font-weight: bold; 
                color: #0f172a; 
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .vuln-info-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; font-size: 13px; margin-bottom: 15px; }
            .vuln-info-item strong { color: #334155; }
            .vuln-section-title { font-size: 14px; font-weight: bold; color: #334155; margin-top: 12px; margin-bottom: 5px; }
            .vuln-text { font-size: 13px; color: #475569; margin-bottom: 8px; }
            .vuln-list { padding-left: 18px; margin: 0; font-size: 13px; color: #475569; }
            
            /* Static Attack Chain */
            .chain-flow {
                display: flex;
                flex-direction: column;
                align-items: center;
                margin: 30px 0;
            }
            .flow-box {
                width: 250px;
                padding: 15px;
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                text-align: center;
                font-weight: bold;
                box-shadow: 0 2px 6px rgba(0,0,0,0.05);
            }
            .flow-arrow { font-size: 24px; color: #1d4ed8; margin: 10px 0; }
            
            .footer { text-align: center; font-size: 11px; color: #94a3b8; margin-top: 40px; }
            .page-break { page-break-after: always; }
        </style>
    </head>
    <body>
        <div class="cover-page">
            <img src="{{ logo_path }}" class="logo" alt="ReconX Logo">
            <div class="report-type">CYBERSECURITY REPORT</div>
            <div class="report-title">RECONX SECURITY ASSESSMENT REPORT</div>
            <div class="report-meta">
                User: {{ username }}<br>
                Target Domain: {{ domain }}<br>
                Scan Date: {{ date }}<br>
                Scan ID: {{ scan_id }}
            </div>
        </div>

        <div class="content-page">
            <h1>SECTION 1 — EXECUTIVE SUMMARY</h1>
            <p>This security assessment report summarizes findings from an automated scan of {{ domain }}.</p>
            
            <div class="summary-container">
                <div class="summary-card">
                    <div class="count">{{ subdomains|length }}</div>
                    <div class="label">Subdomains</div>
                </div>
                <div class="summary-card">
                    <div class="count">{{ ports|length }}</div>
                    <div class="label">Open Ports</div>
                </div>
                <div class="summary-card">
                    <div class="count">{{ vulns|length }}</div>
                    <div class="label">Vulnerabilities</div>
                </div>
            </div>
            
            <h3>Risk Distribution</h3>
            <table>
                <tr><th>Severity</th><th>Count</th><th>Description</th></tr>
                <tr><td><span class="badge badge-critical">CRITICAL</span></td><td>{{ critical_count }}</td><td>Critical impact requiring immediate remediation.</td></tr>
                <tr><td><span class="badge badge-high">HIGH</span></td><td>{{ high_count }}</td><td>High risk vulnerabilities prone to exploitation.</td></tr>
                <tr><td><span class="badge badge-medium">MEDIUM</span></td><td>{{ medium_count }}</td><td>Moderate security flaws.</td></tr>
                <tr><td><span class="badge badge-low">LOW</span></td><td>{{ low_count }}</td><td>Minor security issues or hardening info.</td></tr>
            </table>

            <div class="page-break"></div>

            <h1>SECTION 2 — RECONNAISSANCE RESULTS</h1>
            <h3>Discovered Subdomains</h3>
            <table>
                <tr><th>Subdomain</th><th>IP Address</th><th>Status</th></tr>
                {% for sub in (subdomains or []) %}
                {% if sub is not none %}
                <tr>
                    <td>{{ sub.subdomain if sub is mapping else sub }}</td>
                    <td>{{ sub.ip if sub is mapping else "N/A" }}</td>
                    <td>{{ sub.status if sub is mapping else "Active" }}</td>
                </tr>
                {% endif %}
                {% endfor %}
            </table>

            <h3>Open Ports & Services</h3>
            <table>
                <tr><th>Port</th><th>Service</th><th>Version</th><th>Source Host</th></tr>
                {% for port in (ports or []) %}
                {% if port is not none %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version }}</td>
                    <td>{{ port.host }}</td>
                </tr>
                {% endif %}
                {% endfor %}
            </table>

            <h3>Technology Fingerprinting</h3>
            <table>
                <tr><th>Technology</th><th>Category</th><th>Version</th><th>Target URL</th></tr>
                {% for tech_batch in (technologies or []) %}
                    {% if tech_batch is not none %}
                        {% for item in (tech_batch.get('technologies') or []) %}
                            {% if item is not none %}
                            <tr>
                                <td><strong>{{ item.get('technology') or 'Unknown' }}</strong></td>
                                <td>{{ item.get('category') or 'Unknown' }}</td>
                                <td>{{ item.get('version') or 'N/A' }}</td>
                                <td>{{ tech_batch.get('url') or 'N/A' }}</td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    {% endif %}
                {% endfor %}
            </table>

            <div class="page-break"></div>

            <h1>SECTION 3 — ATTACK CHAIN ANALYSIS</h1>
            <div class="chain-flow">
                <div class="flow-box">Reconnaissance</div>
                <div class="flow-arrow">↓</div>
                <div class="flow-box">Service Discovery</div>
                <div class="flow-arrow">↓</div>
                <div class="flow-box">Web Exploitation</div>
                <div class="flow-arrow">↓</div>
                <div class="flow-box">Data Exposure</div>
            </div>

            <div class="page-break"></div>

            <h1>SECTION 4 — VULNERABILITY DETAILS</h1>
            
            <h3>Vulnerability Summary Matrix</h3>
            <table>
                <tr><th>CVE ID</th><th>Service</th><th>Port</th><th>CVSS</th><th>Severity</th></tr>
                {% for vuln in (vulns or []) %}
                {% if vuln is not none %}
                    {% set sev = (vuln.get('risk_level') or vuln.get('severity') or "UNKNOWN")|upper %}
                    <tr>
                        <td><strong>{{ vuln.get('cve_id') }}</strong></td>
                        <td>{{ vuln.get('service_name') or vuln.get('service') }}</td>
                        <td>{{ vuln.get('port_number') or vuln.get('port') }}</td>
                        <td>{{ vuln.get('cvss_score') or vuln.get('cvss') }}</td>
                        <td><span class="badge badge-{{ sev|lower }}">{{ sev }}</span></td>
                    </tr>
                {% endif %}
                {% endfor %}
            </table>

            <br><hr><br>

            {% for rec in (recommendations or []) %}
            {% if rec is not none %}
            <div class="vuln-block">
                <div class="vuln-block-header">
                    {{ rec.get('cve_id') }} — 
                    {% set sev = (rec.get('severity') or "UNKNOWN")|upper %}
                    <span class="badge badge-{{ sev|lower }}">{{ sev }}</span>
                </div>
                
                <div class="vuln-info-grid">
                    <div class="vuln-info-item"><strong>Service:</strong> {{ rec.get('service') }}</div>
                    <div class="vuln-info-item"><strong>Port:</strong> {{ rec.get('port') or "N/A" }}</div>
                    <div class="vuln-info-item"><strong>CVSS:</strong> {{ rec.get('cvss_score') or rec.get('cvss') or "N/A" }}</div>
                </div>

                <div class="vuln-section-title">Risk Summary</div>
                <div class="vuln-text">{{ rec.get('risk_summary') }}</div>

                <div class="vuln-section-title">Explanation</div>
                <div class="vuln-text">{{ rec.get('explanation') }}</div>

                <div class="vuln-section-title">Attacker Perspective</div>
                <div class="vuln-text">{{ rec.get('attacker_perspective') }}</div>

                <div class="vuln-section-title">Remediation</div>
                <ul class="vuln-list">
                    {% for item in (rec.get('remediation') or []) %}
                    <li>{{ item }}</li>
                    {% endfor %}
                </ul>

                <div class="vuln-section-title">References</div>
                <ul class="vuln-list">
                    {% for ref in (rec.get('references') or []) %}
                    <li><a href="{{ ref }}" style="color: #1d4ed8; text-decoration: none;">{{ ref }}</a></li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            {% endfor %}
        </div>

        <div class="footer">
            ReconX Security Platform — Confidential Security Report
        </div>
    </body>
    </html>
    """
    
    template = Template(html_template)
    return template.render(
        logo_path=logo_path,
        username=username,
        domain=domain,
        date=datetime.now().strftime("%B %d, %Y"),
        scan_id=scan_id,
        subdomains=subdomains,
        ports=ports,
        vulns=vulns,
        technologies=technologies,
        recommendations=recommendations,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )

def generate_pdf_report(html_file_path):
    """
    Converts the HTML file to PDF using wkhtmltopdf.
    """
    output_pdf = html_file_path.replace(".html", ".pdf")
    options = {
        'page-size': 'A4',
        'margin-top': '0mm',
        'margin-right': '0mm',
        'margin-bottom': '0mm',
        'margin-left': '0mm',
        'encoding': "UTF-8",
        'no-outline': None,
        'enable-local-file-access': None
    }
    
    pdfkit.from_file(html_file_path, output_pdf, configuration=config, options=options)
    return output_pdf
