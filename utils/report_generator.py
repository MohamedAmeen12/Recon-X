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
            
    # If not found, return None or a dummy config and handle it in the generation function
    return None

config = get_pdfkit_config()

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
    strategies = scan_results.get("model5", {}).get("strategies", []) or []
    
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
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
            :root { --accent: #10B981; --accent-dark: #059669; --text-main: #1f2937; --text-muted: #6b7280; --border: #e5e7eb; --red: #ef4444; --orange: #f97316; --yellow: #facc15; --green: #10b981; --blue: #2563eb; }
            @page { size: A4; margin: 20mm; @bottom-right { content: "Page " counter(page); font-family: 'Inter', sans-serif; font-size: 10px; color: #9ca3af; } @bottom-left { content: "ReconX Security Platform | Confidential Report"; font-family: 'Inter', sans-serif; font-size: 10px; color: #9ca3af; } }
            body { font-family: 'Inter', sans-serif; color: var(--text-main); line-height: 1.6; margin: 0; padding: 0; background-color: #ffffff; font-size: 11pt; word-wrap: break-word; }
            .header-panel { text-align: center; margin-bottom: 40px; padding-bottom: 30px; border-bottom: 2px solid var(--border); }
            .header-logo { height: 60px; margin-bottom: 20px; }
            .header-title { font-size: 24pt; font-weight: 700; color: #111827; margin: 0 0 5px 0; }
            .header-subtitle { font-size: 12pt; color: var(--text-muted); text-transform: uppercase; font-weight: 500; letter-spacing: 1px; }
            .info-label { font-size: 9pt; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
            .info-value { font-size: 11pt; font-weight: 600; color: #111827; }
            h1.section-title { color: var(--accent); font-size: 16pt; font-weight: 700; border-bottom: 2px solid var(--accent); padding-bottom: 8px; margin-top: 32px; margin-bottom: 24px; text-transform: uppercase; page-break-after: avoid; line-height: 1.3; }
            h3 { color: #374151; font-size: 13pt; margin-top: 24px; margin-bottom: 16px; font-weight: 600; page-break-after: avoid; }
            p { margin-bottom: 16px; color: #4b5563; line-height: 1.6; }
            .summary-cards { display: table; width: 100%; margin: 24px 0; table-layout: fixed; border-spacing: 16px 0; }
            .card { display: table-cell; border: 1px solid var(--border); padding: 20px 16px; border-radius: 8px; text-align: center; }
            .card .count { font-size: 28pt; font-weight: 700; color: #111827; line-height: 1; margin-bottom: 8px; }
            .card .label { font-size: 9pt; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }
            .card-vuln .count { color: var(--orange); }
            .card-critical .count { color: var(--red); }
            .card-high .count { color: var(--orange); }
            .severity-bar { height: 6px; width: 100%; border-radius: 3px; background: #e5e7eb; margin: 24px 0; display: flex; overflow: hidden; }
            .sev-crit { background-color: var(--red); }
            .sev-high { background-color: var(--orange); }
            .sev-med { background-color: var(--yellow); }
            .sev-low { background-color: var(--green); }
            table { width: 100%; border-collapse: collapse; margin-top: 16px; margin-bottom: 32px; font-size: 10pt; }
            th, td { border: 1px solid var(--border); padding: 12px 14px; text-align: left; }
            th { background-color: #f9fafb; font-weight: 600; color: #374151; font-size: 9pt; text-transform: uppercase; padding: 14px 14px; }
            tr:nth-child(even) { background-color: #f9fafb; }
            .host-alive { color: var(--green); font-weight: 600; }
            .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 8pt; text-transform: uppercase; }
            .badge-tech { background-color: #f3f4f6; color: #374151; border: 1px solid #d1d5db; margin: 2px; }
            .badge-critical { background-color: var(--red); color: white; }
            .badge-high { background-color: var(--orange); color: white; }
            .badge-medium { background-color: var(--yellow); color: #111827; }
            .badge-low { background-color: var(--green); color: white; }
            .cvss-bold { font-weight: 700; color: #111827; }
            .attack-chain { display: table; width: 100%; margin: 32px 0; table-layout: fixed; text-align: center; }
            .chain-step { display: table-cell; vertical-align: middle; }
            .chain-box { background: #f0fdf4; border: 2px solid #86efac; border-radius: 8px; padding: 16px 12px; font-weight: 600; color: #166534; font-size: 10pt; }
            .chain-arrow { display: table-cell; vertical-align: middle; color: var(--accent); font-weight: bold; font-size: 16pt; width: 40px; }
            .cve-card { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 32px; page-break-inside: avoid; }
            .cve-card-CRITICAL { border-left: 4px solid var(--red); }
            .cve-card-HIGH { border-left: 4px solid var(--orange); }
            .cve-card-MEDIUM { border-left: 4px solid var(--yellow); }
            .cve-card-LOW { border-left: 4px solid var(--green); }
            .cve-header { background: #f9fafb; padding: 16px 20px; border-bottom: 1px solid var(--border); border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }
            .cve-title { margin: 0; font-size: 14pt; font-weight: 700; display: inline-block; }
            .cve-title-CRITICAL { color: var(--red); }
            .cve-title-HIGH { color: var(--orange); }
            .cve-meta-bar { padding: 12px 20px; border-bottom: 1px solid var(--border); font-size: 10pt; color: #4b5563; font-weight: 500; }
            .cve-meta-item { display: inline-block; margin-right: 25px; }
            .cve-meta-item strong { color: #111827; font-weight: 600; }
            .cve-body { padding: 20px; }
            .cve-section { margin-bottom: 24px; }
            .cve-section-remediation { background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 16px; border-radius: 8px; }
            .cve-section-remediation .cve-label { color: #166534; margin-bottom: 8px; }
            .cve-label { font-size: 10pt; font-weight: 700; color: #111827; margin-bottom: 8px; text-transform: uppercase; }
            .cve-refs a { color: var(--blue); text-decoration: underline; }
            .page-break { page-break-before: always; }
        </style>
    </head>
    <body>
        <div class="header-panel">
            <h1 class="header-title">ReconX Security Assessment</h1>
            <div class="header-subtitle"><br>Comprehensive Vulnerability Report</div>
            <div style="width: 100%; display: table; margin-top: 30px;">
                <div style="display: table-row;">
                    <div style="display: table-cell; text-align: center;"><div class="info-label">User</div><div class="info-value">{{ username }}</div></div>
                    <div style="display: table-cell; text-align: center;"><div class="info-label">Target Domain</div><div class="info-value">{{ domain }}</div></div>
                    <div style="display: table-cell; text-align: center;"><div class="info-label">Scan Date</div><div class="info-value">{{ date }}</div></div>
                    <div style="display: table-cell; text-align: center;"><div class="info-label">Scan ID</div><div class="info-value">{{ scan_id[:8] if scan_id else 'N/A' }}</div></div>
                </div>
            </div>
        </div>

        <h1 class="section-title">Executive Summary</h1>
        <p>This document presents the findings from an automated ReconX security assessment of <strong>{{ domain }}</strong>. The objective of this scan is to identify exposed assets, map the external attack surface, and uncover potential vulnerabilities that could be exploited by malicious actors.</p>
        <div class="summary-cards">
            <div class="card"><div class="count">{{ subdomains|length }}</div><div class="label">Subdomains</div></div>
            <div class="card card-vuln"><div class="count">{{ vulns|length }}</div><div class="label">Vulnerabilities</div></div>
            <div class="card card-critical"><div class="count">{{ critical_count }}</div><div class="label">Critical</div></div>
            <div class="card card-high"><div class="count">{{ high_count }}</div><div class="label">High</div></div>
        </div>
        {% set total = critical_count + high_count + medium_count + low_count %}
        {% if total > 0 %}
        <div class="severity-bar">
            <div class="sev-crit" style="width: {{ (critical_count / total * 100)|round }}%;"></div>
            <div class="sev-high" style="width: {{ (high_count / total * 100)|round }}%;"></div>
            <div class="sev-med" style="width: {{ (medium_count / total * 100)|round }}%;"></div>
            <div class="sev-low" style="width: {{ (low_count / total * 100)|round }}%;"></div>
        </div>
        {% endif %}

        <h1 class="section-title">Reconnaissance Results</h1>
        <h3>Discovered Subdomains</h3>
        <table>
            <thead><tr><th>Subdomain</th><th>IP Address</th><th>Status</th></tr></thead>
            <tbody>
                {% for sub in (subdomains or []) %}
                {% if sub is not none %}
                <tr>
                    <td>{{ sub.subdomain if sub is mapping else sub }}</td>
                    <td>{{ sub.ip if sub is mapping else "N/A" }}</td>
                    <td>
                        {% set st = (sub.status if sub is mapping else "Active")|lower %}
                        {% if 'active' in st or 'alive' in st or '200' in st %}
                            <span class="host-alive">✅ {{ sub.status if sub is mapping else "Active" }}</span>
                        {% else %}
                            <span style="color:var(--red);">❌ {{ sub.status if sub is mapping else "Dead" }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% endif %}{% endfor %}
            </tbody>
        </table>

        <h3>Open Ports & Services</h3>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Source Host</th></tr></thead>
            <tbody>
                {% for port in (ports or []) %}
                {% if port is not none %}
                <tr><td><strong>{{ port.port }}</strong></td><td>{{ port.service }}</td><td>{{ port.version }}</td><td>{{ port.host }}</td></tr>
                {% endif %}{% endfor %}
            </tbody>
        </table>

        <h3>Technology Fingerprinting</h3>
        <table>
            <thead><tr><th>Target URL</th><th>Detected Technologies</th></tr></thead>
            <tbody>
                {% for tech_batch in (technologies or []) %}
                {% if tech_batch is not none and tech_batch.get('technologies') %}
                <tr>
                    <td style="width: 30%; word-break: break-all;">{{ tech_batch.get('url') or 'N/A' }}</td>
                    <td>
                        {% for item in tech_batch.get('technologies') %}
                            {% if item is not none %}
                            <span class="badge badge-tech">{{ item.get('technology') or 'Unknown' }} {% if item.get('version') %}({{ item.get('version') }}){% endif %}</span>
                            {% endif %}
                        {% endfor %}
                    </td>
                </tr>
                {% endif %}{% endfor %}
            </tbody>
        </table>

        <div class="page-break"></div>

        <h1 class="section-title">Attack Chain Framework</h1>
        <p>To better interpret how an attacker might leverage the vulnerabilities identified in this report, the following conceptual attack chain illustrates the typical progression from external reconnaissance to exploitation and data compromise.</p>
        <div class="attack-chain">
            <div class="chain-step"><div class="chain-box">1. Reconnaissance<br><span style="font-weight: normal; font-size: 8pt; color: #166534;">Mapping attack surface</span></div></div>
            <div class="chain-arrow">→</div>
            <div class="chain-step"><div class="chain-box">2. Service Discovery<br><span style="font-weight: normal; font-size: 8pt; color: #166534;">Identifying vulnerable layers</span></div></div>
            <div class="chain-arrow">→</div>
            <div class="chain-step"><div class="chain-box">3. Exploitation<br><span style="font-weight: normal; font-size: 8pt; color: #166534;">Weaponizing identified CVEs</span></div></div>
            <div class="chain-arrow">→</div>
            <div class="chain-step"><div class="chain-box">4. Data Exposure<br><span style="font-weight: normal; font-size: 8pt; color: #166534;">Accessing sensitive systems</span></div></div>
        </div>

        {% if strategies %}
        <div class="page-break"></div>
        <h1 class="section-title">Exploitation Strategy & Attack Paths</h1>
        <p>The following predicted attack paths map discovered vulnerabilities to their logical exploitation chains based on CWE mechanics and public exploit availability.</p>
        
        {% for strat in strategies %}
        {% set sev = (strat.get('severity') or "UNKNOWN")|upper %}
        <div class="cve-card cve-card-{{ sev }}">
            <div class="cve-header">
                <h3 class="cve-title cve-title-{{ sev }}">{{ strat.get('cve_id') }}</h3>
                <span class="badge badge-{{ sev|lower }}">{{ strat.get('evidence_status', 'Unknown')|upper }}</span>
            </div>
            <div class="cve-meta-bar">
                <div class="cve-meta-item">Service: <strong>{{ strat.get('service', 'N/A') }}</strong></div>
                <div class="cve-meta-item">CWE: <strong>{{ strat.get('cwe_id', 'N/A') }}</strong></div>
            </div>
            <div class="cve-body">
                <div class="cve-section">
                    <p style="margin:0; font-size:10pt; font-style: italic;">"{{ strat.get('explanation', '') }}"</p>
                    <p style="margin-top:8px; font-size:10pt;"><strong>MITRE TTP:</strong> <span style="font-family: monospace;">{{ strat.get('mitre_technique', 'N/A') }}</span></p>
                </div>
                
                {% if strat.get('attack_chain') %}
                <div class="cve-section cve-section-remediation" style="background-color: #f9fafb; border-color: #e5e7eb;">
                    <div class="cve-label" style="color: #4b5563;">🎯 Predicted Attack Path</div>
                    <div style="font-size:10pt; font-weight: 600; color: #374151; margin-top: 5px;">
                        {% for step in strat.get('attack_chain') %}
                            <span style="display:inline-block; padding: 4px 8px; background: white; border: 1px solid #d1d5db; border-radius: 4px;">{{ step }}</span>
                            {% if not loop.last %}<span style="color: #9ca3af; margin: 0 4px;">→</span>{% endif %}
                        {% endfor %}
                    </div>
                </div>
                {% endif %}
                
                {% if strat.get('exploit_db_reference') %}
                <div class="cve-section cve-refs">
                    <div class="cve-label">🔗 Exploit-DB Intelligence</div>
                    <ul style="margin:5px 0 0 0; padding-left:20px; font-size:9pt;">
                        {% for ref in strat.get('exploit_db_reference') %}
                        <li><a href="{{ ref.get('url', '#') }}" target="_blank">{{ ref.get('title', 'Reference') }}</a></li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        {% endif %}

        <h1 class="section-title">Vulnerability Summary</h1>
        <table>
            <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Service / Target</th></tr></thead>
            <tbody>
                {% for vuln in (vulns or []) %}
                {% if vuln is not none %}
                    {% set sev = (vuln.get('risk_level') or vuln.get('severity') or "UNKNOWN")|upper %}
                    <tr>
                        <td><strong>{{ vuln.get('cve_id') }}</strong></td>
                        <td><span class="badge badge-{{ sev|lower }}">{{ sev }}</span></td>
                        <td class="cvss-bold">{{ vuln.get('cvss_score') or vuln.get('cvss') or 'N/A' }}</td>
                        <td>{{ vuln.get('service_name') or vuln.get('service') or 'N/A' }} {% if vuln.get('port_number') %}(Port: {{ vuln.get('port_number') }}){% endif %}</td>
                    </tr>
                {% endif %}{% endfor %}
            </tbody>
        </table>

        <div class="page-break"></div>
        <h1 class="section-title">Vulnerability Details & Recommendations</h1>
        
        {% for rec in (recommendations or []) %}
        {% if rec is not none %}
        {% set sev = (rec.get('severity') or "UNKNOWN")|upper %}
        {% set conf = rec.get('confidence_level', 'MEDIUM') %}
        <div class="cve-card cve-card-{{ sev }}">
            <div class="cve-header">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <h3 class="cve-title cve-title-{{ sev }}">{{ rec.get('cve_id', 'Unknown Vulnerability') }}</h3>
                    <span style="font-size: 8pt; font-weight: 700; padding: 2px 6px; border: 1px solid #d1d5db; border-radius: 4px; color: #6b7280;">{{ conf }} CONFIDENCE</span>
                </div>
                <span class="badge badge-{{ sev|lower }}">{{ sev }}</span>
            </div>
            <div class="cve-meta-bar">
                <div class="cve-meta-item">Service: <strong>{{ rec.get('service', 'N/A') }}</strong></div>
                <div class="cve-meta-item">Port: <strong>{{ rec.get('port', 'N/A') }}</strong></div>
                <div class="cve-meta-item">CVSS: <strong>{{ rec.get('cvss_score') or rec.get('cvss') or "N/A" }}</strong></div>
            </div>
            <div class="cve-body">
                {% if rec.get('justification') %}
                <div class="cve-section">
                    <div class="cve-label" style="font-size: 8pt; color: #6b7280;">Confidence Justification</div>
                    <p style="margin:0; font-size:10pt; color: #374151;">{{ rec.get('justification') }}</p>
                </div>
                {% endif %}
                
                {% if rec.get('explanation') %}
                <div class="cve-section">
                    <div class="cve-label">Analyst Explanation</div>
                    <p style="margin:0; font-size:10pt;">{{ rec.get('explanation') }}</p>
                </div>
                {% endif %}

                {% if rec.get('attacker_perspective') %}
                <div class="cve-section">
                    <div class="cve-label" style="color: #b91c1c;">Attacker Perspective</div>
                    <p style="margin:0; font-size:10pt; color: #b91c1c;">{{ rec.get('attacker_perspective') }}</p>
                </div>
                {% endif %}

                {% if rec.get('remediation') %}
                <div class="cve-section cve-section-remediation">
                    <div class="cve-label">🟢 Actionable Remediation</div>
                    <ul style="margin:5px 0 0 0; padding-left:20px; font-size:10pt; color: #14532d; list-style-type: none;">
                        {% for item in (rec.get('remediation') or []) %}
                            {% set parts = item.split(': ') %}
                            <li style="margin-bottom: 4px;">
                                {% if parts|length > 1 %}
                                    <strong>{{ parts[0] }}:</strong> {{ parts[1:]|join(': ') }}
                                {% else %}
                                    {{ item }}
                                {% endif %}
                            </li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}

                {% if rec.get('references') %}
                <div class="cve-section cve-refs">
                    <div class="cve-label">🔗 References</div>
                    <ul style="margin:5px 0 0 0; padding-left:20px; font-size:9pt;">
                        {% for ref in (rec.get('references') or []) %}<li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>{% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}{% endfor %}
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
        strategies=strategies,
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
    
    if not config:
        print("[!] ERROR: wkhtmltopdf executable not found. PDF report generation failed.")
        print("[!] Please install wkhtmltopdf and ensure it is in your PATH or at C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
        return None
        
    try:
        pdfkit.from_file(html_file_path, output_pdf, configuration=config, options=options)
        return output_pdf
    except Exception as e:
        print(f"[!] ERROR during PDF generation: {str(e)}")
        return None
