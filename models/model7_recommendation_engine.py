"""
Model 7 – Centralized Recommendation Engine (v2)
Generates tailored, NLP-driven remediation guidance per vulnerability.
"""
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import logging
import re
from datetime import datetime
from utils.nvd_api_tool import get_nvd_client
try:
    from config.database import recommendations_collection
except ImportError:
    recommendations_collection = None

logger = logging.getLogger(__name__)

class RecommendationEngine:
    def __init__(self):
        self.nvd_client = get_nvd_client()
        self.cve_cache = {}  
        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=10)

    def generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Main entry point. Outputs list of recommendation dicts matching the Task 6 JSON schema.
        """
        recommendations = []

        for vuln in vulnerabilities or []:
            cve_id = vuln.get("cve_id")
            service = vuln.get("service") or vuln.get("technology_stack") or "Unknown Service"
            port = vuln.get("port") if vuln.get("port") is not None else vuln.get("port_number", "N/A")
            version = vuln.get("version", "")
            host = vuln.get("subdomain") or vuln.get("host") or ""
            
            # Extract and parse CVSS
            cvss = vuln.get("cvss_score")
            if cvss is None: cvss = vuln.get("cvss", 0.0)
            try: cvss = float(cvss)
            except (TypeError, ValueError): cvss = 0.0
                
            risk_score = vuln.get("risk_score") or vuln.get("traffic_anomaly_score", 0.0)
            model6_severity = vuln.get("risk_level") or vuln.get("severity") or "UNKNOWN"
            
            cve_metadata = self.enrich_cve_metadata(cve_id) if cve_id else {}

            explanation = self.generate_explanation(cve_metadata, service, version)
            attacker_perspective = self.generate_attack_scenario(vuln, cve_metadata, service, port)
            attack_chain = self.generate_attack_chain(vuln, cve_metadata, service, port)
            remediation_steps = self.generate_remediation(vuln, cve_metadata, service, port, version)
            priority = self.prioritize_recommendations(cvss, risk_score, model6_severity)
            risk_summary = self.generate_risk_summary(vuln, cve_metadata, priority, cvss)

            # References merging
            references = cve_metadata.get("references", [])
            patch_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id and str(cve_id).startswith("CVE-") else ""
            if patch_link and patch_link not in references:
                references.insert(0, patch_link)

            rec_obj = {
                "host": host,
                "service": service,
                "port": port,
                "cve_id": cve_id or "N/A",
                "severity": model6_severity,
                "cvss_score": cvss,
                "risk_summary": risk_summary,
                "attack_chain": attack_chain,
                "explanation": explanation,
                "attacker_perspective": attacker_perspective,
                "remediation": remediation_steps,
                "references": references[:5], # Limit to top 5
                "priority": priority
            }
            
            self.save_recommendation_to_db(rec_obj)
            recommendations.append(rec_obj)

        # Sort recommendations: Critical > High > Medium > Low
        priority_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        recommendations.sort(key=lambda x: priority_map.get(x["priority"], 0), reverse=True)

        return recommendations

    def enrich_cve_metadata(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch specific metadata from NVD with caching.
        """
        if not cve_id or not str(cve_id).startswith("CVE-"):
            return {}

        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]

        try:
            logger.info(f"Model 7: Fetching NVD data for {cve_id}")
            df = self.nvd_client.search_by_cve_id(cve_id)
            if df is not None and not df.empty:
                record = df.iloc[0].to_dict()
                self.cve_cache[cve_id] = record
                return record
        except Exception as e:
            logger.error(f"Error fetching CVE metadata for {cve_id}: {str(e)}")
            
        return {}

    def generate_explanation(self, metadata: Dict[str, Any], service: str, version: str) -> str:
        """
        NLP explaination generator following precise template.
        """
        description = metadata.get("description", "")
        cwe = metadata.get("cwe", "unknown weakness").lower()

        if not description:
            return f"This vulnerability affects outdated {service} versions and involves {cwe}. The flaw can trigger unintended behavior, potentially allowing attackers to compromise the system."

        try:
            # Fit TF-IDF to find the top keywords for summarization context
            X = self.vectorizer.fit_transform([description])
            feature_names = self.vectorizer.get_feature_names_out()
            scores = X.toarray().flatten()
            
            # top keywords
            keywords = [feature_names[i] for i in scores.argsort()[-3:][::-1] if len(feature_names[i]) > 2]
            kw_str = " ".join(keywords) if keywords else "data processing"
            
            # Impact guess
            desc_lower = description.lower()
            if "read" in desc_lower or "disclosure" in desc_lower or "memory" in cwe:
                impact = "read sensitive memory data or crash the application"
            elif "execute" in desc_lower or "code" in desc_lower or "rce" in desc_lower:
                impact = "achieve arbitrary code execution or take complete control of the system"
            elif "privilege" in desc_lower or "escalate" in desc_lower:
                impact = "escalate administrative privileges or pivot through the network"
            elif "cross-site" in cwe or "xss" in cwe:
                impact = "execute malicious scripts in user sessions or steal authentication tokens"
            elif "injection" in cwe or "sql" in cwe:
                impact = "bypass authentication barriers or extract raw database contents"
            elif "denial" in desc_lower or "crash" in desc_lower or "dos" in desc_lower:
                impact = "trigger resource exhaustion or persistently crash the service"
            else:
                impact = "obtain unauthorized access or disrupt core application availability"
                
            v_str = f"{service} versions" if version else f"{service} implementations"
            
            explanation = f"This vulnerability affects outdated {v_str} and occurs when the {cwe} processes malformed {kw_str} input. "
            explanation += f"The flaw can trigger a security breach, potentially allowing attackers to {impact}."
                 
            return explanation

        except Exception as e:
            logger.error(f"NLP explanation failed: {e}")
            return f"This vulnerability affects outdated {service} versions and occurs when the {cwe} processes malformed input. The flaw can trigger insecure behavior, potentially allowing attackers to compromise the application."

    def generate_attack_scenario(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any) -> str:
        """
        Generate short attacker perspective explanation based on attack vectors.
        """
        vector = metadata.get("attack_vector", "NETWORK").lower()
        complexity = metadata.get("attack_complexity", "LOW").lower()
        cwe = metadata.get("cwe", "").lower()
        
        port_context = str(port) if port and str(port) not in ["N/A", "0", ""] else "any active port"
        vector_text = "network" if "network" in vector else ("local" if "local" in vector else "specially crafted")
        
        if "overflow" in cwe or "memory" in cwe:
            flaw = "memory corruption flaw"
            impact = "memory disclosure or denial of service"
        elif "injection" in cwe or "sql" in cwe:
            flaw = "injection flaw"
            impact = "database extraction or authentication bypass"
        elif "cross-site" in cwe or "xss" in cwe:
            flaw = "script injection flaw"
            impact = "session hijacking or unauthorized actions"
        elif "traversal" in cwe or "path list" in cwe:
            flaw = "path traversal flaw"
            impact = "sensitive file disclosure"
        else:
            flaw = f"{cwe if cwe else 'security'} flaw"
            impact = "unauthorized access or system compromise"
            
        scenario = f"If the vulnerable {service} service is exposed on port {port_context}, "
        scenario += f"an attacker could send {vector_text} requests to exploit the {flaw}, "
        scenario += f"potentially allowing {impact}."
            
        return scenario

    def generate_attack_chain(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any) -> List[str]:
        """
        Integrates exploitation insights to form a sequenced attacker path.
        """
        cve_id = vuln.get("cve_id", "a known vulnerability")
        cwe = metadata.get("cwe", "").lower()
        vector = metadata.get("attack_vector", "NETWORK").lower()
        
        chain = []
        port_txt = str(port) if port and str(port) not in ["N/A", "0", ""] else "an unknown port"
        
        # Step 1: Reconnaissance
        chain.append(f"Reconnaissance: attacker scans the host and finds port {port_txt} open")
        
        # Step 2: Service Detection
        chain.append(f"Service Detection: the server is running {service}")
        
        # Step 3: Vulnerability Matching
        cve_str = f"matches {cve_id}" if cve_id != "a known vulnerability" else "matches a known vulnerability"
        chain.append(f"Vulnerability Matching: detected version {cve_str}")
        
        # Step 4: Exploitation
        if "network" in vector:
            act = "sends a crafted remote payload"
        elif "local" in vector:
            act = "executes a local exploit script"
        else:
            act = "delivers a crafted payload"
        chain.append(f"Exploitation: attacker {act} to target the {cwe} flaw")
        
        # Step 5: Impact
        if "privilege" in cwe:
            impact = "escalation to administrative privileges"
        elif "read" in cwe or "disclosure" in cwe or "memory" in cwe:
            impact = "memory disclosure or unauthorized data access"
        elif "execute" in cwe or "code" in cwe:
            impact = "arbitrary remote code execution"
        else:
            impact = "application crash or confidentiality loss"
            
        chain.append(f"Impact: {impact}")
        
        return chain

    def generate_risk_summary(self, vuln: Dict[str, Any], metadata: Dict[str, Any], priority: str, cvss: float) -> str:
        """
        Add a short professional risk summary.
        """
        service = vuln.get('service') or vuln.get('technology_stack') or 'service'
        vector = metadata.get("attack_vector", "NETWORK").lower()
        if "network" in vector:
            exp_text = "remote exploitability"
        elif "local" in vector:
            exp_text = "local exploitability requiring prior access"
        else:
            exp_text = "exploitability"
            
        cwe = metadata.get("cwe", "").lower()
            
        if "memory" in cwe or "read" in cwe or "disclosure" in cwe:
            imp_text = "expose sensitive memory or disrupt application availability"
        elif "execute" in cwe or "code" in cwe:
            imp_text = "allow arbitrary code execution and system takeover"
        elif "injection" in cwe or "sql" in cwe:
            imp_text = "extract sensitive database records or bypass authentication"
        elif "cross-site" in cwe or "xss" in cwe:
            imp_text = "hijack active user sessions and rewrite active DOM content"
        else:
            imp_text = "compromise host integrity or availability"
            
        summary = f"This vulnerability is rated {priority.upper()} due to its {exp_text} "
        summary += f"and the potential to {imp_text}."
            
        return summary

    def generate_remediation(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any, version: str) -> List[str]:
        """
        Rule-based remediation generating multiple specific context-aware steps.
        """
        steps = []
        cwe = metadata.get("cwe", "").lower()
        desc = metadata.get("description", "").lower()
        service_lower = service.lower()
        
        # 1. Version / Core Patching
        cve_id = vuln.get('cve_id')
        if version:
            steps.append(f"Upgrade {service} to version {version} or later where the vulnerability is patched.")
        elif cve_id:
            steps.append(f"Upgrade {service} to the latest stable release containing the patch for {cve_id}.")
        else:
            steps.append(f"Ensure {service} is running the latest stable secure release.")

        # 2. Service Specific Rules
        if "php" in service_lower:
            steps.append("Disable unnecessary PHP extensions such as XML-RPC if not required.")
            steps.append("Restrict access to vulnerable endpoints through firewall rules.")
            if "xml" in desc or "rpc" in desc:
                steps.append("Deploy WAF rules to detect malicious XML payloads.")
        
        elif "apache" in service_lower or "httpd" in service_lower:
            if "traversal" in desc or "directory" in desc:
                steps.append("Implement strict `AllowOverride None` and `Require all denied` configuration directives on web roots.")
            if "module" in desc or "mod_" in desc:
                steps.append("Disable deprecated or unused Apache modules dynamically.")
            steps.append("Deploy WAF rules to block malicious path traversal requests.")
            
        elif "nginx" in service_lower:
            steps.append("Toggle `server_tokens off` configuration mapping to obscure running versions.")
            if "buffer" in desc or "memory" in desc:
                steps.append("Tighten `client_max_body_size` memory buffers to prevent exhaustion.")
                
        elif "ssh" in service_lower or str(port) == "22":
            steps.append("Restrict SSH access to trusted internal IP ranges only via network firewalls.")
            steps.append("Disable root login directly by modifying the PermitRootLogin configuration directive.")
            
        elif "mysql" in service_lower or "postgres" in service_lower or str(port) in ["3306", "5432"]:
            steps.append("Isolate database network listeners strictly to the local loopback interface or trusted subnets.")

        # 3. CWE Specific Rules
        if "cross-site scripting" in cwe or "xss" in desc:
            steps.append("Implement a strict Content-Security-Policy (CSP) header.")
            steps.append("Ensure context-aware output encoding is used in the frontend application.")
            
        if "injection" in cwe or "sql" in desc:
            steps.append("Refactor database queries in the application layer to exclusively use parameterized statements (Prepared Statements).")
            steps.append("Deploy a Web Application Firewall (WAF) rule to immediately block common injection payloads.")

        # 4. Port / Network Rules
        port_str = str(port)
        if port_str and port_str not in ["80", "443", "N/A", "0"]:
            steps.append(f"Restrict public access to port {port} using VPC security groups or host firewalls (iptables/ufw).")

        # Deduplicate
        unique_steps = []
        for s in steps:
            if s not in unique_steps:
                unique_steps.append(s)

        return unique_steps

    def prioritize_recommendations(self, cvss: float, risk_score: Any, model6_severity: str) -> str:
        """
        Sort priority using strict boundaries relying on model 6 severity, risk score, and CVSS.
        """
        sev_upper = str(model6_severity).upper()
        
        if "CRITICAL" in sev_upper: return "CRITICAL"
        if "HIGH" in sev_upper: return "HIGH"
        if "MEDIUM" in sev_upper: return "MEDIUM"
        if "LOW" in sev_upper: return "LOW"
            
        # Attempt parsing risk score (Model 6 outputs standard floats 0.0 to 1.0)
        try:
            rs = float(risk_score)
            if rs >= 0.9: return "CRITICAL"
            if rs >= 0.7: return "HIGH"
            if rs >= 0.4: return "MEDIUM"
            if rs > 0.0: return "LOW"
        except (TypeError, ValueError):
            pass

        # Fallback to CVSS
        if cvss >= 9.0: return "CRITICAL"
        if cvss >= 7.0: return "HIGH"
        if cvss >= 4.0: return "MEDIUM"
        return "LOW"
        
    def generate_fix_script(self, vulnerability: Dict[str, Any]) -> str:
        """
        Dynamically builds a valid PowerShell remediation script based on detected vulnerabilities.
        """
        cve_id = vulnerability.get("cve_id", "Unknown CVE")
        service = vulnerability.get("service", "Unknown Service")
        port = vulnerability.get("port", "Unknown Port")
        
        script = []
        
        # Admin Privilege Check
        script.append('If (-NOT ([Security.Principal.WindowsPrincipal] `')
        script.append('    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`')
        script.append('    [Security.Principal.WindowsBuiltInRole] "Administrator"))')
        script.append('{')
        script.append('    Write-Host "Please run this script as Administrator." -ForegroundColor Red')
        script.append('    Exit')
        script.append('}\n')
        
        # Improved Script Header
        script.append("# ReconX Automated Security Remediation Script")
        script.append("# Generated by ReconX Vulnerability Recommendation Engine")
        script.append(f"# CVE: {cve_id}")
        script.append(f"# Service: {service}")
        script.append(f"# Port: {port}\n")
        
        script.append('Write-Host "ReconX Security Remediation Script Starting..." -ForegroundColor Green\n')
        
        script.append('Write-Host "Checking service version..." -ForegroundColor Cyan')
        
        service_lower = service.lower()
        
        # 1. Service Specific Actions
        if "php" in service_lower:
            script.append("php -v\n")
            
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('$phpIni = "C:\\php\\php.ini"')
            script.append('if (Test-Path $phpIni) {')
            script.append('    Write-Host "Applying PHP security hardening..." -ForegroundColor Cyan')
            script.append('    (Get-Content $phpIni) `')
            script.append('        -replace "disable_functions\\s*=", "disable_functions = exec,shell_exec,passthru,system" |')
            script.append('        Set-Content $phpIni')
            script.append('}\n')
            
        elif "apache" in service_lower or "httpd" in service_lower:
            script.append('Write-Host "Checking Apache configuration..." -ForegroundColor Cyan')
            script.append("httpd -v")
            script.append('Write-Host "Ensure latest Apache version is installed."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade Apache to a patched version."')
            script.append('Write-Host "2. Implement AllowOverride None on root directories."\n')
            
        elif "mysql" in service_lower or "postgres" in service_lower:
            script.append('Write-Host "Checking database version..." -ForegroundColor Cyan')
            script.append("mysql --version 2>$null" if "mysql" in service_lower else "psql -V 2>$null")
            script.append('Write-Host "Ensure database access is restricted."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan\n')
            
        elif "nginx" in service_lower:
            script.append('Write-Host "Checking Nginx version..." -ForegroundColor Cyan')
            script.append("nginx -v")
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade Nginx to a patched version."')
            script.append('Write-Host "2. Toggle server_tokens off in nginx.conf."\n')
            
        elif "ssh" in service_lower:
            script.append('Write-Host "Ensure OpenSSH is updated and root login is disabled."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan\n')

        else:
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade the applicable service to a patched version."')
            script.append('Write-Host "2. Restrict public access to vulnerable service blocks."\n')

        script.append('Write-Host "Security hardening complete." -ForegroundColor Green\n')

        # 2. Port and Firewall Hardening with existence check
        if str(port) not in ["N/A", "0", "", "None", None]:
            script.append(f'$ruleName = "ReconX Port {port} Restriction"')
            script.append('if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {')
            script.append('    New-NetFirewallRule `')
            script.append('        -DisplayName $ruleName `')
            script.append('        -Direction Inbound `')
            script.append('        -Protocol TCP `')
            script.append(f'        -LocalPort {port} `')
            script.append('        -Action Block')
            script.append('    Write-Host "Firewall rule created." -ForegroundColor Green')
            script.append('}')
            script.append('else {')
            script.append('    Write-Host "Firewall rule already exists." -ForegroundColor Yellow')
            script.append('}\n')
            
        # Final Completion Message
        script.append('Write-Host ""')
        script.append('Write-Host "ReconX remediation process completed." -ForegroundColor Green')
        script.append('Write-Host "Please review configuration changes and restart affected services if required."')
            
        return "\n".join(script)
        
    def save_recommendation_to_db(self, recommendation: Dict[str, Any]):
        """
        Store recommendation in MongoDB collection if available. Avoid duplicates by host, cve_id, port.
        """
        if recommendations_collection is None:
            return
            
        try:
            query = {
                "host": recommendation.get("host"),
                "cve_id": recommendation.get("cve_id"),
                "port": recommendation.get("port")
            }
            
            # Upsert
            doc = recommendation.copy()
            doc["timestamp"] = datetime.utcnow()
            doc["source"] = "ReconX Model 7"
            
            recommendations_collection.update_one(
                query,
                {"$set": doc},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save recommendation to DB: {e}")

    def get_recommendations_for_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieve all stored recommendations for a target host.
        """
        if recommendations_collection is None:
            return []
            
        try:
            cursor = recommendations_collection.find({"host": host})
            return [doc for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to fetch recommendations for {host}: {e}")
            return []
