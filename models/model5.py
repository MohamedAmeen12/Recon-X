"""
Model 5 – Exploitation Strategy Engine
-------------------------------------
Purpose:
- Generate exploitation strategies
- Map technologies to attack paths
- Reference exploit intelligence
- NO risk scoring
- NO prioritization
"""

import requests


# ==============================
# Exploit Intelligence Sources
# ==============================

class ExploitSource:
    def search(self, technology, version=None, cve=None):
        raise NotImplementedError


class ExploitDBSource(ExploitSource):
    BASE_URL = "https://www.exploit-db.com/search"

    def search(self, technology, version=None, cve=None):
        query = cve or f"{technology} {version}" if version else technology
        if not query:
            return []

        try:
            requests.get(
                self.BASE_URL,
                params={"q": query},
                headers={"User-Agent": "ReconX"},
                timeout=5
            )
        except requests.RequestException:
            return []

        return [{
            "source": "Exploit-DB",
            "exploit_type": "public_poc",
            "execution_mode": "manual"
        }]


class MetasploitSource(ExploitSource):
    def search(self, technology, version=None, cve=None):
        if not technology:
            return []
        return [{
            "source": "Metasploit",
            "exploit_type": "weaponized",
            "execution_mode": "framework"
        }]


class GitHubPoCSource(ExploitSource):
    def search(self, technology, version=None, cve=None):
        if not technology:
            return []
        return [{
            "source": "GitHub",
            "exploit_type": "community_poc",
            "execution_mode": "manual"
        }]


# ==============================
# MITRE Technique Mapping
# ==============================

def map_to_mitre(technology):
    tech = technology.lower()

    if any(x in tech for x in ["wordpress", "drupal", "joomla"]):
        return "T1190 - Exploit Public-Facing Application"

    if any(x in tech for x in ["apache", "nginx", "iis"]):
        return "T1190 - Exploit Public-Facing Application"

    if any(x in tech for x in ["mysql", "redis", "mongo"]):
        return "T1046 - Network Service Discovery"

    if "ssh" in tech:
        return "T1110 - Brute Force"

    return "T1190 - Exploit Public-Facing Application"


# ==============================
# ATTACK CHAIN (ENHANCED BUT SAFE)
# ==============================

def build_attack_chain(technology, version, has_cve):
    tech = technology.lower()
    chain = ["Initial Access"]

    if any(x in tech for x in ["http", "apache", "nginx", "php", "wordpress"]):
        chain.append("Web Exploitation")
        chain.append("Exploit Known Vulnerability" if has_cve else "Exploit Misconfiguration")
        chain.append("Credential Access")

    elif "ssh" in tech:
        chain.append("Credential Brute Force")
        chain.append("Remote Access")

    elif any(x in tech for x in ["mysql", "redis", "mongo"]):
        chain.append("Unauthorized Database Access")
        chain.append("Data Extraction")

    else:
        chain.append("Service Exploitation")

    chain.append("Privilege Escalation")
    return chain


# ==============================
# CONFIDENCE (JUSTIFIED)
# ==============================

def calculate_confidence(source, has_cve, version):
    score = 0

    if source == "Metasploit":
        score += 3
    elif source == "Exploit-DB":
        score += 2
    else:
        score += 1

    if has_cve:
        score += 2
    if version:
        score += 1

    return "high" if score >= 6 else "medium" if score >= 4 else "low"


# ==============================
# MODEL 5 CORE
# ==============================

class ExploitationStrategyEngine:
    def __init__(self):
        self.sources = [
            ExploitDBSource(),
            MetasploitSource(),
            GitHubPoCSource()
        ]

    def generate_strategies(self, technologies, open_ports, http_anomalies):
        strategies = []

        for tech in technologies:
            tech_name = tech.get("technology")
            version = tech.get("version")
            cves = tech.get("cves", [])
            has_cve = bool(cves)

            for source in self.sources:
                exploits = source.search(
                    technology=tech_name,
                    version=version,
                    cve=cves[0]["cve"] if cves else None
                )

                for exploit in exploits:
                    strategies.append({
                        "technology": tech_name,
                        "version": version,
                        "exploit_source": exploit["source"],
                        "exploit_type": exploit["exploit_type"],
                        "execution_mode": exploit["execution_mode"],
                        "mitre_technique": map_to_mitre(tech_name),
                        "attack_chain": build_attack_chain(
                            tech_name,
                            version,
                            has_cve
                        ),
                        "related_ports": sorted(set(p["port"] for p in open_ports)),
                        "http_signal": http_anomalies.get("status", "unknown"),
                        "confidence": calculate_confidence(
                            exploit["source"],
                            has_cve,
                            version
                        )
                    })

        # Deduplicate (unchanged behavior)
        unique = {}
        for s in strategies:
            key = (s["technology"], s["version"], s["exploit_source"])
            unique[key] = s

        return list(unique.values())


# ==============================
# PUBLIC RUNNER
# ==============================

def run_model_5(port_scan_results, technology_results, http_anomaly_result):
    engine = ExploitationStrategyEngine()

    strategies = engine.generate_strategies(
        technologies=technology_results,
        open_ports=port_scan_results,
        http_anomalies=http_anomaly_result
    )

    return {
        "model": "Model 5 - Exploitation Strategy",
        "strategy_count": len(strategies),
        "strategies": strategies
    }
