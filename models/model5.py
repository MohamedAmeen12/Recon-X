"""
Model 5 – Exploitation Strategy Engine
-------------------------------------
Purpose:
- Generate exploitation strategies
- Map technologies to attack paths
- Reference online exploit intelligence
- NO risk scoring
- NO prioritization (handled in Model 6)
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
        query = cve or technology
        if not query:
            return []

        try:
            requests.get(
                self.BASE_URL,
                params={"q": query},
                headers={"User-Agent": "ReconX"},
                timeout=10
            )
        except requests.RequestException:
            return []

        return [{
            "source": "Exploit-DB",
            "exploit_type": "public_poc",
            "execution_mode": "manual",
            "confidence": "medium"
        }]


class MetasploitSource(ExploitSource):

    def search(self, technology, version=None, cve=None):
        if not technology:
            return []

        return [{
            "source": "Metasploit",
            "exploit_type": "weaponized",
            "execution_mode": "framework",
            "confidence": "high"
        }]


class GitHubPoCSource(ExploitSource):

    def search(self, technology, version=None, cve=None):
        if not technology:
            return []

        return [{
            "source": "GitHub",
            "exploit_type": "community_poc",
            "execution_mode": "manual",
            "confidence": "low"
        }]


# ==============================
# Attack Mapping (MITRE + Chain)
# ==============================

def map_to_mitre(technology: str) -> str:
    tech = technology.lower()

    if any(x in tech for x in ["wordpress", "drupal", "joomla"]):
        return "T1190 – Exploit Public-Facing Application"

    if any(x in tech for x in ["apache", "nginx", "iis"]):
        return "T1190 – Exploit Public-Facing Application"

    if any(x in tech for x in ["redis", "mongodb", "mysql"]):
        return "T1046 – Network Service Discovery"

    if "ssh" in tech:
        return "T1110 – Brute Force"

    return "T1190 – Exploit Public-Facing Application"


def build_attack_chain(technology: str) -> list:
    tech = technology.lower()

    chain = ["Initial Access"]

    if any(x in tech for x in ["http", "apache", "nginx", "php", "wordpress"]):
        chain += [
            "Web Exploitation",
            "Webshell Deployment",
            "Credential Access"
        ]

    elif any(x in tech for x in ["database", "redis", "mongo"]):
        chain += [
            "Unauthorized Access",
            "Data Extraction"
        ]

    else:
        chain.append("Service Exploitation")

    chain.append("Privilege Escalation")

    return chain


# ==============================
# Model 5 Core Engine
# ==============================

class ExploitationStrategyEngine:

    def __init__(self):
        self.sources = [
            ExploitDBSource(),
            MetasploitSource(),
            GitHubPoCSource()
        ]

    def generate_strategies(
        self,
        technologies: list,
        open_ports: list,
        http_anomalies: dict
    ) -> list:

        strategies = []

        for tech in technologies:
            tech_name = tech.get("technology")
            version = tech.get("version")
            cves = tech.get("cves", [])

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
                        "attack_chain": build_attack_chain(tech_name),
                        "related_ports": sorted(set(p["port"] for p in open_ports)),
                        "http_signal": http_anomalies.get("status", "unknown"),
                        "confidence": exploit["confidence"]
                    })

        unique = {}
        for s in strategies:
            key = (
                s["technology"],
                s["version"],
                s["exploit_source"],
                s["mitre_technique"]
            )
            unique[key] = s

        return list(unique.values())


# ==============================
# Public Runner (Pipeline Entry)
# ==============================

def run_model_5(
    port_scan_results: list,
    technology_results: list,
    http_anomaly_result: dict
):
    """
    Inputs:
    - From Model 2: port_scan_results
    - From Model 3: technology_results
    - From Model 4: http_anomaly_result
    """

    engine = ExploitationStrategyEngine()

    strategies = engine.generate_strategies(
        technologies=technology_results,
        open_ports=port_scan_results,
        http_anomalies=http_anomaly_result
    )

    return {
        "model": "Model 5 – Exploitation Strategy",
        "strategy_count": len(strategies),
        "strategies": strategies
    }
