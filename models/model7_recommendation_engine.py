"""
Model 7 – Centralized Recommendation Engine
Generates remediation guidance for every vulnerability produced by Model 6.
Uses: CVE ID, service, port, CVSS score, risk level.
"""


class RecommendationEngine:
    """
    Generates one recommendation per vulnerability with remediation guidance,
    priority, and NVD patch link.
    """

    def generate_recommendations(self, vulnerabilities):
        """
        Args:
            vulnerabilities: list of dicts with cve_id, service, port,
                            cvss_score (or cvss), risk_level
        Returns:
            list of dicts: cve_id, service, port, risk_level, remediation,
                           priority, patch_link
        """
        recommendations = []

        for vuln in vulnerabilities or []:
            cve = vuln.get("cve_id") or "N/A"
            service = vuln.get("service") or "N/A"
            port = vuln.get("port")
            if port is None:
                port = vuln.get("port_number", "N/A")
            cvss = vuln.get("cvss_score")
            if cvss is None:
                cvss = vuln.get("cvss", 0)
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                cvss = 0.0
            risk = vuln.get("risk_level") or "Unknown"

            patch_link = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve and str(cve).startswith("CVE-") else ""

            awareness = (
                f"The vulnerability {cve} affects the {service} service running on port {port}. "
                "Attackers may exploit it remotely."
            )

            remediation = (
                f"Upgrade {service} to the latest supported version and apply vendor security patches."
            )

            if cvss >= 9:
                priority = "Immediate patch required"
            elif cvss >= 7:
                priority = "High priority fix recommended"
            elif cvss >= 4:
                priority = "Medium priority mitigation"
            else:
                priority = "Low priority"

            recommendations.append({
                "cve_id": cve,
                "service": service,
                "port": port,
                "risk_level": risk,
                "remediation": remediation,
                "priority": priority,
                "patch_link": patch_link,
                "awareness": awareness,
            })

        return recommendations
