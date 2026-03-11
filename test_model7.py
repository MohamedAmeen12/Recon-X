import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath('.'))

from models.model7_recommendation_engine import RecommendationEngine

engine = RecommendationEngine()

# Mock Model 6 output
mock_vulnerabilities = [
    {
        "subdomain": "test.target.com",
        "service": "PHP",
        "technology_stack": "PHP",
        "version": "7.2.0",
        "port": 80,
        "cve_id": "CVE-2019-9020",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "risk_score": 0.91
    },
    {
        "subdomain": "test.target.com",
        "service": "Apache",
        "port": 80,
        "cve_id": "CVE-2021-41773",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "risk_level": "HIGH",
        "risk_score": 0.82
    }
]

print("Running Model 7 Recommendation Engine on mock data...")
recs = engine.generate_recommendations(mock_vulnerabilities)

print("\n--- RESULTS ---")
print(json.dumps(recs, indent=2))
