"""
Scan Controller - Handles domain scanning operations
"""

import time
import datetime
from flask import request, jsonify, Blueprint
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from models.model1 import run_subdomain_discovery
from models.model3 import run_technology_fingerprinting_for_subdomains
from models.model4 import HTTPAnomalyModel
from utils.http_collector import collect_http_features

from config.database import (
    subdomains_collection,
    reports_collection,
    technologies_collection,
    vulnerabilities_collection,
    anomalies_collection
)

scan_bp = Blueprint('scan', __name__)

# ====================================================
# MODEL 4 INITIALIZATION (ONCE)
# ====================================================
model4 = HTTPAnomalyModel()
model4.load()


@scan_bp.route("/add_domain", methods=["POST"])
def add_domain():
    from config.database import domains_collection
    data = request.get_json()
    domain_name = data.get("domain")

    if not domain_name:
        return jsonify({"message": "Domain name is required!"}), 400

    domains_collection.insert_one({"domain": domain_name})
    return jsonify({"message": "Domain saved successfully!"}), 201


@scan_bp.route("/scan_domain", methods=["POST"])
def scan_domain():
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()
        include_tech_scan = data.get("include_tech_scan", False)

        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        start = time.time()
        print(f"Starting scan for domain: {domain}")

        # ====================================================
        # MODEL 1: SUBDOMAIN DISCOVERY
        # ====================================================
        result = run_subdomain_discovery(domain)

        for sub in result.get("raw_docs", []):
            sub["domain"] = domain
            sub["scanned_at"] = datetime.datetime.utcnow()
            subdomains_collection.update_one(
                {"domain": domain, "subdomain": sub["subdomain"]},
                {"$set": sub},
                upsert=True
            )

        # ====================================================
        # MODEL 4: HTTP ANOMALY DETECTION
        # ====================================================
        http_anomaly_results = []

        targets = [
            sub for sub in result.get("raw_docs", [])
            if sub.get("subdomain")
        ]

        for sub in targets[:5]:
            try:
                subdomain = sub.get("subdomain")
                url = f"http://{subdomain}"

                features = collect_http_features(url)
                anomaly_result = model4.predict(features)

                anomaly_doc = {
                    "domain": domain,
                    "subdomain": subdomain,
                    "url": url,
                    "status": anomaly_result.get("status"),
                    "anomaly_score": anomaly_result.get("anomaly_score"),
                    "signals": anomaly_result.get("signals", []),
                    "model": "Model 4 - HTTP Anomaly Detection",
                    "scanned_at": datetime.datetime.utcnow()
                }

                anomalies_collection.update_one(
                    {"domain": domain, "subdomain": subdomain},
                    {"$set": anomaly_doc},
                    upsert=True
                )

                http_anomaly_results.append({
                    "domain": domain,
                    "subdomain": subdomain,
                    "url": url,
                    "model4_result": anomaly_result,
                    "scanned_at": datetime.datetime.utcnow()
                })

            except Exception as e:
                print(f"[Model4] Error on {subdomain}: {e}")

        # ====================================================
        # MODEL 3: TECHNOLOGY FINGERPRINTING
        # ====================================================
        tech_results = []
        if include_tech_scan:
            try:
                live_subdomains = [
                    sub for sub in result.get("raw_docs", [])
                    if sub.get("live_http")
                ]

                if live_subdomains:
                    subdomains_data = []
                    for sub_doc in live_subdomains[:5]:
                        subdomains_data.append({
                            "subdomain": sub_doc.get("subdomain"),
                            "url": f"http://{sub_doc.get('subdomain')}",
                            "nmap_data": None,
                            "ip": sub_doc.get("ip")
                        })

                    executor = ThreadPoolExecutor(max_workers=1)
                    future = executor.submit(
                        run_technology_fingerprinting_for_subdomains,
                        subdomains_data
                    )

                    try:
                        tech_results = future.result(timeout=30)
                    except FutureTimeoutError:
                        tech_results = []

                    for tech_result in tech_results:
                        url = tech_result.get("url")
                        subdomain = url.replace("http://", "").replace("https://", "")

                        for tech in tech_result.get("technologies", []):
                            technologies_collection.update_one(
                                {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version")
                                },
                                {"$set": {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "url": url,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version"),
                                    "category": tech.get("category"),
                                    "source": tech.get("source"),
                                    "vulnerability_status": tech.get("vulnerability_status"),
                                    "confidence": tech.get("confidence"),
                                    "max_cvss": tech.get("max_cvss"),
                                    "similarity_score": tech.get("similarity_score"),
                                    "scanned_at": datetime.datetime.utcnow()
                                }},
                                upsert=True
                            )

            except Exception as e:
                print(f"Model 3 error: {e}")

        # ====================================================
        # ✅ FINAL REPORT (MODEL 1 FIX APPLIED HERE)
        # ====================================================
        report = {
            # 🔥 MODEL 1 FIELDS (ADDED – FIX)
            "domain": domain,
            "total_candidates": result.get("total_candidates", 0),
            "resolved": result.get("resolved", 0),
            "live_http": result.get("live_http", 0),
            "examples": result.get("examples", []),
            "clusters": result.get("clusters", []),
            "raw_docs": result.get("raw_docs", []),

            # Timing
            "elapsed_seconds": time.time() - start,

            # Model 2 (already embedded in raw_docs / ports)
            "ports_summary": result.get("ports_summary", {}),

            # Model 3
            "technology_fingerprints": tech_results,

            # Model 4
            "http_anomalies": http_anomaly_results
        }

        reports_collection.update_one(
            {"domain": domain},
            {"$set": {"result": report}},
            upsert=True
        )

        return jsonify({"message": "Scan complete", "report": report}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
