"""
Scan Controller - Handles domain scanning operations
"""

import time
import datetime

from flask import request, jsonify, Blueprint, session
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from bson.objectid import ObjectId
import time
import datetime
import numpy as np

from models.model1 import run_subdomain_discovery
from models.model3 import run_technology_fingerprinting_for_subdomains
from models.model4 import HTTPAnomalyModel
from models.model5 import run_model_5
from utils.http_collector import collect_http_features
from utils.traffic_collector import capture_traffic

from config.database import (
    subdomains_collection,
    reports_collection,
    technologies_collection,
    vulnerabilities_collection,
    anomalies_collection
)

scan_bp = Blueprint('scan', __name__)

def sanitize_for_mongo(data):
    if isinstance(data, dict):
        return {k: sanitize_for_mongo(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_mongo(v) for v in data]
    elif isinstance(data, (np.bool_, np.bool)):
        return bool(data)
    elif isinstance(data, (np.int64, np.int32, np.int16, np.int8)):
        return int(data)
    elif isinstance(data, (np.float64, np.float32)):
        return float(data)
    return data

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
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized. Please login to scan."}), 401

        data = request.get_json()
        domain = data.get("domain", "").strip()
        include_tech_scan = data.get("include_tech_scan", False)

        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        start = time.time()
        print(f"Starting scan for domain: {domain} by user {session['user_id']}")

        # ====================================================
        # MODEL 1: SUBDOMAIN DISCOVERY
        # ====================================================
        result = run_subdomain_discovery(domain)
        result = sanitize_for_mongo(result)

        for sub in result.get("raw_docs", []):
            sub["domain"] = domain
            sub["scanned_at"] = datetime.datetime.utcnow()
            # sub = sanitize_for_mongo(sub) # Already sanitized via result
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

                # --- MULTI-MODEL COLLECTION ---
                # Run HTTP Analysis and Traffic Capture in Parallel
                with ThreadPoolExecutor(max_workers=2) as coll_exec:
                    http_future = coll_exec.submit(collect_http_features, url)
                    traffic_future = coll_exec.submit(capture_traffic, subdomain, duration=3)
                    
                    features = http_future.result()
                    traffic_features = traffic_future.result()
                    
                    # Merge features
                    features.update(traffic_features)

                anomaly_result = model4.predict(features)

                anomaly_doc = {
                    "domain": domain,
                    "subdomain": subdomain,
                    "url": url,
                    "status": anomaly_result.get("status"),
                    "anomaly_score": anomaly_result.get("anomaly_score"),
                    "signals": anomaly_result.get("signals", []),
                    "traffic_data": anomaly_result.get("traffic_data", {}),
                    "model": "Model 4 - HTTP & Traffic Anomaly Detection",
                    "scanned_at": datetime.datetime.utcnow()
                }

                anomaly_doc = sanitize_for_mongo(anomaly_doc)
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
                            tech_update = {
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
                            }
                            tech_update = sanitize_for_mongo(tech_update)

                            technologies_collection.update_one(
                                {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version")
                                },
                                {"$set": tech_update},
                                upsert=True
                            )

            except Exception as e:
                print(f"Model 3 error: {e}")

        # ====================================================
        # MODEL 5: EXPLOITATION STRATEGY
        # ====================================================
        try:
            port_scan_results = []
            for sub in result.get("raw_docs", []):
                for port in sub.get("open_ports", []):
                    port_scan_results.append({
                        "subdomain": sub["subdomain"],
                        "port": port["port"],
                        "service": port["service"]
                    })

            technology_results_for_model5 = []

            for tech_result in tech_results:
                for tech in tech_result.get("technologies", []):
                    technology_results_for_model5.append(tech)

            http_anomaly_result_for_model5 = http_anomaly_results[0]["model4_result"] if http_anomaly_results else {}
            
            model5_output = run_model_5(
                port_scan_results=port_scan_results,
                technology_results=technology_results_for_model5,
                http_anomaly_result=http_anomaly_result_for_model5
            )
        except Exception as e:
            print(f"[Model5] Error generating strategies: {e}")
            model5_output = {"strategies": []}

        # ====================================================
        # ✅ FINAL REPORT (SNAPSHOT)
        # ====================================================
        report = {
            "domain": domain,
            "user_id": session.get("user_id"),
            "scanned_at": datetime.datetime.utcnow(),
            "total_candidates": result.get("total_candidates", 0),
            "result": {
                "domain": domain,
                "total_candidates": result.get("total_candidates", 0),
                "resolved": result.get("resolved", 0),
                "live_http": result.get("live_http", 0),
                "examples": result.get("examples", []),
                "clusters": result.get("clusters", []),
                "raw_docs": result.get("raw_docs", []),
                "elapsed_seconds": time.time() - start,
                "ports_summary": result.get("ports_summary", {}),
                "technology_fingerprints": tech_results,
                "http_anomalies": http_anomaly_results,
                "model5": model5_output
            }
        }
        
        # Insert as new document instead of update
        report = sanitize_for_mongo(report)
        insert_result = reports_collection.insert_one(report)
        report_id = str(insert_result.inserted_id)

        return jsonify({
            "message": "Scan complete", 
            "report_id": report_id,
            "report": report["result"]
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@scan_bp.route("/get_history", methods=["GET"])
def get_history():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session["user_id"]
    
    try:
        # Fetch scans only for this user
        cursor = reports_collection.find(
            {"user_id": user_id},
            {"_id": 1, "domain": 1, "scanned_at": 1, "result.total_candidates": 1}
        ).sort("scanned_at", -1)
        
        history = []
        for doc in cursor:
            history.append({
                "report_id": str(doc["_id"]),
                "domain": doc.get("domain", "Unknown"),
                "scanned_at": doc.get("scanned_at").isoformat() if doc.get("scanned_at") else None,
                "candidates": doc.get("result", {}).get("total_candidates", 0)
            })
            
        return jsonify({"history": history}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
