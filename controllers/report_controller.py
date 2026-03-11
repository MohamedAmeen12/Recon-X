"""
Report Controller - Handles report retrieval and technology verification
"""
import datetime
import requests
from flask import request, jsonify, Blueprint, session
from middlewares.auth_middleware import login_required
from bson.objectid import ObjectId
from utils.audit_logger import log_audit_event
from config.database import (
    reports_collection,
    technologies_collection,
    vulnerabilities_collection,
    recommendations_collection,
)

# ==============================
# MODEL 5 IMPORTS
# ==============================
from models.model5 import run_model_5
from models.model6_vulnerability_risk import Model6RiskScorer
from models.model7_recommendation_engine import RecommendationEngine
from utils.strategy_stats import build_strategy_statistics
# ==============================

# ==============================
# MODEL 6 LAZY INITIALIZATION
# ==============================
_model6_instance = None

def get_model6():
    global _model6_instance
    if _model6_instance is None:
        _model6_instance = Model6RiskScorer()
        _model6_instance.load_model()
    return _model6_instance

report_bp = Blueprint('report', __name__)


@report_bp.route("/get_technologies", methods=["GET"])
@login_required
def get_technologies():
    domain = request.args.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    try:
        technologies = list(technologies_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("scanned_at", -1))
        
        vulnerabilities = list(vulnerabilities_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("cvss_score", -1))
        
        return jsonify({
            "domain": domain,
            "technologies": technologies,
            "vulnerabilities": vulnerabilities,
            "total_technologies": len(technologies),
            "total_vulnerabilities": len(vulnerabilities)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@report_bp.route("/get_report", methods=["GET"])
@login_required
def get_report():
    domain = request.args.get("domain", "").strip()
    report_id = request.args.get("report_id", "").strip()
    
    current_user_id = session["user_id"]
    is_admin = session.get("role") == "admin"

    record = None

    # 2. FETCH BY ID
    if report_id:
        try:
            record = reports_collection.find_one({"_id": ObjectId(report_id)})
        except:
            return jsonify({"error": "Invalid Report ID"}), 400

    # 3. FALLBACK: FETCH BY DOMAIN (LATEST FOR USER)
    elif domain:
        # If admin, just get the latest global report (or specific user's logic? For now, latest owned by anyone or maybe just latest scan on that domain)
        # But requirement says "see only their scan" for users.
        if is_admin:
             record = reports_collection.find_one(
                {"domain": domain},
                sort=[("scanned_at", -1)]
             )
        else:
            record = reports_collection.find_one(
                {"domain": domain, "user_id": current_user_id},
                sort=[("scanned_at", -1)]
            )
    else:
        return jsonify({"error": "Domain or Report ID required"}), 400

    if not record:
        return jsonify({"message": "No report found"}), 404

    # 4. OWNERSHIP CHECK (Skip for Admin)
    # If the record has a user_id, check it. (Legacy records might not have user_id, maybe allow those or block? Assuming new system.)
    record_owner = record.get("user_id")
    if not is_admin and record_owner and str(record_owner) != str(current_user_id):
        return jsonify({"error": "Unauthorized access to this report"}), 403

    # ====================================================
    # EXISTING LOGIC – TECHNOLOGY FINGERPRINT FALLBACK
    # ====================================================
    # Note: We are now modifying a SNAPSHOT if we update. 
    # To preserve history immutability, we should probably NOT update the snapshot unless it's a "repair" operation.
    # But the existing logic updates the record if fingerprints are missing.
    # We will keep it but be aware it modifies the historical record.
    
    if not record.get("result", {}).get("technology_fingerprints"):
        try:
            # Logic to fetch and populate technologies...
            # This relies on secondary collections (technologies_collection) which are also updated during scan.
            # Ideally, these should have been embedded in the report at scan time.
            # But we'll keep the existing "lazy load" logic for backward compatibility or if scan didn't finish populating.
            
            technologies = list(technologies_collection.find(
                {"domain": record.get("domain")},
                {"_id": 0}
            ).sort("scanned_at", -1))
            
            vulnerabilities = list(vulnerabilities_collection.find(
                {"domain": record.get("domain")},
                {"_id": 0}
            ).sort("cvss_score", -1))
            
            tech_by_url = {}
            for tech in technologies:
                url = tech.get("url", f"http://{tech.get('subdomain', '')}")
                tech_by_url.setdefault(url, {"url": url, "technologies": []})
                
                if not any(
                    t["technology"] == tech.get("technology") and
                    t["version"] == tech.get("version")
                    for t in tech_by_url[url]["technologies"]
                ):
                    tech_cves = [
                        {
                            "cve": v.get("cve_id"),
                            "cvss": v.get("cvss_score"),
                            "description": v.get("description", ""),
                            "severity": v.get("severity", "UNKNOWN"),
                            "published_date": v.get("published_date"),
                            "cwe": v.get("cwe", "N/A")
                        }
                        for v in vulnerabilities
                        if v.get("subdomain") == tech.get("subdomain") and
                           v.get("technology") == tech.get("technology") and
                           v.get("version") == tech.get("version")
                    ]

                    tech_by_url[url]["technologies"].append({
                        "technology": tech.get("technology"),
                        "version": tech.get("version"),
                        "category": tech.get("category", "Unknown"),
                        "source": tech.get("source", "Unknown"),
                        "vulnerability_status": tech.get("vulnerability_status", "unknown"),
                        "confidence": tech.get("confidence", 0.0),
                        "max_cvss": tech.get("max_cvss", 0.0),
                        "similarity_score": tech.get("similarity_score", 0.0),
                        "cves": tech_cves
                    })

            record.setdefault("result", {})["technology_fingerprints"] = list(tech_by_url.values())

            # Update the specific snapshot
            reports_collection.update_one(
                {"_id": record["_id"]},
                {"$set": {"result": record["result"]}}
            )

        except Exception as e:
            print(f"[Tech Fingerprint Error] {e}")

    # ====================================================
    # ✅ FIXED MODEL 5 LOGIC (REUSE + STATISTICS)
    # ====================================================
    try:
        result = record.get("result", {})

        # ✅ CASE 1: Model 5 already exists → reuse it
        if result.get("model5"):
            model5_result = result["model5"]

            # Add statistics if missing
            if "statistics" not in model5_result:
                model5_result["statistics"] = build_strategy_statistics(
                    model5_result.get("strategies", [])
                )

        # ✅ CASE 2: Model 5 does NOT exist → generate it
        else:
            port_scan_results = result.get("port_scan_results", [])
            technology_results = result.get("technology_fingerprints", [])
            http_anomaly_result = {}

            if result.get("http_anomalies"):
                http_anomaly_result = result["http_anomalies"][0].get("model4_result", {})

            model5_result = run_model_5(
                port_scan_results=port_scan_results,
                technology_results=technology_results,
                http_anomaly_result=http_anomaly_result
            )

            model5_result["statistics"] = build_strategy_statistics(
                model5_result.get("strategies", [])
            )

        record["result"]["model5"] = model5_result
        
    except Exception as e:
        print(f"[Model 5] Error: {e}")

    # ====================================================
    # ✅ MODEL 6 LOGIC (LAZY LOADING & REGENERATION)
    # ====================================================
    try:
        model6_data = record["result"].get("model6", [])
        
        # Check if model6 data is missing OR in an outdated format (missing risk_level)
        outdated = False
        if model6_data and len(model6_data) > 0:
            first_item = model6_data[0]
            if "risk_level" not in first_item or "service" not in first_item:
                outdated = True
                print("[Model 6] Outdated data detected, forcing regeneration...")

        if not model6_data or outdated:
            tech_results = record["result"].get("technology_fingerprints", [])
            raw_docs = record["result"].get("raw_docs", [])
            subdomain_count = len(raw_docs)
            
            vulnerabilities_to_score = []
            
            # Map port metrics per subdomain
            subdomain_metrics = {
                s["subdomain"]: len(s.get("open_ports", []))
                for s in raw_docs
            }
            
            # Use Model 4 results if present
            anomaly_map = {}
            if record["result"].get("http_anomalies"):
                anomaly_map = {a["subdomain"]: a["model4_result"] for a in record["result"]["http_anomalies"]}

            for tech_res in tech_results:
                url = tech_res.get("url", "")
                subdomain = url.replace("http://", "").replace("https://", "")
                exposed_service_count = subdomain_metrics.get(subdomain, 0)
                anomaly_data = anomaly_map.get(subdomain, {})
                
                for tech in tech_res.get("technologies", []):
                    # Robust port detection
                    port = tech.get("metadata", {}).get("port")
                    if not port or port == 0:
                        port = 443 if "https://" in url else 80
                        
                    for cve in tech.get("cves", []):
                        record_features = {
                            "domain": record.get("domain"),
                            "subdomain": subdomain,
                            "service_name": tech.get("technology"),
                            "port_number": int(port),
                            "cvss_score": float(cve.get("cvss", 0.0)),
                            "exploit_available": 1 if tech.get("source") == "ExploitDB" else 0,
                            "cve_id": cve.get("cve"),
                            "technology_stack": tech.get("technology"),
                            "is_public_port": 1,
                            "anomaly_flag": 1 if anomaly_data.get("status") == "suspicious" else 0,
                            "traffic_anomaly_score": float(anomaly_data.get("anomaly_score", 0.0)),
                            "misconfiguration_flag": 0,
                            "subdomain_count": subdomain_count,
                            "exposed_service_count": exposed_service_count
                        }
                        vulnerabilities_to_score.append(record_features)

            if vulnerabilities_to_score:
                print(f"[Model 6] Scoring {len(vulnerabilities_to_score)} vulnerabilities for report")
                scorer = get_model6()
                record["result"]["model6"] = scorer.predict_batch(vulnerabilities_to_score)
            else:
                record["result"]["model6"] = []

    except Exception as e:
        print(f"[Model 6] Error: {e}")

    # ====================================================
    # MODEL 7 – Centralized Recommendation Engine
    # ====================================================
    try:
        model6_results = record["result"].get("model6", [])
        # Normalize: Model 6 returns "cvss", engine expects "cvss_score" or "cvss"
        vulnerabilities_for_model7 = []
        for v in model6_results:
            vuln = dict(v)
            if "cvss_score" not in vuln and "cvss" in vuln:
                vuln["cvss_score"] = vuln["cvss"]
            vulnerabilities_for_model7.append(vuln)

        recommendation_engine = RecommendationEngine()
        recommendations = recommendation_engine.generate_recommendations(vulnerabilities_for_model7)

        report_id = record.get("_id")
        report_id_str = str(report_id) if report_id else None
        domain = record.get("domain", "")

        for rec in recommendations:
            doc = dict(rec)
            doc["report_id"] = report_id_str
            doc["domain"] = domain
            doc["created_at"] = datetime.datetime.utcnow()
            try:
                recommendations_collection.insert_one(doc)
            except Exception as e:
                print(f"[Model 7] MongoDB insert warning: {e}")

        record["result"]["recommendations"] = recommendations
    except Exception as e:
        print(f"[Model 7] Error: {e}")
        record["result"]["recommendations"] = []

    record["_id"] = str(record["_id"])

    # ── Audit Log: report downloaded/viewed ──
    log_audit_event(
        action="report_downloaded",
        domain=record.get("domain", ""),
        details={"report_id": record["_id"]},
    )

    return jsonify(record)


@report_bp.route("/verify_headers", methods=["GET"])
@login_required
def verify_headers():
    url = request.args.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        
        headers = {
            "Server": response.headers.get("Server", "Not detected"),
            "X-Powered-By": response.headers.get("X-Powered-By", "Not detected"),
            "X-AspNet-Version": response.headers.get("X-AspNet-Version", "Not detected"),
            "X-PHP-Version": response.headers.get("X-PHP-Version", "Not detected"),
            "X-Runtime": response.headers.get("X-Runtime", "Not detected"),
            "X-Framework": response.headers.get("X-Framework", "Not detected"),
            "Content-Type": response.headers.get("Content-Type", "Not detected"),
            "Status-Code": response.status_code,
            "Final-URL": response.url
        }
        
        return jsonify({
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "relevant_headers": headers,
            "verification_timestamp": datetime.datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
