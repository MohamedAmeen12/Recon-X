"""
Report Controller - Handles report retrieval and technology verification
"""
import os
import datetime
import requests
from flask import request, jsonify, Blueprint, session, make_response
from middlewares.auth_middleware import login_required
from bson.objectid import ObjectId
from utils.audit_logger import log_audit_event
import config.database as db
from utils.logger import get_logger
from utils.json_utils import mongo_to_json

logger = get_logger(__name__)

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

def enrich_report_data(record):
    """
    Shared logic to enrich a report record with technology fingerprints, 
    Model 5 (strategies), and Model 6 (scored vulnerabilities).
    """
    domain = record.get("domain")
    result = record.setdefault("result", {})

    # 1. Technology Fingerprint Fallback
    if not result.get("technology_fingerprints"):
        try:
            technologies = list(db.technologies_collection.find({"domain": domain}, {"_id": 0}).sort("scanned_at", -1))
            vulnerabilities = list(db.vulnerabilities_collection.find({"domain": domain}, {"_id": 0}).sort("cvss_score", -1))
            
            tech_by_url = {}
            for tech in technologies:
                url = tech.get("url", f"http://{tech.get('subdomain', '')}")
                tech_by_url.setdefault(url, {"url": url, "technologies": []})
                
                if not any(t["technology"] == tech.get("technology") and t["version"] == tech.get("version") for t in tech_by_url[url]["technologies"]):
                    tech_cves = [
                        {
                            "cve": v.get("cve_id"),
                            "cvss": v.get("cvss_score"),
                            "severity": v.get("severity", "UNKNOWN")
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
                        "cves": tech_cves
                    })
            result["technology_fingerprints"] = list(tech_by_url.values())
        except Exception as e:
            print(f"[Enrich] Tech Error: {e}")

    # 2. Model 5 (Strategies)
    try:
        if result.get("model5"):
            if "statistics" not in result["model5"]:
                result["model5"]["statistics"] = build_strategy_statistics(result["model5"].get("strategies", []))
        else:
            result["model5"] = run_model_5(
                port_scan_results=result.get("port_scan_results", []),
                technology_results=result.get("technology_fingerprints", []),
                http_anomaly_result=result.get("http_anomalies", [{}])[0].get("model4_result", {}) if result.get("http_anomalies") else {}
            )
            result["model5"]["statistics"] = build_strategy_statistics(result["model5"].get("strategies", []))
    except Exception as e:
        print(f"[Enrich] Model 5 Error: {e}")

    # 3. Model 6 (Risk Scoring)
    try:
        model6_data = result.get("model6", [])
        if not model6_data:
            tech_results = result.get("technology_fingerprints", [])
            raw_docs = result.get("raw_docs", [])
            subdomain_metrics = {s["subdomain"]: len(s.get("open_ports", [])) for s in raw_docs}
            anomaly_map = {a["subdomain"]: a["model4_result"] for a in result.get("http_anomalies", [])}
            
            vulnerabilities_to_score = []
            for tech_res in tech_results:
                url = tech_res.get("url", "")
                subdomain = url.replace("http://", "").replace("https://", "")
                for tech in tech_res.get("technologies", []):
                    port = tech.get("metadata", {}).get("port") or (443 if "https://" in url else 80)
                    for cve in tech.get("cves", []):
                        vulnerabilities_to_score.append({
                            "domain": domain, "subdomain": subdomain, "service_name": tech.get("technology"),
                            "version": tech.get("version", ""), "port_number": int(port),
                            "cvss_score": float(cve.get("cvss", 0.0)), "cve_id": cve.get("cve"),
                            "traffic_anomaly_score": float(anomaly_map.get(subdomain, {}).get("anomaly_score", 0.0)),
                            "subdomain_count": len(raw_docs), "exposed_service_count": subdomain_metrics.get(subdomain, 0)
                        })
            if vulnerabilities_to_score:
                scorer = get_model6()
                result["model6"] = scorer.predict_batch(vulnerabilities_to_score)
    except Exception as e:
        print(f"[Enrich] Model 6 Error: {e}")

    # 4. Model 7 (Recommendations) - Try to fetch from DB if missing in result
    if not result.get("recommendations"):
        try:
            recs = list(db.recommendations_collection.find({"report_id": str(record["_id"])}, {"_id": 0}))
            if recs:
                result["recommendations"] = recs
        except Exception as e:
            logger.warning(f"[Enrich] Report {record.get('_id')} has no domain. Cannot enrich.")

    return record

@report_bp.route("/get_technologies", methods=["GET"])
@login_required
def get_technologies():
    domain = request.args.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    try:
        technologies = list(db.technologies_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("scanned_at", -1))
        
        vulnerabilities = list(db.vulnerabilities_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("cvss_score", -1))
        
        return jsonify(mongo_to_json({
            "domain": domain,
            "technologies": technologies,
            "vulnerabilities": vulnerabilities,
            "total_technologies": len(technologies),
            "total_vulnerabilities": len(vulnerabilities)
        })), 200
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
            record = db.reports_collection.find_one({"_id": ObjectId(report_id)})
        except:
            return jsonify({"error": "Invalid Report ID"}), 400

    # 3. FALLBACK: FETCH BY DOMAIN (LATEST FOR USER)
    elif domain:
        # If admin, just get the latest global report (or specific user's logic? For now, latest owned by anyone or maybe just latest scan on that domain)
        # But requirement says "see only their scan" for users.
        if is_admin:
             record = db.reports_collection.find_one(
                {"domain": domain},
                sort=[("scanned_at", -1)]
             )
        else:
            record = db.reports_collection.find_one(
                {"domain": domain, "user_id": current_user_id},
                sort=[("scanned_at", -1)]
            )
    else:
        return jsonify({"error": "Domain or Report ID required"}), 400

    if not record:
        return jsonify({"message": "No report found"}), 404

    record_owner = record.get("user_id")
    if not is_admin and record_owner and str(record_owner) != str(current_user_id):
        return jsonify({"error": "Unauthorized access to this report"}), 403

    # Enrich report data (using shared logic)
    record = enrich_report_data(record)

    # ── Audit Log...

    record["_id"] = str(record["_id"])

    # ── Audit Log: report downloaded/viewed ──
    log_audit_event(
        action="report_downloaded",
        domain=record.get("domain", ""),
        details={"report_id": record["_id"]},
    )

    return jsonify(mongo_to_json(record))


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

@report_bp.route("/generate_recommendations", methods=["POST"])
@login_required
def generate_recommendations():
    data = request.json or {}
    report_id = data.get("report_id", "").strip()
    domain = data.get("domain", "").strip()
    
    current_user_id = session["user_id"]
    is_admin = session.get("role") == "admin"
    record = None

    if report_id:
        try:
            record = db.reports_collection.find_one({"_id": ObjectId(report_id)})
        except:
            return jsonify({"error": "Invalid Report ID"}), 400
    elif domain:
        if is_admin:
             record = db.reports_collection.find_one(
                {"domain": domain},
                sort=[("scanned_at", -1)]
             )
        else:
            record = db.reports_collection.find_one(
                {"domain": domain, "user_id": current_user_id},
                sort=[("scanned_at", -1)]
            )
    else:
        return jsonify({"error": "Domain or Report ID required"}), 400

    if not record:
        return jsonify({"message": "No report found"}), 404
        
    record_owner = record.get("user_id")
    if not is_admin and record_owner and str(record_owner) != str(current_user_id):
        return jsonify({"error": "Unauthorized access to this report"}), 403

    try:
        model6_results = record.get("result", {}).get("model6", [])
        vulnerabilities_for_model7 = []
        for v in model6_results:
            vuln = dict(v)
            if "cvss_score" not in vuln and "cvss" in vuln:
                vuln["cvss_score"] = vuln["cvss"]
            vulnerabilities_for_model7.append(vuln)

        recommendation_engine = RecommendationEngine()
        recommendations = recommendation_engine.generate_recommendations(vulnerabilities_for_model7)

        report_id_str = str(record.get("_id"))
        domain_str = record.get("domain", "")

        # Optional: update recommendation collection
        for rec in recommendations:
            doc = dict(rec)
            doc["report_id"] = report_id_str
            doc["domain"] = domain_str
            doc["created_at"] = datetime.datetime.utcnow()
            try: # Use upsert safely if re-running
                db.recommendations_collection.update_one(
                    {"report_id": report_id_str, "cve_id": rec.get("cve_id"), "service": rec.get("service"), "port": rec.get("port")},
                    {"$set": doc},
                    upsert=True
                )
            except Exception as e:
                print(f"[Model 7] MongoDB insert warning: {e}")

        # Update the report record itself with the recommendations so future get_report could potentially see it
        db.reports_collection.update_one(
            {"_id": record["_id"]},
            {"$set": {"result.recommendations": recommendations}}
        )

        log_audit_event(
            action="recommendations_generated",
            domain=domain_str,
            details={"report_id": report_id_str, "vuln_count": len(vulnerabilities_for_model7)},
        )

        return jsonify(mongo_to_json({"recommendations": recommendations}))

    except Exception as e:
        print(f"[Model 7 Endpoint] Error: {e}")
        return jsonify({"error": f"Failed to generate recommendations: {str(e)}"}), 500

@report_bp.route("/download_fix_script", methods=["GET"])
@login_required
def download_fix_script():
    """
    Downloads a dynamically generated PowerShell remediation script.
    """
    try:
        host = request.args.get("host", "").strip()
        service = request.args.get("service", "").strip()
        port = request.args.get("port", "").strip()
        cve_id = request.args.get("cve_id", "").strip()
        
        vuln_dict = {
            "host": host,
            "service": service,
            "port": port,
            "cve_id": cve_id
        }
        
        engine = RecommendationEngine()
        script_content = engine.generate_fix_script(vuln_dict)
        
        response = make_response(script_content)
        response.headers["Content-Type"] = "application/octet-stream"
        
        filename_cve = cve_id if cve_id and cve_id != "N/A" else f"port_{port}"
        response.headers["Content-Disposition"] = f"attachment; filename=reconx_fix_{filename_cve}.ps1"
        
        return response
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
import tempfile
from utils.report_generator import generate_html_report, generate_pdf_report

@report_bp.route("/download_report", methods=["GET"])
@login_required
def download_report():
    """
    Redesigned: Generates HTML report then converts to PDF via wkhtmltopdf.
    """
    domain = request.args.get("domain", "").strip()
    report_id = request.args.get("report_id", "").strip()
    username = session.get("username", "Analyst")

    try:
        if report_id:
            record = db.reports_collection.find_one({"_id": ObjectId(report_id)})
        elif domain:
            record = db.reports_collection.find_one(
                {"domain": domain},
                sort=[("scanned_at", -1)]
            )
        else:
            return jsonify({"error": "Domain or Report ID required"}), 400

        if not record or not record.get("result"):
            return jsonify({"error": "No scan data available to generate report."}), 404

        # Enrich report data to match dashboard format (Models 5, 6, 7, and Tech Fingerprints)
        record = enrich_report_data(record)

        scan_results = record.get("result", {})
        scan_id = str(record.get("_id", "N/A"))
        domain_name = record.get("domain", "Unknown")

        # 1. Generate HTML
        html_content = generate_html_report(scan_results, domain_name, username, scan_id)

        # 2. Convert to PDF using temp files
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = os.path.join(tmpdir, "report.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            pdf_path = generate_pdf_report(html_path)
            
            with open(pdf_path, "rb") as f:
                pdf_data = f.read()

        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=reconx_security_report_{domain_name}.pdf'
        
        return response

    except Exception as e:
        print(f"[PDF Redesign] Error: {e}")
        return jsonify({"error": str(e)}), 500
