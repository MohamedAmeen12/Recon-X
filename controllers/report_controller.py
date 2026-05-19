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
    Enrich a report record with data from supporting collections.
    IMPORTANT: This function is called on every report page load — keep it FAST.
    Never run Model 5 (Exploit-DB calls) or Model 6 (XGBoost inference) here;
    those are computed once during the scan and stored in the report document.

    Performance: MongoDB queries for raw_docs, technologies, and recommendations
    run concurrently using ThreadPoolExecutor so total latency ≈ max(each query)
    instead of sum(each query).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed as _asc
    domain = record.get("domain")
    result = record.setdefault("result", {})
    report_id = str(record["_id"])

    # ── Export Fallback: Regenerate exports in background if missing ────────
    # Running the export pipeline synchronously here would block the entire
    # request for minutes, causing the "infinite spinner" on the report page.
    # Instead we fire it as a daemon thread and return immediately.
    if "report_files" not in result:
        import threading as _t
        def _regen_exports():
            try:
                from pipeline.pipeline_controller import run_export_pipeline
                export_res = run_export_pipeline(result, domain, report_id)
                db.reports_collection.update_one(
                    {"_id": record["_id"]},
                    {"$set": {
                        "result.report_files": export_res["report_files"],
                        "result.export_status": export_res["export_status"],
                    }},
                )
            except Exception as _e:
                print(f"[Enrich] Background export error: {_e}")
        _t.Thread(target=_regen_exports, daemon=True).start()

    # ── Run all three DB hydration queries concurrently ──────────────────────
    def _fetch_raw_docs():
        if result.get("raw_docs"):
            return None
        return list(db.subdomains_collection.find(
            {"domain": domain}, {"_id": 0}
        ).sort("scanned_at", -1).limit(100))   # limit 100 (was 200) for faster transfer

    def _fetch_technologies():
        if result.get("technology_fingerprints"):
            return None
        return list(db.technologies_collection.find(
            {"domain": domain}, {"_id": 0}
        ).sort("scanned_at", -1))

    def _fetch_recommendations():
        if result.get("recommendations"):
            return None
        return list(db.recommendations_collection.find(
            {"report_id": report_id}, {"_id": 0}
        ))

    with ThreadPoolExecutor(max_workers=3) as _pool:
        _rf = _pool.submit(_fetch_raw_docs)
        _tf = _pool.submit(_fetch_technologies)
        _rr = _pool.submit(_fetch_recommendations)
        raw_docs_db      = _rf.result()
        technologies_db  = _tf.result()
        recommendations  = _rr.result()

    # ── 0. Apply raw_docs ─────────────────────────────────────────────────────
    if raw_docs_db is not None:
        result["raw_docs"] = raw_docs_db
        result.setdefault("total_candidates", len(raw_docs_db))
        result.setdefault("resolved",
            sum(1 for s in raw_docs_db if s.get("ip") and s["ip"] != "Unresolved"))
        result.setdefault("live_http",
            sum(1 for s in raw_docs_db if s.get("live_http")))

    # ── 1. Apply technology fingerprints (O(1) dedup via set) ────────────────
    if technologies_db is not None:
        tech_by_url: dict = {}
        # Use a set for O(1) duplicate check instead of the previous O(N) any() scan
        seen_keys: dict = {}   # url → set of (technology, version) tuples

        for tech in technologies_db:
            url = tech.get("url") or f"http://{tech.get('subdomain', '')}"
            tech_by_url.setdefault(url, {"url": url, "technologies": []})
            seen_keys.setdefault(url, set())

            dedup_key = (tech.get("technology"), tech.get("version"))
            if dedup_key in seen_keys[url]:
                continue
            seen_keys[url].add(dedup_key)

            tech_cves = tech.get("cves") or []
            if not tech_cves and tech.get("max_cvss", 0) > 0:
                cvss_val = float(tech["max_cvss"])
                severity = (
                    "CRITICAL" if cvss_val >= 9 else
                    "HIGH"     if cvss_val >= 7 else
                    "MEDIUM"   if cvss_val >= 4 else "LOW"
                )
                tech_cves = [{
                    "cve": "CVE-PENDING", "cvss": cvss_val, "severity": severity,
                    "description": (
                        f"Known vulnerability in {tech.get('technology', '')} "
                        f"{tech.get('version', '')} (max CVSS {cvss_val})"
                    ),
                }]

            tech_by_url[url]["technologies"].append({
                "technology":           tech.get("technology"),
                "version":              tech.get("version"),
                "category":             tech.get("category", "Unknown"),
                "cves":                 tech_cves,
                "vulnerability_status": tech.get("vulnerability_status", "unknown"),
                "confidence":           tech.get("confidence", 0.0),
                "max_cvss":             tech.get("max_cvss", 0.0),
                "source":               tech.get("source", ""),
            })

        result["technology_fingerprints"] = list(tech_by_url.values())

    # ── 2. Model 5 statistics (zero-cost, in-memory) ──────────────────────────
    try:
        if result.get("model5") and "statistics" not in result["model5"]:
            result["model5"]["statistics"] = build_strategy_statistics(
                result["model5"].get("strategies", [])
            )
    except Exception as e:
        print(f"[Enrich] Model 5 statistics error: {e}")

    # ── 3. Apply recommendations ──────────────────────────────────────────────
    if recommendations:
        result["recommendations"] = recommendations

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
            
            if not pdf_path:
                return jsonify({"error": "Failed to generate PDF. You need to ensure 'wkhtmltopdf' is installed on your operating system (C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe). Download it from wkhtmltopdf.org"}), 500
                
            with open(pdf_path, "rb") as f:
                pdf_data = f.read()

        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=reconx_security_report_{domain_name}.pdf'
        
        return response

    except Exception as e:
        print(f"[PDF Redesign] Error: {e}")
        return jsonify({"error": str(e)}), 500
