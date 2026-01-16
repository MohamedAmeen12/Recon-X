"""
Report Controller - Handles report retrieval and technology verification
"""
import datetime
import requests
from flask import request, jsonify, Blueprint
from config.database import (
    reports_collection, technologies_collection, vulnerabilities_collection
)

report_bp = Blueprint('report', __name__)


@report_bp.route("/get_technologies", methods=["GET"])
def get_technologies():
    """Get technology fingerprints and vulnerabilities for a domain from MongoDB."""
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
def get_report():
    domain = request.args.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    record = reports_collection.find_one({"domain": domain})
    if not record:
        return jsonify({"message": "No report found"}), 404

    # If technology_fingerprints is missing or empty, fetch from MongoDB
    if not record.get("result", {}).get("technology_fingerprints") or len(record.get("result", {}).get("technology_fingerprints", [])) == 0:
        try:
            technologies = list(technologies_collection.find(
                {"domain": domain},
                {"_id": 0}
            ).sort("scanned_at", -1))
            
            vulnerabilities = list(vulnerabilities_collection.find(
                {"domain": domain},
                {"_id": 0}
            ).sort("cvss_score", -1))
            
            # Group technologies by subdomain/url
            tech_by_url = {}
            for tech in technologies:
                url = tech.get("url", f"http://{tech.get('subdomain', '')}")
                if url not in tech_by_url:
                    tech_by_url[url] = {
                        "url": url,
                        "technologies": []
                    }
                
                existing_tech = next(
                    (t for t in tech_by_url[url]["technologies"] 
                     if t.get("technology") == tech.get("technology") and t.get("version") == tech.get("version")),
                    None
                )
                
                if not existing_tech:
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
            
            technology_fingerprints = list(tech_by_url.values())
            
            if "result" not in record:
                record["result"] = {}
            record["result"]["technology_fingerprints"] = technology_fingerprints
            
            reports_collection.update_one(
                {"domain": domain},
                {"$set": {"result": record["result"]}}
            )
            
        except Exception as e:
            print(f"Error fetching technologies for report: {e}")
            import traceback
            traceback.print_exc()

    record["_id"] = str(record["_id"])
    return jsonify(record)


@report_bp.route("/verify_headers", methods=["GET"])
def verify_headers():
    """Fetch and return HTTP headers from a URL for verification."""
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
        
        all_headers = dict(response.headers)
        
        return jsonify({
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "relevant_headers": headers,
            "all_headers": all_headers,
            "verification_timestamp": datetime.datetime.utcnow().isoformat()
        }), 200
        
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": f"Failed to fetch headers: {str(e)}",
            "url": url
        }), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
