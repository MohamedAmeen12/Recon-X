"""
Scan Controller - Handles domain scanning operations
"""
import time
import datetime
from flask import request, jsonify, Blueprint
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from models.model1 import run_subdomain_discovery
from models.model3 import run_technology_fingerprinting_for_subdomains
from config.database import (
    subdomains_collection, reports_collection,
    technologies_collection, vulnerabilities_collection
)

scan_bp = Blueprint('scan', __name__)


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

        result = run_subdomain_discovery(domain)
        print(f"Model 1 completed in {time.time() - start:.2f} seconds")

        # Store results into DB
        for sub in result.get("raw_docs", []):
            sub["domain"] = domain
            sub["scanned_at"] = datetime.datetime.utcnow()
            subdomains_collection.update_one(
                {"domain": domain, "subdomain": sub["subdomain"]},
                {"$set": sub},
                upsert=True
            )

        # Model 3: Technology Fingerprinting & Vulnerability Detection
        tech_results = []
        if include_tech_scan:
            try:
                print("Starting Model 3 (Technology Fingerprinting)...")
                live_subdomains = [sub for sub in result.get("raw_docs", []) if sub.get("live_http")]
                
                if live_subdomains:
                    subdomains_data = []
                    for sub_doc in live_subdomains[:5]:
                        subdomain = sub_doc.get("subdomain")
                        ip = sub_doc.get("ip")
                        url = f"http://{subdomain}" if subdomain else None
                        
                        subdomains_data.append({
                            "subdomain": subdomain,
                            "url": url,
                            "nmap_data": None,
                            "ip": ip
                        })
                    
                    executor = ThreadPoolExecutor(max_workers=1)
                    future = executor.submit(run_technology_fingerprinting_for_subdomains, subdomains_data)
                    
                    try:
                        tech_results = future.result(timeout=30)
                    except FutureTimeoutError:
                        print("Model 3 timed out after 30 seconds - skipping")
                        tech_results = []
                    except Exception as e:
                        print(f"Model 3 error: {e}")
                        tech_results = []
                    
                    # Store technology fingerprints in MongoDB
                    for tech_result in tech_results:
                        url = tech_result.get("url")
                        subdomain = tech_result.get("url", "").replace("http://", "").replace("https://", "")
                        
                        for tech in tech_result.get("technologies", []):
                            tech_doc = {
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
                            
                            technologies_collection.update_one(
                                {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version")
                                },
                                {"$set": tech_doc},
                                upsert=True
                            )
                            
                            # Store CVE details separately
                            for cve in tech.get("cves", []):
                                cve_doc = {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version"),
                                    "cve_id": cve.get("cve"),
                                    "cvss_score": cve.get("cvss"),
                                    "description": cve.get("description"),
                                    "severity": cve.get("severity", "UNKNOWN"),
                                    "published_date": cve.get("published_date"),
                                    "cwe": cve.get("cwe", "N/A"),
                                    "scanned_at": datetime.datetime.utcnow()
                                }
                                
                                vulnerabilities_collection.update_one(
                                    {
                                        "domain": domain,
                                        "subdomain": subdomain,
                                        "cve_id": cve.get("cve")
                                    },
                                    {"$set": cve_doc},
                                    upsert=True
                                )
            except Exception as e:
                print(f"Model 3 error: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("Model 3 skipped (set include_tech_scan=true to enable)")

        report = {
            "domain": domain,
            "total_candidates": result.get("total_candidates", 0),
            "resolved": result.get("resolved", 0),
            "live_http": result.get("live_http", 0),
            "elapsed_seconds": time.time() - start,
            "examples": result.get("examples", []),
            "clusters": result.get("clusters", []),
            "raw_docs": result.get("raw_docs", []),
            "ports_summary": result.get("ports_summary", {}),
            "technology_fingerprints": tech_results if tech_results else []
        }

        reports_collection.update_one(
            {"domain": domain},
            {"$set": {"result": report}},
            upsert=True
        )

        return jsonify({"message": "Scan complete", "report": report}), 200
    except Exception as e:
        print(f"Error in scan_domain: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500
