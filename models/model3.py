"""
Model 3: Technology Fingerprinting & Vulnerability Detection (Supervised ML)

Input: Nmap output, Web banners
Output: Detected technologies, CVE mappings, Vulnerability Prediction
"""
import numpy as np
import os
import re
import logging
import joblib
from scipy.sparse import hstack
from typing import Dict, List, Optional
from utils.tech_fingerprint_tool import fingerprint_technologies
from models.active_validator import validate_cve

# Global variables for model artifacts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models", "artifacts", "model3")
LR_MODEL_PATH = os.path.join(MODEL_DIR, "model3_lr.pkl")
TFIDF_PATH = os.path.join(MODEL_DIR, "model3_tfidf.pkl")

# Cache for loaded models
_artifacts = {
    "model": None,
    "tfidf": None
}

logger = logging.getLogger(__name__)


def create_technology_fingerprint(tech_name, version=""):
    """
    Create a fingerprint string from technology name and version.
    Used for TF-IDF vectorization.
    """
    fingerprint = f"{tech_name.lower()} {version.lower()}"
    # Add version components separately for better matching
    if version:
        version_parts = re.findall(r'\d+', version)
        fingerprint += " " + " ".join(version_parts)
    return fingerprint.strip()


def load_artifacts():
    """Load model artifacts with caching"""
    if _artifacts["model"] is not None and _artifacts["tfidf"] is not None:
        return _artifacts["model"], _artifacts["tfidf"]
    
    try:
        if os.path.exists(LR_MODEL_PATH) and os.path.exists(TFIDF_PATH):
            _artifacts["model"] = joblib.load(LR_MODEL_PATH)
            _artifacts["tfidf"] = joblib.load(TFIDF_PATH)
            # print(f"[Model 3] Loaded ML models from {MODEL_DIR}")
        else:
            print(f"[Model 3] Warning: Model artifacts not found. Run scripts/train_model3.py")
    except Exception as e:
        print(f"[Model 3] Error loading models: {e}")
        
    return _artifacts["model"], _artifacts["tfidf"]


from packaging.version import Version, InvalidVersion

def is_version_in_range(v_str: str, range_info: dict) -> tuple:
    """
    Programmatic comparison of detected version against NVD range definitions.
    Returns: (bool, status_label, range_str)
    """
    try:
        v = Version(v_str)
        
        start_inc = range_info.get("start_inc")
        start_exc = range_info.get("start_exc")
        end_inc = range_info.get("end_inc")
        end_exc = range_info.get("end_exc")
        
        # Build range string for justification
        s = start_inc or start_exc or "0"
        e = end_inc or end_exc or "latest"
        range_str = f"{s} – {e}"
        
        # Check boundaries first (Task 1 Rule 2 in Master Prompt)
        is_boundary = False
        if start_inc and v == Version(start_inc): is_boundary = True
        if start_exc and v == Version(start_exc): is_boundary = True
        if end_inc and v == Version(end_inc): is_boundary = True
        if end_exc and v == Version(end_exc): is_boundary = True
        
        if is_boundary:
            return True, "UNCERTAIN (BOUNDARY CASE)", range_str

        in_start = True
        if start_inc: in_start = (v >= Version(start_inc))
        elif start_exc: in_start = (v > Version(start_exc))
        
        in_end = True
        if end_inc: in_end = (v <= Version(end_inc))
        elif end_exc: in_end = (v < Version(end_exc))
        
        if in_start and in_end:
            return True, "CONFIRMED VULNERABILITY", range_str
            
        return False, "NOT AFFECTED", range_str
        
    except (InvalidVersion, ValueError, TypeError):
        return False, "INSUFFICIENT EVIDENCE", "Unclear"

def lookup_cve(tech_name, version=""):
    """
    Lookup CVE information using NVD API.
    """
    cves = []
    from utils.domain_validator import is_lab_mode_enabled
    if is_lab_mode_enabled():
        return cves

    try:
        from utils.nvd_api_tool import get_nvd_client
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
        
        client = get_nvd_client()
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(client.lookup_technology_vulnerabilities, tech_name, version)
        
        try:
            df = future.result(timeout=25)  # NVD API can be slow; 25 s gives it enough time
            if df is not None and not df.empty:
                for _, row in df.head(10).iterrows():
                    cves.append({
                        "cve": row["cve_id"],
                        "cvss": float(row["cvss_score"]),
                        "description": row["description"],
                        "severity": row["severity"],
                        "published_date": row["published_date"],
                        "affected_versions": row.get("affected_versions", []),
                        "cwe": row.get("cwe", "N/A")
                    })
        except FutureTimeoutError:
            logger.warning(f"[Model 3] NVD lookup timed out for {tech_name} {version} — CVEs may be incomplete")
        except Exception as _e:
            logger.warning(f"[Model 3] NVD API error for {tech_name} {version}: {_e}")
            
    except Exception as e:
        # Fallback to empty context if NVD tool fails drastically
        print(f"[Model 3] NVD lookup error: {e}")
    
    return cves


def classify_vulnerability_status(tech_name, version, cves):
    """
    STRICT MODE: Programmatic justification replaces supervised ML.
    """
    # Reject if missing data (Task 1 Rule 4)
    if not version:
        return {
            "status": "safe",
            "confidence": 0.0,
            "reason": "INSUFFICIENT EVIDENCE: Version missing",
            "cves": []
        }

    confirmed_cves = []
    potential_cves = []

    for cve in cves:
        affected_ranges = cve.get("affected_versions", [])

        # No version range data from NVD — include as a potential finding rather than
        # silently dropping it. Many real CVEs lack CPE configurations in NVD.
        if not affected_ranges:
            cve = dict(cve)
            cve["justification"] = (
                f"POTENTIAL: No version range data available in NVD for this CVE. "
                f"Detected version {version} may be affected — manual review recommended."
            )
            cve["affected_version_range"] = "N/A (no NVD range data)"
            potential_cves.append(cve)
            continue

        final_justification = "NOT AFFECTED"
        final_range = "N/A"
        matched = False

        for r_info in affected_ranges:
            is_match, status, r_str = is_version_in_range(version, r_info)
            if is_match:
                matched = True
                final_range = r_str
                if status == "CONFIRMED VULNERABILITY":
                    final_justification = f"Version {version} is within affected range {r_str}"
                    break
                else:
                    final_justification = status

        if matched:
            cve = dict(cve)
            cve["justification"] = final_justification
            cve["affected_version_range"] = final_range
            confirmed_cves.append(cve)

    # Always include confirmed matches first, then potentials (no range data).
    # Returning both ensures CVEs found only via keyword search are not suppressed.
    valid_cves = confirmed_cves + potential_cves

    if not valid_cves:
        return {
            "status": "safe",
            "confidence": 1.0,
            "reason": "No confirmed vulnerabilities for this version",
            "cves": []
        }

    status_label = "vulnerable" if confirmed_cves else "potential"
    reason = (
        f"{len(confirmed_cves)} confirmed + {len(potential_cves)} potential matches"
        if confirmed_cves and potential_cves
        else f"{'Confirmed' if confirmed_cves else 'Potential'} {len(valid_cves)} matches"
    )
    return {
        "status": status_label,
        "confidence": 1.0 if confirmed_cves else 0.5,
        "reason": reason,
        "cves": valid_cves
    }


def run_technology_fingerprinting(urls_data):
    """
    Main function for Model 3: Technology Fingerprinting & Vulnerability Detection.
    """
    results = []
    
    # Pre-load models once
    load_artifacts()
    
    for url_info in urls_data:
        url = url_info.get("url")
        is_root = url_info.get("is_root", False)
        nmap_data = url_info.get("nmap_data")
        whatweb_result = url_info.get("whatweb_result")
        
        if not url:
            continue
        
        # Step 1: Fingerprint technologies
        technologies = fingerprint_technologies(url, nmap_data, whatweb_result)
        
        # Step 2: Process each technology
        tech_results = []
        for tech in technologies:
            tech_name = tech.get("name", "")
            version = tech.get("version", "")
            
            # Step 2a: Lookup CVEs (Required for features)
            cves = lookup_cve(tech_name, version)
            
            # Step 2b: Strict Classification (Task 1)
            vuln_status = classify_vulnerability_status(tech_name, version, cves)
            
            # Extract filtered CVEs from status result
            filtered_cves = vuln_status.get("cves", [])

            # Step 2c: Active Validation (Task 2)
            verified_cves = []
            unverified_cves = []
            
            for cve_item in filtered_cves:
                cve_id = cve_item.get("cve")
                if cve_id:
                    validation_result = validate_cve(cve_id, url)
                    status = validation_result.get("validation_status", "Unknown")
                    cve_item["validation_status"] = status
                    cve_item["http_response_code"] = validation_result.get("http_response_code")
                    
                    if status == "Exploitable":
                        verified_cves.append(cve_item)
                    else:
                        unverified_cves.append(cve_item)

            tech_result = {
                "technology": tech_name,
                "version": version,
                "category": tech.get("category", "Unknown"),
                "vulnerability_status": vuln_status["status"],
                "confidence": vuln_status["confidence"],
                "max_cvss": max([c.get("cvss", 0) for c in filtered_cves]) if filtered_cves else 0.0,
                # New Categorized Slots
                "verified_vulnerabilities": verified_cves,
                "unverified_vulnerabilities": unverified_cves,
                "cves": filtered_cves,
                "all_cves": filtered_cves,
                "source": tech.get("source", ""),
                "metadata": {
                    "port": tech.get("port"),
                    "raw_data": tech.get("raw_data", {})
                }
            }
            
            tech_results.append(tech_result)
        
        results.append({
            "url": url,
            "is_root": is_root,
            "technologies": tech_results,
            "vulnerable_count": sum(1 for t in tech_results if t["vulnerability_status"] == "vulnerable"),
            "safe_count": sum(1 for t in tech_results if t["vulnerability_status"] == "safe")
        })
    
    return results


def run_technology_fingerprinting_for_subdomains(subdomains_data):
    """
    Run technology fingerprinting for multiple subdomains.
    """
    urls_data = []
    for sub_data in subdomains_data:
        url = sub_data.get("url") or f"http://{sub_data.get('subdomain', '')}"
        urls_data.append({
            "url": url,
            "is_root": sub_data.get("is_root", False),
            "nmap_data": sub_data.get("nmap_data"),
            "whatweb_result": None
        })
    
    return run_technology_fingerprinting(urls_data)


# =============================================================================
# ENHANCED PIPELINE — additive extension, existing functions above are unchanged
# =============================================================================

def _severity_to_cvss(severity: str) -> float:
    """Map Nuclei severity string to approximate CVSS float."""
    return {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.0,
    }.get(str(severity).lower(), 0.0)


def run_full_model3_pipeline(subdomains_data: list) -> list:
    """
    Enhanced Model 3 entry point that executes:
      1. Existing technology fingerprinting (run_technology_fingerprinting_for_subdomains)
      2. NEW crawling pipeline (CrawlingPipeline) in parallel
      3. Merges crawling discoveries back into the fingerprinting results

    The existing function is called unchanged. This wrapper only adds data on top.
    Falls back gracefully to the original results if the crawling pipeline errors.

    Args:
        subdomains_data: Same format accepted by run_technology_fingerprinting_for_subdomains.

    Returns:
        Enhanced list — same schema as run_technology_fingerprinting_for_subdomains output
        with an additional "crawling" key per result dict.
    """
    import logging as _logging
    _log = _logging.getLogger(__name__)

    # ── Step 1: Existing fingerprinting (unchanged) ──────────────────────
    existing_results = run_technology_fingerprinting_for_subdomains(subdomains_data)

    # ── Step 2: Crawling pipeline ────────────────────────────────────────
    crawling_results: list = []
    try:
        from models.crawling.pipeline import CrawlingPipeline
        pipeline = CrawlingPipeline()
        crawling_results = pipeline.run_for_subdomains(subdomains_data)
    except Exception as exc:
        _log.error(f"[Model3Enhanced] Crawling pipeline failed (non-fatal): {exc}")

    if not crawling_results:
        # Tag results with empty crawling data so callers always have the key
        for r in existing_results:
            r.setdefault("crawling", _empty_crawling_block())
        return existing_results

    # ── Step 3: Merge crawling discoveries into fingerprinting results ────
    crawling_by_url = {r["url"]: r for r in crawling_results}

    enhanced = []
    for tech_result in existing_results:
        url = tech_result.get("url", "")
        crawl_data = crawling_by_url.get(url, {})

        merged = dict(tech_result)
        merged["crawling"] = {
            "crawl_source":            crawl_data.get("crawl_result", {}).get("source"),
            "endpoints":               crawl_data.get("endpoint_collection", {}).get("endpoints", []),
            "endpoint_summary":        {
                k: crawl_data.get("endpoint_collection", {}).get(k, 0)
                for k in ("total", "with_params", "api_count", "high_value_count")
            },
            "parameter_inventory":     crawl_data.get("endpoint_collection", {}).get("parameter_inventory", {}),
            "js_analysis":             crawl_data.get("js_analysis", {}),
            "nuclei_extended_findings": crawl_data.get("validated_findings", []),
            "pipeline_summary":        crawl_data.get("summary", {}),
        }

        # Inject confirmed Nuclei crawling findings as CVE-like entries so they
        # flow through Model 6 (risk scoring) and Model 7 (recommendations).
        # Only inject confirmed findings to avoid noise.
        confirmed_findings = [
            f for f in crawl_data.get("validated_findings", [])
            if f.get("is_confirmed")
        ]
        if confirmed_findings and merged.get("technologies"):
            for finding in confirmed_findings:
                synthetic_cve = {
                    "cve": finding.get("template_id", "NUCLEI-CRAWL-UNKNOWN"),
                    "cvss": _severity_to_cvss(finding.get("severity", "low")),
                    "description": finding.get("description") or finding.get("name", ""),
                    "severity": str(finding.get("severity", "low")).upper(),
                    "affected_versions": [],
                    "justification": (
                        f"Discovered via crawled endpoint ({finding.get('discovery_source', 'crawler')}). "
                        + finding.get("confidence_explanation", "")
                    ),
                    "affected_version_range": "N/A",
                    "validation_status": (
                        "Exploitable"
                        if finding.get("confidence_level") == "HIGH"
                        else "Unverified"
                    ),
                    "source": "crawling_nuclei",
                    "matched_at": finding.get("matched_at", ""),
                }
                # Append to the first technology entry (root-level finding)
                if merged["technologies"]:
                    first_tech = merged["technologies"][0]
                    existing_ids = {c.get("cve") for c in first_tech.get("cves", [])}
                    if synthetic_cve["cve"] not in existing_ids:
                        first_tech.setdefault("cves", []).append(synthetic_cve)

        enhanced.append(merged)

    return enhanced


def _empty_crawling_block() -> dict:
    return {
        "crawl_source": None,
        "endpoints": [],
        "endpoint_summary": {"total": 0, "with_params": 0, "api_count": 0, "high_value_count": 0},
        "parameter_inventory": {},
        "js_analysis": {},
        "nuclei_extended_findings": [],
        "pipeline_summary": {},
    }
