"""
Model 3: Technology Fingerprinting & Vulnerability Detection (Supervised ML)

Input: Nmap output, Web banners
Output: Detected technologies, CVE mappings, Vulnerability Prediction
"""
import logging
import os
import re

import joblib
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from models.active_validator import validate_cve
from utils.tech_fingerprint_tool import fingerprint_technologies

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


def _clean_version(v_str: str) -> str:
    """
    Strip Linux distro suffixes and extra annotations from version strings.
    Examples:
      '2.4.7 (Ubuntu)'  → '2.4.7'
      '1.18.0-1~bionic' → '1.18.0'
      '7.4.33-1+deb11u1'→ '7.4.33'
      '8.2p1'           → '8.2' (packaging can't parse 'p1' suffix)
    """
    import re
    v = v_str.split()[0]          # drop anything after the first space
    v = v.split('+')[0]           # drop Debian revision (+deb11u1)
    v = v.split('~')[0]           # drop Ubuntu epoch (~bionic)
    v = v.split('-')[0]           # drop release candidate / patch level
    # Remove any trailing non-numeric suffix (e.g., '8.2p1' → '8.2')
    v = re.sub(r'[a-zA-Z]+\d*$', '', v)
    return v.strip('.')


def is_version_in_range(v_str: str, range_info: dict) -> tuple:
    """
    Programmatic comparison of detected version against NVD range definitions.
    Returns: (bool, status_label, range_str)
    Cleans the version string before parsing to handle distro suffixes.
    """
    try:
        v = Version(_clean_version(v_str))
        
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

# Process-level CVE cache — avoids hitting NVD repeatedly for the same tech/version
# across multiple subdomains in one scan and across sequential scans in the session.
_CVE_CACHE: dict = {}


def lookup_cve(tech_name, version=""):
    """
    Lookup CVE information using NVD API with process-level caching.
    Timeout reduced from 25 s to 10 s — NVD usually responds in < 2 s with an API key.
    NVD lookups are NOT skipped in DEV_MODE — DEV_MODE only controls auth bypass.
    Set SKIP_NVD_LOOKUPS=true to explicitly disable NVD (for offline testing).
    """
    import os
    if os.getenv("SKIP_NVD_LOOKUPS", "").strip().lower() == "true":
        return []

    cache_key = f"{tech_name.lower().strip()}:{version.lower().strip()}"
    if cache_key in _CVE_CACHE:
        return list(_CVE_CACHE[cache_key])   # return a copy so callers can mutate safely

    cves = []
    try:
        from utils.nvd_api_tool import get_nvd_client
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

        client = get_nvd_client()
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(client.lookup_technology_vulnerabilities, tech_name, version)
            try:
                df = future.result(timeout=10)  # reduced from 25 s
                if df is not None and not df.empty:
                    for _, row in df.head(5).iterrows():   # top-5 CVEs is enough
                        cves.append({
                            "cve":              row["cve_id"],
                            "cvss":             float(row["cvss_score"]),
                            "description":      row["description"],
                            "severity":         row["severity"],
                            "published_date":   row["published_date"],
                            "affected_versions": row.get("affected_versions", []),
                            "cwe":              row.get("cwe", "N/A"),
                        })
            except FutureTimeoutError:
                logger.warning(f"[Model 3] NVD timeout for {tech_name} {version}")
            except Exception as _e:
                logger.warning(f"[Model 3] NVD error for {tech_name} {version}: {_e}")
    except Exception as exc:
        print(f"[Model 3] NVD lookup error: {exc}")

    _CVE_CACHE[cache_key] = list(cves)
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


def _process_single_technology(tech: dict, url: str) -> dict:
    """
    Process one technology: CVE lookup → classification → active validation.
    Runs in a thread pool so all technologies for a URL are processed in parallel.
    """
    tech_name = tech.get("name", "")
    version   = tech.get("version", "")

    cves          = lookup_cve(tech_name, version)
    vuln_status   = classify_vulnerability_status(tech_name, version, cves)
    filtered_cves = vuln_status.get("cves", [])

    # Active validation — run all CVEs for this technology in parallel
    verified_cves   = []
    unverified_cves = []

    if filtered_cves:
        with ThreadPoolExecutor(max_workers=min(len(filtered_cves), 4)) as val_exec:
            val_futures = {
                val_exec.submit(validate_cve, cve_item.get("cve"), url): cve_item
                for cve_item in filtered_cves
                if cve_item.get("cve")
            }
            for vfuture, cve_item in val_futures.items():
                try:
                    vresult = vfuture.result(timeout=12)  # was 60 s
                    vstatus = vresult.get("validation_status", "Unknown")
                    cve_item = dict(cve_item)
                    cve_item["validation_status"] = vstatus
                    cve_item["http_response_code"] = vresult.get("http_response_code")
                    if vstatus == "Exploitable":
                        verified_cves.append(cve_item)
                    else:
                        unverified_cves.append(cve_item)
                except Exception:
                    unverified_cves.append(cve_item)

    return {
        "technology":           tech_name,
        "version":              version,
        "category":             tech.get("category", "Unknown"),
        "vulnerability_status": vuln_status["status"],
        "confidence":           vuln_status["confidence"],
        "max_cvss":             max((c.get("cvss", 0) for c in filtered_cves), default=0.0),
        "verified_vulnerabilities":   verified_cves,
        "unverified_vulnerabilities": unverified_cves,
        "cves":     filtered_cves,
        "all_cves": filtered_cves,
        "source":   tech.get("source", ""),
        "metadata": {"port": tech.get("port"), "raw_data": tech.get("raw_data", {})},
    }


def run_technology_fingerprinting(urls_data):
    """
    Model 3: Technology Fingerprinting & Vulnerability Detection.

    Performance model:
    - All technologies within a URL are processed IN PARALLEL (CVE lookup + validation).
    - Multiple URLs are also processed concurrently.
    - CVE results are cached process-wide to avoid duplicate NVD API calls.
    """
    results = []
    load_artifacts()

    def _process_url(url_info: dict) -> dict:
        url          = url_info.get("url")
        is_root      = url_info.get("is_root", False)
        nmap_data    = url_info.get("nmap_data")
        whatweb_res  = url_info.get("whatweb_result")

        if not url:
            return None

        technologies = fingerprint_technologies(url, nmap_data, whatweb_res)

        if not technologies:
            return {
                "url": url, "is_root": is_root,
                "technologies": [], "vulnerable_count": 0, "safe_count": 0,
            }

        # Run all technologies for this URL in parallel
        tech_results = []
        with ThreadPoolExecutor(max_workers=min(len(technologies), 5)) as tex:
            futures = [tex.submit(_process_single_technology, tech, url)
                       for tech in technologies]
            for f in futures:
                try:
                    tech_results.append(f.result(timeout=30))
                except Exception as exc:
                    logger.warning(f"[Model3] Tech processing error on {url}: {exc}")

        return {
            "url":             url,
            "is_root":         is_root,
            "technologies":    tech_results,
            "vulnerable_count": sum(1 for t in tech_results if t["vulnerability_status"] in ("vulnerable", "potential")),
            "safe_count":       sum(1 for t in tech_results if t["vulnerability_status"] == "safe"),
        }

    # Process all URLs concurrently (each URL itself runs its techs in parallel)
    with ThreadPoolExecutor(max_workers=min(len(urls_data), 3)) as url_exec:
        url_futures = [url_exec.submit(_process_url, ui) for ui in urls_data]
        for uf in url_futures:
            try:
                r = uf.result(timeout=60)
                if r:
                    results.append(r)
            except Exception as exc:
                logger.warning(f"[Model3] URL processing error: {exc}")
    
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
    Enhanced Model 3 entry point.

    IMPORTANT — execution model:
      Step 1 (fingerprinting) runs SYNCHRONOUSLY and its results are returned
      immediately so Models 4-6 are never blocked.

      Step 2 (crawling) runs in a BACKGROUND DAEMON THREAD.  It writes its
      enriched data to MongoDB (crawled_endpoints_collection) after the main
      scan has already saved and the user can already see results.  The next
      time the report is fetched, crawling data will be there.

    This prevents the scan_controller 300-second FutureTimeoutError that was
    causing tech_results to return [] and silencing Models 5 and 6.
    """
    import logging as _logging
    import threading
    _log = _logging.getLogger(__name__)

    # ── Step 1: Fingerprinting — runs synchronously, must finish fast ────
    existing_results = run_technology_fingerprinting_for_subdomains(subdomains_data)

    # Tag every result with an empty crawling block immediately so callers
    # always have the key in the result dict (avoids KeyError in pipeline).
    for r in existing_results:
        r.setdefault("crawling", _empty_crawling_block())

    # ── Step 2: Crawling — fires in background, does NOT block caller ────
    def _run_crawling_background():
        try:
            from models.crawling.pipeline import CrawlingPipeline
            pipeline = CrawlingPipeline()
            crawling_results = pipeline.run_for_subdomains(subdomains_data)
            _merge_crawling_into_results(existing_results, crawling_results)
            _log.info(f"[Model3] Background crawling complete for {len(subdomains_data)} targets")
        except Exception as exc:
            _log.error(f"[Model3] Background crawling error (non-fatal): {exc}")

    t = threading.Thread(target=_run_crawling_background, daemon=True)
    t.start()

    # Return fingerprinting results immediately — crawling enriches in background
    return existing_results


def _merge_crawling_into_results(existing_results: list, crawling_results: list) -> None:
    """Merge crawling pipeline output into existing_results in-place."""
    crawling_by_url = {r["url"]: r for r in (crawling_results or [])}

    for tech_result in existing_results:
        url = tech_result.get("url", "")
        crawl_data = crawling_by_url.get(url, {})
        if not crawl_data:
            continue

        tech_result["crawling"] = {
            "crawl_source":             crawl_data.get("crawl_result", {}).get("source"),
            "endpoints":                crawl_data.get("endpoint_collection", {}).get("endpoints", []),
            "endpoint_summary":         {
                k: crawl_data.get("endpoint_collection", {}).get(k, 0)
                for k in ("total", "with_params", "api_count", "high_value_count")
            },
            "parameter_inventory":      crawl_data.get("endpoint_collection", {}).get("parameter_inventory", {}),
            "js_analysis":              crawl_data.get("js_analysis", {}),
            "nuclei_extended_findings": crawl_data.get("validated_findings", []),
            "pipeline_summary":         crawl_data.get("summary", {}),
        }

        # Inject confirmed crawling findings into the CVE list
        for finding in crawl_data.get("validated_findings", []):
            if not finding.get("is_confirmed"):
                continue
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
                    "Exploitable" if finding.get("confidence_level") == "HIGH" else "Unverified"
                ),
                "source": "crawling_nuclei",
                "matched_at": finding.get("matched_at", ""),
            }
            techs = tech_result.get("technologies", [])
            if techs:
                existing_ids = {c.get("cve") for c in techs[0].get("cves", [])}
                if synthetic_cve["cve"] not in existing_ids:
                    techs[0].setdefault("cves", []).append(synthetic_cve)


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
