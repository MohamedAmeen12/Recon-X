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

# Global variables for model artifacts
MODEL_DIR = os.path.join("models", "artifacts", "model3")
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


def lookup_cve(tech_name, version=""):
    """
    Lookup CVE information using NVD API.
    """
    cves = []
    try:
        from utils.nvd_api_tool import get_nvd_client
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
        
        client = get_nvd_client()
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(client.lookup_technology_vulnerabilities, tech_name, version)
        
        try:
            df = future.result(timeout=5)
            if df is not None and not df.empty:
                for _, row in df.head(10).iterrows():
                    cves.append({
                        "cve": row["cve_id"],
                        "cvss": float(row["cvss_score"]),
                        "description": row["description"][:200],
                        "severity": row["severity"],
                        "published_date": row["published_date"]
                    })
        except FutureTimeoutError:
            pass # Timeout silent fail
        except Exception:
            pass # API silent fail
            
    except Exception as e:
        # Fallback to empty context if NVD tool fails drastically
        print(f"[Model 3] NVD lookup error: {e}")
    
    return cves


def classify_vulnerability_status(tech_name, version, cves):
    """
    Classify vulnerability status using SUPERVISED ML model.
    """
    # 1. Calculate features from CVEs
    max_cvss = max([c.get("cvss", 0) for c in cves]) if cves else 0.0
    cve_count = len(cves)
    has_version = 1 if version else 0
    
    # 2. Load Models
    model, tfidf = load_artifacts()
    
    # Default fallback if models missing
    if model is None or tfidf is None:
        return {
            "status": "unknown",
            "confidence": 0.0,
            "reason": "Model artifacts not loaded",
            "max_cvss": max_cvss
        }
    
    # 3. Create Feature Vector
    try:
        # Text features
        fingerprint = create_technology_fingerprint(tech_name, version)
        X_text = tfidf.transform([fingerprint])
        
        # Numeric features [max_cvss, cve_count, has_version]
        X_numeric = np.array([[max_cvss, cve_count, has_version]])
        
        # Combine
        X = hstack([X_text, X_numeric])
        
        # 4. Predict
        prediction = model.predict(X)[0] # 0 or 1
        probability = model.predict_proba(X)[0][1] # Probability of class 1 (Vulnerable)
        
        status = "vulnerable" if prediction == 1 else "safe"
        confidence = float(probability) if prediction == 1 else float(1 - probability)
        
        return {
            "status": status,
            "confidence": confidence,
            "max_cvss": max_cvss,
            "cve_count": cve_count,
            "ml_prediction": int(prediction)
        }
        
    except Exception as e:
        print(f"[Model 3] Inference error: {e}")
        return {
            "status": "unknown",
            "confidence": 0.0,
            "error": str(e)
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
            
            # Step 2b: ML Classification
            vuln_status = classify_vulnerability_status(tech_name, version, cves)
            
            tech_result = {
                "technology": tech_name,
                "version": version,
                "category": tech.get("category", "Unknown"),
                "cves": cves if vuln_status["status"] == "vulnerable" else [], # Attach only if vulnerable
                "vulnerability_status": vuln_status["status"],
                "confidence": vuln_status["confidence"],
                "max_cvss": vuln_status.get("max_cvss", 0.0),
                "metadata": {
                    "port": tech.get("port"),
                    "raw_data": tech.get("raw_data", {})
                }
            }
            
            tech_results.append(tech_result)
        
        results.append({
            "url": url,
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
            "nmap_data": sub_data.get("nmap_data"),
            "whatweb_result": None
        })
    
    return run_technology_fingerprinting(urls_data)

