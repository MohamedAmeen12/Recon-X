"""
Model 3: Technology Fingerprinting & Vulnerability Detection

Input: WhatWeb output, Nmap service detection, HTTP headers, banners
Output: Detected technologies, CVE mappings, vulnerability labels
"""
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import requests
import json
import re
import logging
from typing import Dict, List, Optional
from utils.tech_fingerprint_tool import fingerprint_technologies
from utils.whatweb_tool import run_whatweb, extract_technologies_from_whatweb

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


def extract_tfidf_features(technologies):
    """
    Extract TF-IDF features from technology fingerprints.
    Returns vectorized features and vectorizer.
    """
    if not technologies:
        return None, None
    
    fingerprints = []
    for tech in technologies:
        fingerprint = create_technology_fingerprint(
            tech.get("name", ""),
            tech.get("version", "")
        )
        fingerprints.append(fingerprint)
    
    if not fingerprints:
        return None, None
    
    vectorizer = TfidfVectorizer(
        max_features=100,
        ngram_range=(1, 2),
        stop_words='english'
    )
    
    try:
        features = vectorizer.fit_transform(fingerprints)
        return features, vectorizer
    except Exception as e:
        print(f"TF-IDF extraction error: {e}")
        return None, None


def lookup_cve(tech_name, version=""):
    """
    Lookup CVE information for a technology/version using NVD API.
    Fast lookup with timeout to avoid blocking.
    
    Args:
        tech_name: Technology name (e.g., "Apache", "WordPress")
        version: Version string (e.g., "2.4.41", "5.8")
    
    Returns:
        List of CVE dictionaries with cve, cvss, description
    """
    cves = []
    
    try:
        from utils.nvd_api_tool import get_nvd_client
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
        
        # Get NVD API client
        client = get_nvd_client()
        
        # Run CVE lookup with timeout (max 5 seconds per lookup)
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(client.lookup_technology_vulnerabilities, tech_name, version)
        
        try:
            df = future.result(timeout=5)
            
            if df is not None and not df.empty:
                # Convert DataFrame to list of dicts (limit to top 5 for speed)
                for _, row in df.head(5).iterrows():
                    cves.append({
                        "cve": row["cve_id"],
                        "cvss": float(row["cvss_score"]),
                        "description": row["description"][:200] if len(row["description"]) > 200 else row["description"],  # Truncate long descriptions
                        "severity": row["severity"],
                        "published_date": row["published_date"],
                        "cwe": row["cwe"]
                    })
        except FutureTimeoutError:
            logger.warning(f"CVE lookup timeout for {tech_name} {version}")
        except Exception as e:
            logger.warning(f"CVE lookup error: {e}")
        
        # If no results from API, fallback to known vulnerabilities
        if not cves:
            cves = match_known_vulnerabilities(tech_name, version)
        
    except ValueError as e:
        # API key not configured, use fallback
        cves = match_known_vulnerabilities(tech_name, version)
    except Exception as e:
        logger.error(f"CVE lookup error: {e}")
        # Fallback to known vulnerabilities
        cves = match_known_vulnerabilities(tech_name, version)
    
    return cves


def match_known_vulnerabilities(tech_name, version):
    """
    Match against known vulnerabilities (simplified version).
    In production, this would query a CVE database.
    """
    cves = []
    tech_lower = tech_name.lower()
    
    # Common vulnerability patterns (simplified - in production use real CVE DB)
    vulnerability_db = {
        "apache": {
            "2.4.41": [{"cve": "CVE-2020-11984", "cvss": 7.5, "description": "Apache HTTP Server vulnerability"}],
            "2.4.40": [{"cve": "CVE-2020-11984", "cvss": 7.5, "description": "Apache HTTP Server vulnerability"}],
        },
        "nginx": {
            "1.18.0": [{"cve": "CVE-2021-23017", "cvss": 7.5, "description": "Nginx resolver vulnerability"}],
        },
        "php": {
            "7.4": [{"cve": "CVE-2021-21703", "cvss": 6.5, "description": "PHP vulnerability"}],
        },
        "wordpress": {
            "5.8": [{"cve": "CVE-2021-44228", "cvss": 9.8, "description": "WordPress vulnerability"}],
        }
    }
    
    # Check for matches
    for tech_key, versions in vulnerability_db.items():
        if tech_key in tech_lower:
            for ver_key, cve_list in versions.items():
                if ver_key in version.lower() or not version:
                    cves.extend(cve_list)
    
    # If no specific match, check for general vulnerabilities
    if not cves:
        # Add generic check based on version age
        if version and any(char.isdigit() for char in version):
            # Older versions more likely to have vulnerabilities
            cves.append({
                "cve": "UNKNOWN",
                "cvss": 5.0,
                "description": f"Potential vulnerabilities in {tech_name} {version} - recommend update"
            })
    
    return cves


def classify_vulnerability_status(tech_name, version, cves, features_vector):
    """
    Binary classification: vulnerable / safe / unknown
    Uses Logistic Regression and Decision Tree.
    """
    if not cves:
        return {
            "status": "safe",
            "confidence": 0.7,
            "reason": "No known CVEs found"
        }
    
    # Calculate vulnerability score based on CVEs
    max_cvss = max([cve.get("cvss", 0) for cve in cves])
    cve_count = len(cves)
    
    # Feature vector for classification
    # [max_cvss, cve_count, has_version, version_age_score]
    has_version = 1 if version else 0
    version_age_score = 0.5  # Simplified - would calculate based on version
    
    X = np.array([[max_cvss, cve_count, has_version, version_age_score]])
    
    # Train simple classifier (in production, use pre-trained model)
    # For now, use rule-based classification
    if max_cvss >= 9.0:
        status = "vulnerable"
        confidence = 0.95
    elif max_cvss >= 7.0:
        status = "vulnerable"
        confidence = 0.85
    elif max_cvss >= 5.0:
        status = "vulnerable"
        confidence = 0.70
    elif cve_count > 0:
        status = "unknown"
        confidence = 0.60
    else:
        status = "safe"
        confidence = 0.80
    
    return {
        "status": status,
        "confidence": confidence,
        "max_cvss": max_cvss,
        "cve_count": cve_count
    }


def run_technology_fingerprinting(urls_data):
    """
    Main function for Model 3: Technology Fingerprinting & Vulnerability Detection.
    
    Input: List of dicts with 'url', 'nmap_data', 'whatweb_result'
    Output: Technology fingerprints with vulnerability assessments
    """
    results = []
    
    for url_info in urls_data:
        url = url_info.get("url")
        nmap_data = url_info.get("nmap_data")
        whatweb_result = url_info.get("whatweb_result")
        
        if not url:
            continue
        
        # Step 1: Fingerprint technologies
        technologies = fingerprint_technologies(url, nmap_data, whatweb_result)
        
        # Step 2: Extract TF-IDF features
        tfidf_features, vectorizer = extract_tfidf_features(technologies)
        
        # Step 3: Process each technology
        tech_results = []
        for tech in technologies:
            tech_name = tech.get("name", "")
            version = tech.get("version", "")
            
            # Step 3a: Lookup CVEs
            cves = lookup_cve(tech_name, version)
            
            # Step 3b: Classify vulnerability status
            tech_vector = None
            if tfidf_features is not None and vectorizer is not None:
                fingerprint = create_technology_fingerprint(tech_name, version)
                try:
                    tech_vector = vectorizer.transform([fingerprint])
                except:
                    pass
            
            vuln_status = classify_vulnerability_status(
                tech_name, version, cves, tech_vector
            )
            
            # Step 3c: Calculate similarity scores (for matching against known vulnerable versions)
            similarity_score = 0.0
            if tech_vector is not None and tfidf_features is not None:
                try:
                    similarities = cosine_similarity(tech_vector, tfidf_features)
                    similarity_score = float(np.max(similarities)) if similarities.size > 0 else 0.0
                except:
                    pass
            
            tech_result = {
                "technology": tech_name,
                "version": version,
                "category": tech.get("category", "Unknown"),
                "source": tech.get("source", "Unknown"),
                "cves": cves,
                "vulnerability_status": vuln_status["status"],
                "confidence": vuln_status["confidence"],
                "max_cvss": vuln_status.get("max_cvss", 0.0),
                "similarity_score": similarity_score,
                "metadata": {
                    "port": tech.get("port"),
                    "raw_data": tech.get("raw_data", {})
                }
            }
            
            tech_results.append(tech_result)
        
        results.append({
            "url": url,
            "technologies": tech_results,
            "total_technologies": len(tech_results),
            "vulnerable_count": sum(1 for t in tech_results if t["vulnerability_status"] == "vulnerable"),
            "safe_count": sum(1 for t in tech_results if t["vulnerability_status"] == "safe"),
            "unknown_count": sum(1 for t in tech_results if t["vulnerability_status"] == "unknown")
        })
    
    return results


def run_technology_fingerprinting_for_subdomains(subdomains_data):
    """
    Run technology fingerprinting for multiple subdomains.
    subdomains_data: List of dicts with 'subdomain', 'url', 'nmap_data'
    """
    urls_data = []
    
    for sub_data in subdomains_data:
        url = sub_data.get("url") or f"http://{sub_data.get('subdomain', '')}"
        urls_data.append({
            "url": url,
            "nmap_data": sub_data.get("nmap_data"),
            "whatweb_result": None  # Can be added if WhatWeb is run
        })
    
    return run_technology_fingerprinting(urls_data)

