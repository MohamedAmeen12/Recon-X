from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
import numpy as np
import socket
import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tools.sublist3r_tool import run_sublist3r, get_sublist3r_result
from model.model2 import scan_ports_parallel


def _resolve_single_subdomain(subdomain):
    """Resolve a single subdomain to IP address."""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except socket.gaierror:
        return (subdomain, None)

def resolve_subdomains(subdomains, max_workers=50):
    """Resolve subdomains to IP addresses in parallel."""
    resolved = {}
    if not subdomains:
        return resolved
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve_single_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            subdomain, ip = future.result()
            if ip:
                resolved[subdomain] = ip
    return resolved

def _check_single_http(subdomain):
    """Check if a single subdomain has live HTTP service."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        if response.status_code < 400:
            return subdomain
    except requests.RequestException:
        pass
    return None

def check_live_http(subdomains, max_workers=50):
    """Check which subdomains have live HTTP services in parallel."""
    live = []
    if not subdomains:
        return live
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_http, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                live.append(result)
    return live


def extract_features(subdomain, resolved_ip=None, ports=None, live_http=False):
    """Extract features from subdomain for ML models."""
    parts = subdomain.split('.')
    features = [
        len(subdomain),                    # Length of subdomain
        len(parts),                        # Number of parts
        len(parts[0]) if parts else 0,     # Length of first part
        subdomain.count('-'),              # Number of hyphens
        subdomain.count('_'),              # Number of underscores
        1 if resolved_ip else 0,          # Resolvable
        1 if live_http else 0,             # Live HTTP
        len(ports) if ports else 0,        # Number of open ports
    ]
    return features

def classify_subdomains_supervised(subdomains, resolved, ports_results, live_http_list):
    """
    Use Random Forest and SVM (supervised learning) to classify subdomains.
    This is a supervised approach that learns from features.
    """
    if not subdomains or len(subdomains) < 2:
        return {}
    
    try:
        # Extract features for each subdomain
        X = []
        y = []  # Labels: 1 = suspicious/interesting, 0 = normal
        
        for sub in subdomains:
            features = extract_features(
                sub,
                resolved.get(sub),
                ports_results.get(sub, []),
                sub in live_http_list
            )
            X.append(features)
            
            # Create labels based on heuristics (suspicious patterns)
            # This simulates supervised learning - in real scenario, you'd have labeled data
            is_suspicious = (
                len(sub) > 30 or  # Very long subdomain
                sub.count('-') > 3 or  # Many hyphens
                len(ports_results.get(sub, [])) > 5 or  # Many open ports
                (sub not in live_http_list and resolved.get(sub))  # Resolvable but not live
            )
            y.append(1 if is_suspicious else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # Check if we have both classes (at least one 0 and one 1)
        unique_labels = np.unique(y)
        if len(unique_labels) < 2:
            # If all labels are the same, return default values
            results = {}
            for sub in subdomains:
                results[sub] = {
                    "rf_prediction": int(y[0]) if len(y) > 0 else 0,
                    "rf_confidence": 0.5,
                    "svm_prediction": int(y[0]) if len(y) > 0 else 0,
                    "svm_confidence": 0.5,
                    "ensemble_confidence": 0.5,
                    "is_suspicious": bool(y[0]) if len(y) > 0 else False
                }
            return results
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Random Forest
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        rf_model.fit(X_scaled, y)
        rf_predictions = rf_model.predict(X_scaled)
        rf_proba = rf_model.predict_proba(X_scaled)[:, 1]  # Probability of being suspicious
        
        # Train SVM
        svm_model = SVC(kernel='rbf', probability=True, random_state=42)
        svm_model.fit(X_scaled, y)
        svm_predictions = svm_model.predict(X_scaled)
        svm_proba = svm_model.predict_proba(X_scaled)[:, 1]  # Probability of being suspicious
        
        # Combine predictions (ensemble approach)
        results = {}
        for i, sub in enumerate(subdomains):
            # Average probability from both models
            avg_proba = (rf_proba[i] + svm_proba[i]) / 2
            results[sub] = {
                "rf_prediction": int(rf_predictions[i]),
                "rf_confidence": float(rf_proba[i]),
                "svm_prediction": int(svm_predictions[i]),
                "svm_confidence": float(svm_proba[i]),
                "ensemble_confidence": float(avg_proba),
                "is_suspicious": avg_proba > 0.5
            }
        
        return results
    except Exception as e:
        # If ML fails, return empty dict (graceful degradation)
        print(f"Warning: ML classification failed: {e}")
        return {}

def cluster_subdomains(subdomains):
    """Cluster subdomains based on their structure (unsupervised learning with KMeans)."""
    if not subdomains:
        return []

    # Simple clustering based on subdomain length and number of dots
    features = []
    for sub in subdomains:
        parts = sub.split('.')
        features.append([len(sub), len(parts)])

    features = np.array(features)
    if len(features) < 2:
        return [{"cluster_id": 0, "size": len(subdomains), "examples": subdomains}]

    kmeans = KMeans(n_clusters=min(3, len(subdomains)), random_state=42)
    labels = kmeans.fit_predict(features)

    clusters = {}
    for i, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(subdomains[i])

    result = []
    for cluster_id, subs in clusters.items():
        result.append({
            "cluster_id": int(cluster_id),  # Convert numpy int32 to int
            "size": len(subs),
            "examples": subs[:5]  # Show up to 5 examples
        })

    return result


def _check_single_dead(subdomain):
    """Check if a single subdomain is dead or unreachable."""
    try:
        ip = socket.gethostbyname(subdomain)
    except socket.gaierror:
        return (subdomain, True)  # Unresolved → dead

    # Try HTTP and HTTPS
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 400:
                return (subdomain, False)  # Alive
        except:
            pass

    return (subdomain, True)  # No valid response → dead

def check_dead_subdomains(subdomains, max_workers=50):
    """Check which subdomains are dead in parallel."""
    dead_subdomains = []
    if not subdomains:
        return dead_subdomains
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_dead, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            subdomain, is_dead = future.result()
            if is_dead:
                dead_subdomains.append(subdomain)
    return dead_subdomains


def run_subdomain_discovery(domain):
    """Main orchestrator function for subdomain discovery with parallel processing."""
    start_time = time.time()

    # Step 1: Start sublist3r in background (non-blocking - returns immediately!)
    sublist3r_future = run_sublist3r(domain)
    
    # Get the result when ready (this will wait, but sublist3r is already running)
    sublist3r_result = get_sublist3r_result(sublist3r_future, timeout=300)
    
    if sublist3r_result.get("status") == "success":
        subdomains = sublist3r_result.get("subdomains", [])
    else:
        print(f"Sublist3r status: {sublist3r_result.get('status')}")
        if sublist3r_result.get("status") == "error":
            print(f"Error: {sublist3r_result.get('error')}")
        subdomains = []

    if not subdomains:
        return {
            "total_candidates": 0,
            "resolved": 0,
            "live_http": 0,
            "elapsed_seconds": time.time() - start_time,
            "clusters": [],
            "examples": [],
            "raw_docs": [],
            "ports_summary": {}
        }

    # Step 2-4: Run all checks in parallel for maximum efficiency!
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all parallel tasks
        resolve_future = executor.submit(resolve_subdomains, subdomains)
        live_http_future = executor.submit(check_live_http, subdomains)
        dead_future = executor.submit(check_dead_subdomains, subdomains)
        
        # Wait for all to complete
        resolved = resolve_future.result()
        live_http = live_http_future.result()
        dead_subdomains = dead_future.result()

    # Step 5: Scan ports in parallel for all resolved IPs
    ip_subdomain_pairs = [(sub, ip) for sub, ip in resolved.items()]
    ports_results = scan_ports_parallel(ip_subdomain_pairs)

    # Step 6: Supervised learning - Classify subdomains using Random Forest and SVM
    try:
        ml_classifications = classify_subdomains_supervised(
            subdomains, resolved, ports_results, live_http
        )
    except Exception as e:
        print(f"Warning: ML classification failed: {e}")
        ml_classifications = {}
    
    # Step 7: Cluster subdomains (unsupervised learning with KMeans)
    clusters = cluster_subdomains(subdomains)

    for cluster in clusters:
        cluster["examples"] = [s for s in cluster["examples"] if s not in dead_subdomains]
        cluster["size"] = len(cluster["examples"])
    # Add a cluster for dead / invalid subdomains
    clusters.append({
        "cluster_id": "dead",
        "size": len(dead_subdomains),
        "examples": dead_subdomains[:5]
    })

    elapsed = time.time() - start_time

    # Create raw docs for MongoDB storage
    raw_docs = []
    for sub in subdomains:
        ml_info = ml_classifications.get(sub, {})
        sub_ip = resolved.get(sub)
        # Get ports for this subdomain (ports are scanned per IP, stored per subdomain)
        sub_ports = ports_results.get(sub, [])
        
        doc = {
            "subdomain": sub,
            "open_ports": sub_ports,  # Ports scanned from this subdomain's IP
            "ip": sub_ip if sub_ip else "Unresolved",
            "live_http": sub in live_http,
            "cluster_id": None,  # Will be set based on clustering
            "status": "dead" if sub in dead_subdomains else "alive",
            # Supervised learning predictions
            "rf_prediction": ml_info.get("rf_prediction", 0),
            "rf_confidence": ml_info.get("rf_confidence", 0.0),
            "svm_prediction": ml_info.get("svm_prediction", 0),
            "svm_confidence": ml_info.get("svm_confidence", 0.0),
            "ensemble_confidence": ml_info.get("ensemble_confidence", 0.0),
            "is_suspicious": ml_info.get("is_suspicious", False)
        }
        raw_docs.append(doc)

    # Assign cluster IDs to raw docs
    for cluster in clusters:
        for example in cluster["examples"]:
            for doc in raw_docs:
                if doc["subdomain"] == example:
                    doc["cluster_id"] = cluster["cluster_id"]

    result = {
        "total_candidates": len(subdomains),
        "resolved": len(resolved),
        "live_http": len(live_http),
        "elapsed_seconds": elapsed,
        "clusters": clusters,
        "examples": subdomains[:10],  # Show first 10 examples
        "raw_docs": raw_docs,  # For MongoDB storage
        "ports_summary": ports_results,
        "ml_classifications": ml_classifications  # Supervised learning results
    }

    return result
