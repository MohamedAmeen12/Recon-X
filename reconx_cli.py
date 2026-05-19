# [ignoring loop detection]
import argparse
import requests
import sys
import json
import time

def scan_target(target, server_url):
    print("==================================================")
    print(f"[*] Starting ReconX CLI Scan against: {target}")
    print(f"[*] Target Server API: {server_url}")
    print("==================================================")
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CLI-Bypass": "reconx_cli_mode"
    }
    
    payload = {
        "domain": target,
        "include_tech_scan": True
    }
    
    scan_endpoint = f"{server_url.rstrip('/')}/scan_domain"
    
    start_time = time.time()
    try:
        response = requests.post(scan_endpoint, json=payload, headers=headers, timeout=600)
    except requests.exceptions.ConnectionError:
        print("[!] Error: Could not connect to the ReconX server.")
        print(f"    Please ensure Flask application is running at {server_url}.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)
        
    duration = time.time() - start_time
    
    if response.status_code != 200:
        print(f"[!] Scan failed with status code {response.status_code}")
        try:
            err_data = response.json()
            print(f"    Reason: {err_data.get('error', 'Unknown error')}")
        except:
            print(f"    Raw Response: {response.text}")
        sys.exit(1)
        
    try:
        data = response.json()
    except Exception as e:
        print(f"[!] Failed to parse response JSON: {e}")
        sys.exit(1)
        
    report = data.get("report", {})
    print("\n[+] Scan successfully completed in {:.2f} seconds!".format(duration))
    print(f"[+] Report ID: {data.get('report_id')}")
    print("\n================== SCAN DETAILS ==================")
    print(f"Target Apex: {report.get('domain')}")
    print(f"Total Candidates: {report.get('total_candidates', 0)}")
    print(f"Resolved Hosts: {report.get('resolved', 0)}")
    print(f"Live HTTP hosts: {report.get('live_http', 0)}")
    
    raw_docs = report.get("raw_docs", [])
    if raw_docs:
        print("\n--- HOST DISCOVERY & PORTS ---")
        for doc in raw_docs:
            sub = doc.get("subdomain")
            ip = doc.get("ip")
            ports = [str(p.get("port")) for p in doc.get("open_ports", [])]
            ports_str = ", ".join(ports) if ports else "No open ports"
            print(f" - {sub} ({ip}) [Ports: {ports_str}]")
            
    anomalies = report.get("http_anomalies", [])
    if anomalies:
        print("\n--- MODEL 4: HTTP ANOMALY DETECTION ---")
        for anom in anomalies:
            sub = anom.get("subdomain")
            res = anom.get("model4_result", {})
            status = res.get("status", "normal")
            score = res.get("anomaly_score", 0.0)
            if status == "suspicious":
                print(f" [!] {sub} - SUSPICIOUS (Score: {score:.2f})")
            else:
                print(f" [*] {sub} - Normal (Score: {score:.2f})")
                
    m6_results = report.get("model6", [])
    if m6_results:
        print("\n--- MODEL 6: VULNERABILITY SCORES ---")
        for vul in m6_results:
            cve = vul.get("cve_id")
            service = vul.get("service_name")
            cvss = vul.get("cvss_score", 0.0)
            status = vul.get("validation_status", "Unverified")
            print(f" - {cve} in {service} | CVSS: {cvss} | Status: {status}")
            
    m5_results = report.get("model5", {})
    if m5_results and m5_results.get("remediation_steps"):
        print("\n--- MODEL 5: REMEDIATION STRATEGY ---")
        for step in m5_results.get("remediation_steps", []):
            print(f" Step {step.get('step', '?')}: {step.get('action')}")
            print(f"   Priority: {step.get('priority')} | CVEs: {', '.join(step.get('associated_cves', []))}")
            
    print("==================================================")

def main():
    parser = argparse.ArgumentParser(description="ReconX Command Line Scanner")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("target", help="Target domain or IP address to scan")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="ReconX backend URL")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        scan_target(args.target, args.server)

if __name__ == "__main__":
    main()
