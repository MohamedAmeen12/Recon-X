import os
import uuid
from urllib.parse import urlparse
from typing import List, Dict, Optional

def generate_burp_export(vulnerabilities: List[Dict], target: str) -> Optional[str]:
    """
    Generate Burp Suite replayable HTTP requests from authentic web exploit findings.
    Does NOT synthesize fake request contexts. Only includes findings of type 'web_exploit'
    that contain authentic captured request headers.
    Saves the file to reports/burp_requests_<scan_id>.txt and returns the filename.
    If no authentic HTTP findings exist, returns None.
    """
    if not vulnerabilities:
        return None

    web_exploits = []
    for vuln in vulnerabilities:
        if vuln.get("finding_type") != "web_exploit":
            continue
            
        headers = vuln.get("request_headers") or vuln.get("headers")
        # ONLY export if authentic captured headers are present
        if not headers or len(headers) == 0:
            continue
            
        web_exploits.append(vuln)

    if not web_exploits:
        return None

    # Generate HTTP/1.1 request contents
    requests_generated = []
    seen_requests = set()

    for vuln in web_exploits:
        url = vuln.get("url")
        host = vuln.get("host") or vuln.get("subdomain")
        endpoint = vuln.get("endpoint") or "/"
        
        if url:
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
                if not path:
                    path = "/"
            except Exception:
                netloc = host or target
                path = endpoint
        else:
            netloc = host
            path = endpoint

        method = str(vuln.get("http_method") or vuln.get("method") or "GET").upper()
        headers = vuln.get("request_headers") or vuln.get("headers") or {}
        body = vuln.get("request_body") or vuln.get("body") or ""

        # Format headers as lines
        header_lines = []
        if isinstance(headers, dict):
            # Ensure Host header is first for standards
            if "Host" in headers:
                header_lines.append(f"Host: {headers['Host']}")
            elif "host" in headers:
                header_lines.append(f"Host: {headers['host']}")
            else:
                header_lines.append(f"Host: {netloc}")

            for k, v in headers.items():
                if k.lower() != "host":
                    header_lines.append(f"{k}: {v}")
        elif isinstance(headers, list):
            header_lines = [str(h) for h in headers]
        elif isinstance(headers, str):
            header_lines = [h.strip() for h in headers.split("\n") if h.strip()]

        headers_str = "\r\n".join(header_lines)

        # Build raw HTTP request string
        raw_request = f"{method} {path} HTTP/1.1\r\n{headers_str}\r\n\r\n"
        if body:
            raw_request += str(body)

        # Deduplicate identical request strings
        request_sig = raw_request.strip()
        if request_sig in seen_requests:
            continue
        seen_requests.add(request_sig)
        
        requests_generated.append(raw_request)

    if not requests_generated:
        return None

    # Join requests with custom separators
    separator = "\n========================================\n"
    content = separator.join(requests_generated)

    # Extract scan_id or generate one
    scan_id = None
    for vuln in vulnerabilities:
        if vuln.get("scan_id"):
            scan_id = str(vuln.get("scan_id"))
            break
        if vuln.get("report_id"):
            scan_id = str(vuln.get("report_id"))
            break

    if not scan_id:
        scan_id = uuid.uuid4().hex[:8]

    # Save to reports directory
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = f"burp_requests_{scan_id}.txt"
    filepath = os.path.join(reports_dir, filename)

    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    return filename
