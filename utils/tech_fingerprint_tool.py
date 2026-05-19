"""
Technology fingerprinting from HTTP headers, httpx, banners, and nmap output.
httpx is the primary active fingerprinting engine when installed.
"""
import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional

import requests

_HTTPX_BIN = os.path.expanduser(r"~\go\bin\httpx.exe")

# Alternative locations for the Go httpx binary
_HTTPX_CANDIDATES = [
    _HTTPX_BIN,
    r"C:\Tools\httpx.exe",
    r"C:\go\bin\httpx.exe",
]


def _find_go_httpx() -> Optional[str]:
    """
    Locate the projectdiscovery Go httpx binary.
    Explicitly avoids the Python httpx CLI which has a different interface.
    """
    for path in _HTTPX_CANDIDATES:
        if os.path.exists(path):
            return path
    # Only accept a PATH entry if it looks like the Go tool (has -tech-detect flag)
    candidate = shutil.which("httpx")
    if candidate:
        try:
            test = subprocess.run(
                [candidate, "-h"], capture_output=True, text=True, timeout=3
            )
            if "tech-detect" in test.stdout or "tech-detect" in test.stderr:
                return candidate
        except Exception:
            pass
    return None


def run_httpx(url: str, timeout: int = 30) -> Dict:
    """
    Run the projectdiscovery Go httpx tool against *url* for technology detection.
    Returns parsed JSON dict or {} if the Go httpx binary is not installed.
    """
    bin_ = _find_go_httpx()
    if not bin_:
        return {}
    try:
        result = subprocess.run(
            [
                bin_, "-u", url,
                "-json", "-silent",
                "-tech-detect",
                "-status-code",
                "-title",
                "-web-server",
                "-no-color",
                "-timeout", "10",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        pass
    return {}


def extract_technologies_from_httpx(httpx_data: Dict) -> List[Dict]:
    """
    Parse httpx JSON output and return a list of technology dicts compatible
    with the existing fingerprint_technologies() format.
    """
    if not httpx_data:
        return []

    technologies = []

    # Web server (e.g. "Apache/2.4.51")
    web_server = httpx_data.get("webserver", "") or httpx_data.get("web-server", "")
    if web_server:
        parts = web_server.split("/", 1)
        technologies.append({
            "name": parts[0].strip(),
            "version": parts[1].strip() if len(parts) > 1 else "",
            "category": "Web Server",
            "source": "httpx",
        })

    # Technologies detected by httpx (list of "Name:Version" or plain "Name")
    for tech in httpx_data.get("tech", []) or httpx_data.get("technologies", []):
        if ":" in tech:
            name, version = tech.split(":", 1)
        else:
            name, version = tech, ""
        technologies.append({
            "name": name.strip(),
            "version": version.strip(),
            "category": "Technology",
            "source": "httpx",
        })

    return technologies

def extract_http_headers(url):
    """Extract HTTP headers from a URL."""
    headers_info = {}
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers_info = {
            "server": response.headers.get("Server", ""),
            "x-powered-by": response.headers.get("X-Powered-By", ""),
            "x-aspnet-version": response.headers.get("X-AspNet-Version", ""),
            "x-php-version": response.headers.get("X-PHP-Version", ""),
            "x-runtime": response.headers.get("X-Runtime", ""),
            "x-framework": response.headers.get("X-Framework", ""),
            "content-type": response.headers.get("Content-Type", ""),
            "all_headers": dict(response.headers)
        }
    except Exception:
        pass
    return headers_info


def extract_technologies_from_headers(headers_info):
    """Extract technology information from HTTP headers."""
    technologies = []
    
    # Server header
    server = headers_info.get("server", "")
    if server:
        # Parse "Apache/2.4.41" or "nginx/1.18.0"
        match = re.match(r'([^/]+)(?:/(.+))?', server)
        if match:
            name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else ""
            technologies.append({
                "name": name,
                "version": version,
                "category": "Web Server",
                "source": "Inferred via application-layer response"
            })
    
    # X-Powered-By header
    powered_by = headers_info.get("x-powered-by", "")
    if powered_by:
        match = re.match(r'([^/]+)(?:/(.+))?', powered_by)
        if match:
            name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else ""
            technologies.append({
                "name": name,
                "version": version,
                "category": "Framework",
                "source": "Inferred via application-layer response"
            })
    
    # X-PHP-Version
    php_version = headers_info.get("x-php-version", "")
    if php_version:
        technologies.append({
            "name": "PHP",
            "version": php_version.strip(),
            "category": "Language",
            "source": "Inferred via application-layer response"
        })
    
    # X-AspNet-Version
    aspnet = headers_info.get("x-aspnet-version", "")
    if aspnet:
        technologies.append({
            "name": "ASP.NET",
            "version": aspnet.strip(),
            "category": "Framework",
            "source": "Inferred via application-layer response"
        })
    
    return technologies


def extract_technologies_from_nmap(nmap_data):
    """
    Extract technology information from nmap service detection.
    nmap_data should be from nmap PortScanner output.
    """
    technologies = []
    
    if not nmap_data:
        return technologies
    
    # nmap structure: nm[ip][proto][port]
    for ip in nmap_data.get("all_hosts", []):
        for proto in nmap_data[ip].get("all_protocols", []):
            ports = nmap_data[ip][proto]
            for port, port_data in ports.items():
                if port_data.get("state") == "open":
                    # Service name
                    service = port_data.get("name", "")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    
                    if product:
                        technologies.append({
                            "name": product,
                            "version": version,
                            "category": "Service",
                            "source": f"nmap-{port}",
                            "port": int(port)
                        })
                    elif service and service not in ["http", "https", "tcp", "udp"]:
                        technologies.append({
                            "name": service,
                            "version": "",
                            "category": "Service",
                            "source": f"nmap-{port}",
                            "port": int(port)
                        })
    
    return technologies


def fingerprint_technologies(url, nmap_data=None, whatweb_result=None):
    """
    Comprehensive technology fingerprinting from multiple sources.
    Priority: httpx (primary) → HTTP headers → WhatWeb → nmap banners.
    Returns combined, deduplicated technology list.
    """
    all_technologies = []

    # ── Primary: httpx (richest detection when installed) ─────────────────
    httpx_data = run_httpx(url)
    if httpx_data:
        all_technologies.extend(extract_technologies_from_httpx(httpx_data))

    # ── HTTP headers (always available, no binary needed) ─────────────────
    headers = extract_http_headers(url)
    header_techs = extract_technologies_from_headers(headers)
    all_technologies.extend(header_techs)

    # ── WhatWeb (if result pre-supplied by caller) ─────────────────────────
    if whatweb_result:
        from utils.whatweb_tool import extract_technologies_from_whatweb
        whatweb_techs = extract_technologies_from_whatweb(whatweb_result)
        all_technologies.extend(whatweb_techs)

    # ── nmap banners (if supplied by caller) ──────────────────────────────
    if nmap_data:
        nmap_techs = extract_technologies_from_nmap(nmap_data)
        all_technologies.extend(nmap_techs)
    
    # Remove duplicates (same name and version)
    seen = set()
    unique_techs = []
    for tech in all_technologies:
        key = (tech["name"].lower(), tech.get("version", "").lower())
        if key not in seen:
            seen.add(key)
            unique_techs.append(tech)
    
    return unique_techs

