"""
Model 2: Port Scanning & Service Detection (Deterministic)

Scanning strategy (tiered — best available tool wins):
  1. masscan  — full 65535-port sweep at high speed (primary, requires admin)
  2. nmap     — service-version detection on masscan-found ports (or standalone fallback)
  3. socket   — concurrent TCP connect scan with banner grabbing (no binary dependency)

Service labelling:
  AI Port Service (RF model) classifies banners → service + version strings.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

# Guard nmap import — python-nmap may not be installed, or nmap binary may be absent.
# All nmap code paths degrade gracefully when the library is unavailable.
try:
    import nmap as _nmap_lib
    _NMAP_LIB_AVAILABLE = True
except ImportError:
    _nmap_lib = None
    _NMAP_LIB_AVAILABLE = False

from models.ai_port_service.model_inference import get_predict_service

# ---------------------------------------------------------------------------
# Port lists
# ---------------------------------------------------------------------------

DEFAULT_PORTS_TO_SCAN = [
    # Web / HTTP
    80, 443, 8080, 8081, 8443, 8000, 8008, 8888, 8181, 9000, 9443, 3000, 4000, 5000,
    # Remote access
    22, 23, 3389, 5900, 5901, 2222,
    # FTP
    21, 990, 2121,
    # Mail
    25, 110, 143, 465, 587, 993, 995,
    # DNS
    53,
    # Databases
    3306, 5432, 27017, 6379, 9200, 9300, 5984, 11211, 1521, 1433, 50000,
    # Directory / Auth
    389, 636, 88,
    # Infrastructure / Message queues
    2375, 2376, 5672, 15672, 9092, 2181, 2049, 111, 161,
    # Cloud / DevOps / Kubernetes
    8500, 5601, 9090, 9100, 6443, 10250, 2379, 4369,
    # SMB / Windows
    135, 139, 445,
    # Other high-value recon ports
    4444, 7001, 7443, 8161, 1883, 8883,
    # Additional common web alternates
    8082, 8083, 8084, 8085, 8086, 8090, 8091, 8443, 9001, 9002,
]

# Remove duplicates while preserving insertion order
_seen_ports: set = set()
_deduped: list = []
for _p in DEFAULT_PORTS_TO_SCAN:
    if _p not in _seen_ports:
        _seen_ports.add(_p)
        _deduped.append(_p)
DEFAULT_PORTS_TO_SCAN = _deduped
del _seen_ports, _deduped, _p

# Ports that require an HTTP probe before they send a banner
_HTTP_PORTS = frozenset({80, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8090,
                          8091, 8000, 8008, 8888, 8181, 9000, 9001, 9002, 3000, 4000, 5000})
_HTTPS_PORTS = frozenset({443, 8443, 9443})

# ---------------------------------------------------------------------------
# masscan support
# ---------------------------------------------------------------------------

_MASSCAN_PATHS = [
    os.path.abspath("masscan.exe"),
    r"C:\Program Files\masscan\masscan.exe",
]


def _find_masscan() -> Optional[str]:
    for p in _MASSCAN_PATHS:
        if os.path.exists(p):
            return p
    return shutil.which("masscan")


def run_masscan(ip: str, rate: int = 1000, timeout: int = 120) -> List[int]:
    """
    Run masscan over all 65535 ports on *ip* and return list of open port numbers.
    Requires admin/root privileges. Returns [] gracefully if masscan is unavailable.
    """
    bin_ = _find_masscan()
    if not bin_:
        return []

    output_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            output_file = fh.name

        subprocess.run(
            [bin_, ip, "-p1-65535", f"--rate={rate}", "-oJ", output_file],
            capture_output=True, text=True, timeout=timeout,
        )

        if not os.path.exists(output_file):
            return []

        with open(output_file, "r") as fh:
            raw = fh.read().strip()

        if not raw or raw == "[]":
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = json.loads(f"[{raw.strip().rstrip(',')}]")

        ports: List[int] = []
        for entry in data:
            for p in entry.get("ports", []):
                port_num = p.get("port")
                if port_num:
                    ports.append(int(port_num))

        print(f"[Model2] masscan found {len(ports)} open ports on {ip}")
        return ports

    except subprocess.TimeoutExpired:
        print(f"[Model2] masscan timed out on {ip}")
    except Exception as exc:
        print(f"[Model2] masscan error on {ip}: {exc}")
    finally:
        if output_file and os.path.exists(output_file):
            try:
                os.unlink(output_file)
            except Exception:
                pass
    return []


# ---------------------------------------------------------------------------
# nmap support (optional — degrades gracefully when binary is absent)
# ---------------------------------------------------------------------------

_NMAP_CANDIDATES = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Nmap\nmap.exe",
]


def _find_nmap() -> Optional[str]:
    """Return the nmap binary path, checking explicit Windows locations first."""
    for p in _NMAP_CANDIDATES:
        if os.path.exists(p):
            return p
    return shutil.which("nmap")


def _nmap_service_scan(ip: str, port_list: str) -> List[dict]:
    """Run nmap service-version detection on a specific port list."""
    if not _NMAP_LIB_AVAILABLE:
        return []
    nmap_bin = _find_nmap()
    open_ports = []
    try:
        nm = _nmap_lib.PortScanner(nmap_search_path=(nmap_bin,) if nmap_bin else ("nmap",))
        try:
            nm.scan(ip, port_list, arguments="-Pn -sS -sV -T4 --max-retries 1 --host-timeout 30s")
        except _nmap_lib.PortScannerError:
            nm.scan(ip, port_list, arguments="-Pn -sT -sV -T4 --max-retries 1 --host-timeout 30s")

        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port_num, port_data in nm[ip][proto].items():
                    if port_data["state"] == "open":
                        open_ports.append({
                            "port":      int(port_num),
                            "state":     "open",
                            "product":   port_data.get("product", ""),
                            "version":   port_data.get("version", ""),
                            "extrainfo": port_data.get("extrainfo", ""),
                            "protocol":  proto,
                        })
    except Exception as exc:
        print(f"[Model2] nmap service scan error on {ip}: {exc}")
    return open_ports


# ---------------------------------------------------------------------------
# Pure-Python concurrent socket scanner (Tier 3 — no binary dependency)
# ---------------------------------------------------------------------------

def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Grab up to 256 bytes from an open port and return clean UTF-8 text.

    Protocol handling:
    - HTTP ports  → send HEAD probe, then read
    - HTTPS ports → TLS wrap + HEAD probe; falls back to plain read on failure
    - All others  → connect and read immediately (server-speaks-first daemons)
    """
    try:
        if port in _HTTPS_PORTS:
            # Try TLS first
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
                tls_sock.settimeout(timeout)
                tls_sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                data = tls_sock.recv(256)
                tls_sock.close()
                return data.decode("utf-8", errors="replace").replace("\x00", "").strip()
            except Exception:
                raw_sock.close()
            # TLS failed — try plain read
            raw_sock2 = socket.create_connection((ip, port), timeout=timeout)
            raw_sock2.settimeout(timeout)
            data = raw_sock2.recv(256)
            raw_sock2.close()
            return data.decode("utf-8", errors="replace").replace("\x00", "").strip()

        elif port in _HTTP_PORTS:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = sock.recv(256)
            sock.close()
            return data.decode("utf-8", errors="replace").replace("\x00", "").strip()

        else:
            # Server-speaks-first: SSH, FTP, SMTP, POP3, IMAP, Redis, MySQL…
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            data = sock.recv(256)
            sock.close()
            return data.decode("utf-8", errors="replace").replace("\x00", "").strip()

    except Exception:
        return ""


def _scan_single_port(ip: str, port: int, connect_timeout: float) -> Optional[int]:
    """Return *port* if TCP connect succeeds, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connect_timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        sock.close()
    return None


def _build_port_records(ip: str, open_ports: List[int]) -> List[dict]:
    """
    Grab banners for *open_ports* in parallel, then assemble output dicts.

    The raw banner is split across product[:80] and extrainfo[80:256] so that
    scan_ports()'s reassembly (``f"{product} {version} {extrainfo}"``) passes
    the full 256-byte banner text into the AI Port Service's TF-IDF vectorizer.
    """
    if not open_ports:
        return []

    def _grab(port: int) -> tuple:
        return port, _grab_banner(ip, port, timeout=1.0)

    banner_map: Dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=min(50, len(open_ports))) as ex:
        for port, banner in ex.map(_grab, open_ports):
            banner_map[port] = banner

    records = []
    for port in open_ports:
        banner = banner_map.get(port, "")
        records.append({
            "port":      port,
            "state":     "open",
            "product":   banner[:80],
            "version":   "",
            "extrainfo": banner[80:256],
            "protocol":  "tcp",
        })
    return records


def _socket_scan_concurrent(
    ip: str,
    ports: List[int],
    connect_timeout: float = 0.5,
    max_workers: int = 100,
) -> List[dict]:
    """
    Fast concurrent TCP connect scan across *ports*.

    All connection attempts fire simultaneously via a thread pool so total
    wall time is bounded by one round-trip pass (~0.5 s) rather than the sum
    of all timeouts. Open ports get a follow-up banner grab in parallel.
    """
    open_port_numbers: List[int] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futures = {ex.submit(_scan_single_port, ip, p, connect_timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result is not None:
                    open_port_numbers.append(result)
            except Exception:
                pass

    if open_port_numbers:
        print(f"[Model2] Socket scan: {len(open_port_numbers)} open ports on {ip}")

    return _build_port_records(ip, open_port_numbers)


def _socket_scan(ip: str, ports: List[int]) -> List[dict]:
    """TCP connect scan — delegates to the concurrent implementation."""
    return _socket_scan_concurrent(ip, ports)


# ---------------------------------------------------------------------------
# Main scan_ports entry point
# ---------------------------------------------------------------------------

def scan_ports(ip, ports=DEFAULT_PORTS_TO_SCAN):
    """
    Tiered port scanning:
      1. masscan  — fast full-range sweep (finds open port numbers)
      2. nmap     — service/version detection on the ports masscan found
      3. socket   — concurrent TCP connect + banner grab (no binary needed)

    Returns list of dicts: [{port, state, product, version, extrainfo, protocol}]
    """
    open_ports = []

    # ── Tier 1: masscan ───────────────────────────────────────────────────
    if _find_masscan():
        masscan_ports = run_masscan(ip)
        if masscan_ports:
            port_list = ",".join(str(p) for p in sorted(set(masscan_ports)))
            nmap_results = _nmap_service_scan(ip, port_list)
            if nmap_results:
                open_ports = nmap_results
            else:
                open_ports = [
                    {"port": p, "state": "open", "product": "",
                     "version": "", "extrainfo": "", "protocol": "tcp"}
                    for p in masscan_ports
                ]
    else:
        # ── Tier 2: nmap standalone ───────────────────────────────────────
        port_list = ",".join(str(p) for p in ports)
        nmap_results = _nmap_service_scan(ip, port_list)
        if nmap_results:
            open_ports = nmap_results
        else:
            # ── Tier 3: concurrent socket scan with banner grabbing ────────
            print(f"[Model2] No masscan/nmap — using concurrent socket scan on {ip}")
            open_ports = _socket_scan(ip, ports)

    # ── AI Port Service Classification ────────────────────────────────────
    final_results = []
    if open_ports:
        fingerprints = []
        for p in open_ports:
            product  = p.get("product", "")
            version  = p.get("version", "")
            extrainfo = p.get("extrainfo", "")
            banner   = f"{product} {version} {extrainfo}".strip()
            fingerprints.append({
                "port":     p["port"],
                "protocol": p.get("protocol", "tcp"),
                "state":    p.get("state", "open"),
                "banner":   banner,
            })

        try:
            predictions = get_predict_service(fingerprints, model_type="rf")
            for i, p in enumerate(open_ports):
                if i < len(predictions):
                    ai_pred = predictions[i]
                    final_results.append({
                        "port":       p["port"],
                        "service":    ai_pred.get("service", "Unknown"),
                        "version":    ai_pred.get("version", ""),
                        "confidence": ai_pred.get("confidence", 0.0),
                    })
        except Exception as exc:
            print(f"[Model2] AI Port Classification failed: {exc} — returning raw ports")
            return [
                {"port": p["port"], "service": "", "version": "", "confidence": 0.0}
                for p in open_ports
            ]

    return final_results


# ---------------------------------------------------------------------------
# Parallel multi-IP scanning
# ---------------------------------------------------------------------------

def scan_ports_parallel(ip_subdomain_pairs, max_workers=20):
    """
    Scan ports for multiple IPs in parallel.

    Args:
        ip_subdomain_pairs: List of tuples (subdomain, ip)
        max_workers: Maximum number of parallel workers

    Returns:
        {subdomain: [{"port": int, "service": str, "version": str, "confidence": float}]}
    """
    ports_results = {}

    def _scan_single_ip(item):
        subdomain, ip = item
        return subdomain, scan_ports(ip)

    if not ip_subdomain_pairs:
        return ports_results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_single_ip, item): item for item in ip_subdomain_pairs}
        for future in as_completed(futures):
            subdomain, _ = futures[future]
            try:
                subdomain, open_ports = future.result()
                ports_results[subdomain] = open_ports
            except Exception as exc:
                print(f"[Model2] Port scan failed for {subdomain}: {exc}")
                ports_results[subdomain] = []

    return ports_results


def analyze_port_security(ports_results):
    """Analyze port scan results for security implications."""
    security_analysis = {
        "high_risk_ports":   [],
        "common_services":   [],
        "total_open_ports":  0,
        "unique_services":   set(),
        "vulnerable_services": [],
    }

    HIGH_RISK_PORTS = {
        21: "FTP (often unencrypted)",
        23: "Telnet (unencrypted)",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
    }

    for subdomain, ports in ports_results.items():
        for port_info in ports:
            port_num = port_info.get("port")
            service  = port_info.get("service", "")
            security_analysis["total_open_ports"] += 1
            security_analysis["unique_services"].add(service)
            if port_num in HIGH_RISK_PORTS:
                security_analysis["high_risk_ports"].append({
                    "subdomain": subdomain,
                    "port":      port_num,
                    "service":   service,
                    "risk":      HIGH_RISK_PORTS[port_num],
                })
            if port_num in {80, 443, 8080, 8443}:
                security_analysis["common_services"].append({
                    "subdomain": subdomain,
                    "port":      port_num,
                    "service":   service,
                })

    security_analysis["unique_services"] = list(security_analysis["unique_services"])
    return security_analysis


def run_port_scanning(ip_subdomain_pairs, max_workers=20):
    """Main orchestrator function for Model 2."""
    start_time = time.time()

    if not ip_subdomain_pairs:
        return {
            "ports_results":    {},
            "security_analysis": {
                "high_risk_ports": [], "common_services": [],
                "total_open_ports": 0, "unique_services": [],
                "vulnerable_services": [],
            },
            "total_scanned":    0,
            "total_open_ports": 0,
            "elapsed_seconds":  0.0,
        }

    print(f"[Model2] Scanning ports for {len(ip_subdomain_pairs)} IPs...")
    ports_results    = scan_ports_parallel(ip_subdomain_pairs, max_workers=max_workers)
    security_analysis = analyze_port_security(ports_results)
    total_open_ports  = sum(len(ports) for ports in ports_results.values())
    elapsed           = time.time() - start_time

    print(f"[Model2] Completed in {elapsed:.2f}s — {total_open_ports} open ports found")
    return {
        "ports_results":    ports_results,
        "security_analysis": security_analysis,
        "total_scanned":    len(ip_subdomain_pairs),
        "total_open_ports": total_open_ports,
        "elapsed_seconds":  elapsed,
    }
