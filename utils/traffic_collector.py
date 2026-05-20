"""
ReconX - Traffic Feature Collector
Primary engine : tcpdump (built from https://github.com/the-tcpdump-group/tcpdump)
Fallback engine: Scapy

Capture flow
────────────
1. Resolve target hostname → IP address (BPF filter target)
2. Auto-detect the active network interface (NPF device matching local outbound IP)
3. Run tcpdump as a subprocess:
       tcpdump -i <iface> -w <tmp.pcap> -n -s 96 -c 1000 host <ip>
   The process is killed after *duration* seconds via communicate(timeout).
4. Parse the resulting pcap file with a pure-Python struct reader — no
   extra libraries needed for the read step.
5. Return the five numeric features consumed by Model 4 (Isolation Forest):
       packet_count, avg_packet_size, tcp_syn_count, udp_count, unique_ips

Windows notes
─────────────
• tcpdump.exe lives in the project root alongside pcap.dll / Packet.dll / wpcap.dll.
• Interface names on Windows look like \\Device\\NPF_{GUID}.
  We discover the correct one via Scapy's get_if_addr() which maps each
  NPF device to its assigned IP — the same mechanism used by traffic_collector
  before this rewrite.
• The -G/-W rotation flags behave differently on Windows, so we use
  proc.communicate(timeout=duration) + proc.terminate() instead.
"""

import os
import shutil
import socket
import struct
import subprocess
import tempfile
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# tcpdump binary path resolution
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_TCPDUMP_CANDIDATES = [
    os.path.join(_PROJECT_ROOT, "tcpdump.exe"),          # project root (primary)
    r"C:\Users\DELL\tcpdump-build\Release\tcpdump.exe",  # build tree fallback
    r"C:\tools\tcpdump.exe",                             # manual install
]


def _find_tcpdump() -> Optional[str]:
    """Return path to tcpdump.exe, or None."""
    for p in _TCPDUMP_CANDIDATES:
        if os.path.exists(p):
            return p
    found = shutil.which("tcpdump")
    return found if found else None


# ---------------------------------------------------------------------------
# Scapy (fallback) availability check
# ---------------------------------------------------------------------------
try:
    from scapy.all import get_if_list, get_if_addr
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Interface auto-detection (shared by both engines)
# ---------------------------------------------------------------------------

def _get_local_outbound_ip() -> Optional[str]:
    """Return the local IP used for internet traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _detect_active_npf_interface() -> Optional[str]:
    """
    Return the NPF device name (e.g. \\Device\\NPF_{GUID}) whose assigned
    IP matches the local outbound IP.  Uses Scapy's get_if_addr() which
    already queries Npcap for this mapping.
    """
    if not _SCAPY_AVAILABLE:
        return None
    local_ip = _get_local_outbound_ip()
    if not local_ip:
        return None
    for iface in get_if_list():
        try:
            if get_if_addr(iface) == local_ip:
                return iface
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Minimal pcap file parser (pure Python — no external deps)
# ---------------------------------------------------------------------------
_PCAP_GLOBAL_HDR = 24   # bytes
_PCAP_RECORD_HDR = 16   # bytes per packet record


def _parse_pcap(path: str) -> Dict:
    """
    Walk a pcap file and extract traffic features.
    Returns the five-feature dict that Model 4 expects.
    """
    empty = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0,
    }
    if not os.path.exists(path) or os.path.getsize(path) <= _PCAP_GLOBAL_HDR:
        return empty

    sizes, syn_count, udp_count = [], 0, 0
    ips: set = set()

    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return empty
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            else:
                return empty
            f.read(20)  # skip rest of global header

            while True:
                rec = f.read(_PCAP_RECORD_HDR)
                if len(rec) < _PCAP_RECORD_HDR:
                    break
                _, _, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec)
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                sizes.append(orig_len)

                # Ethernet header is 14 bytes; check EtherType = IPv4 (0x0800)
                if len(raw) < 14:
                    continue
                if struct.unpack("!H", raw[12:14])[0] != 0x0800:
                    continue

                ip_start = 14
                if len(raw) < ip_start + 20:
                    continue

                ihl = (raw[ip_start] & 0x0F) * 4
                proto = raw[ip_start + 9]
                src_ip = socket.inet_ntoa(raw[ip_start + 12:ip_start + 16])
                dst_ip = socket.inet_ntoa(raw[ip_start + 16:ip_start + 20])
                ips.update([src_ip, dst_ip])

                tcp_start = ip_start + ihl
                if proto == 6 and len(raw) >= tcp_start + 14:   # TCP
                    if raw[tcp_start + 13] & 0x02:               # SYN flag
                        syn_count += 1
                elif proto == 17:                                 # UDP
                    udp_count += 1

    except Exception as exc:
        print(f"[TrafficCollector] pcap parse error: {exc}")

    count = len(sizes)
    return {
        "packet_count":    count,
        "avg_packet_size": sum(sizes) / count if count else 0.0,
        "tcp_syn_count":   syn_count,
        "udp_count":       udp_count,
        "unique_ips":      len(ips),
    }


# ---------------------------------------------------------------------------
# tcpdump capture engine
# ---------------------------------------------------------------------------

def _capture_with_tcpdump(
    tcpdump_bin: str,
    target_ip:   str,
    iface:       str,
    duration:    int,
) -> Dict:
    """
    Run tcpdump for *duration* seconds, write a pcap, parse it, return features.

    Flags:
      -i <iface>   NPF device (auto-detected from local outbound IP)
      -w <file>    write raw pcap
      -n           no DNS lookups (faster)
      -s 96        snaplen sufficient for IP + TCP/UDP headers
      -c 2000      hard packet limit so the process always terminates
      host <ip>    BPF filter — only packets to/from the target
    """
    empty = {
        "packet_count": 0, "avg_packet_size": 0.0,
        "tcp_syn_count": 0, "udp_count": 0, "unique_ips": 0,
    }
    pcap_file = None
    proc = None
    try:
        fd, pcap_file = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)

        cmd = [
            tcpdump_bin,
            "-i", iface,
            "-w", pcap_file,
            "-n",
            "-s", "96",
            "-c", "2000",          # max packets; process exits when reached
            f"host {target_ip}",
        ]

        print(f"[tcpdump] Capturing {duration}s on {iface[:30]}... "
              f"(target={target_ip})")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            cwd=_PROJECT_ROOT,    # DLLs (pcap.dll, Packet.dll) live here
        )

        try:
            _, stderr = proc.communicate(timeout=duration)
            if stderr:
                # Report packet count from tcpdump's own summary line
                for line in stderr.splitlines():
                    if "packet" in line.lower():
                        print(f"[tcpdump] {line.strip()}")
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        features = _parse_pcap(pcap_file)
        if features["packet_count"] > 0:
            print(
                f"[tcpdump] {features['packet_count']} pkts | "
                f"SYNs={features['tcp_syn_count']} | "
                f"UDP={features['udp_count']} | "
                f"IPs={features['unique_ips']}"
            )
        else:
            print(f"[tcpdump] No packets captured for {target_ip} in {duration}s")

        return features

    except Exception as exc:
        print(f"[tcpdump] Capture error: {exc}")
        if proc and proc.poll() is None:
            proc.kill()
        return empty
    finally:
        if pcap_file and os.path.exists(pcap_file):
            try:
                os.unlink(pcap_file)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Scapy fallback capture engine
# ---------------------------------------------------------------------------

def _capture_with_scapy(
    target_ip: str,
    iface:     str,
    duration:  int,
) -> Dict:
    """
    Scapy-based packet capture — sequential (never concurrent to avoid
    Npcap threading deadlocks on Windows).
    """
    from scapy.all import sniff, IP, TCP, UDP

    empty = {
        "packet_count": 0, "avg_packet_size": 0.0,
        "tcp_syn_count": 0, "udp_count": 0, "unique_ips": 0,
    }
    captured = []
    try:
        sniff(
            iface=iface,
            filter=f"host {target_ip}" if target_ip else "",
            timeout=duration,
            prn=lambda pkt: captured.append(pkt),
            store=0,
        )
    except Exception as exc:
        print(f"[Scapy] Capture error: {exc}")
        return empty

    if not captured:
        return empty

    sizes, syn_count, udp_count = [], 0, 0
    ips: set = set()
    for pkt in captured:
        if pkt.haslayer(IP):
            ips.update([pkt[IP].src, pkt[IP].dst])
            sizes.append(len(pkt))
            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:
                    syn_count += 1
            elif pkt.haslayer(UDP):
                udp_count += 1

    count = len(captured)
    print(f"[Scapy] {count} pkts | SYNs={syn_count} | UDP={udp_count} | IPs={len(ips)}")
    return {
        "packet_count":    count,
        "avg_packet_size": sum(sizes) / count if count else 0.0,
        "tcp_syn_count":   syn_count,
        "udp_count":       udp_count,
        "unique_ips":      len(ips),
    }


# ---------------------------------------------------------------------------
# Public API — called by Model 4 (scan_controller.py)
# ---------------------------------------------------------------------------

def capture_traffic(target_subdomain: str, duration: int = 5) -> Dict:
    """
    Capture packets related to *target_subdomain* for *duration* seconds.

    Engine selection (first available wins):
      1. tcpdump  — subprocess, BPF-filtered, pcap parsed in pure Python.
                    Avoids Scapy/Npcap threading conflicts in the main process.
      2. Scapy    — fallback when tcpdump binary is not present.

    Returns five numeric features for Model 4's Isolation Forest:
      { packet_count, avg_packet_size, tcp_syn_count, udp_count, unique_ips }
    """
    empty = {
        "packet_count": 0, "avg_packet_size": 0.0,
        "tcp_syn_count": 0, "udp_count": 0, "unique_ips": 0,
    }

    # Resolve target to IP
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target_subdomain)
    except socket.gaierror:
        print(f"[TrafficCollector] Cannot resolve {target_subdomain}")
        return empty

    # Detect the active network interface (Scapy → NPF device name)
    iface = _detect_active_npf_interface()
    if not iface:
        print("[TrafficCollector] No active network interface detected — skipping capture")
        return empty

    # ── Engine 1: tcpdump ─────────────────────────────────────────────────
    tcpdump_bin = _find_tcpdump()
    if tcpdump_bin:
        return _capture_with_tcpdump(tcpdump_bin, target_ip, iface, duration)

    # ── Engine 2: Scapy fallback ──────────────────────────────────────────
    if _SCAPY_AVAILABLE:
        print(f"[TrafficCollector] tcpdump not found — using Scapy fallback on {iface[:30]}")
        return _capture_with_scapy(target_ip, iface, duration)

    print("[TrafficCollector] No capture engine available")
    return empty
