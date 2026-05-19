"""
ReconX - Traffic Feature Collector
Primary engine: tcpdump (built from https://github.com/the-tcpdump-group/tcpdump)
Fallback engine: Scapy (if tcpdump binary is unavailable)

tcpdump is run as a subprocess with a BPF filter targeting the scan domain IP.
It writes a pcap file which is then parsed for:
  - packet_count, avg_packet_size, tcp_syn_count, udp_count, unique_ips

These five numeric features feed directly into Model 4 (Isolation Forest).
"""

import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# tcpdump binary search order
# ---------------------------------------------------------------------------
_TCPDUMP_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tcpdump.exe"),
    r"C:\Users\DELL\tcpdump-build\Release\tcpdump.exe",
    r"C:\Users\DELL\tcpdump\bin\tcpdump.exe",
    r"C:\tools\tcpdump.exe",
]


def _find_tcpdump() -> Optional[str]:
    """Return the path to tcpdump.exe, or None if not installed."""
    for p in _TCPDUMP_CANDIDATES:
        if os.path.exists(p):
            return p
    # Also check system PATH (may be installed globally)
    found = shutil.which("tcpdump")
    if found and "tcpdump" in found.lower():
        return found
    return None


# ---------------------------------------------------------------------------
# Scapy fallback
# ---------------------------------------------------------------------------
try:
    from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


def _detect_active_interface() -> Optional[str]:
    """
    Returns the Scapy interface name that matches the machine's outbound IP.
    On Windows, Scapy's default is often a dead adapter (IP 0.0.0.0).
    """
    if not _SCAPY_AVAILABLE:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        return None

    for iface in get_if_list():
        try:
            if get_if_addr(iface) == local_ip:
                return iface
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Minimal pcap file parser (no external dependency)
# ---------------------------------------------------------------------------

_PCAP_GLOBAL_HEADER = 24   # bytes
_PCAP_RECORD_HEADER = 16   # bytes per packet record

def _parse_pcap(path: str) -> Dict:
    """
    Parse a pcap file written by tcpdump and extract traffic features.
    Uses raw struct parsing — no libpcap or pyshark dependency at read time.

    Returns the same feature dict shape that Model 4 expects.
    """
    features = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0,
    }

    if not os.path.exists(path) or os.path.getsize(path) <= _PCAP_GLOBAL_HEADER:
        return features

    sizes = []
    syn_count = 0
    udp_count = 0
    ips: set = set()

    try:
        with open(path, "rb") as f:
            # Global header — detect endianness from magic number
            magic = f.read(4)
            if len(magic) < 4:
                return features
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            else:
                return features

            # Skip rest of global header (20 bytes remaining)
            f.read(20)

            while True:
                rec_hdr = f.read(_PCAP_RECORD_HEADER)
                if len(rec_hdr) < _PCAP_RECORD_HEADER:
                    break

                # ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
                _, _, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec_hdr)
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                sizes.append(orig_len)

                # Parse Ethernet (14 bytes) → IP
                if len(raw) < 14:
                    continue
                eth_type = struct.unpack("!H", raw[12:14])[0]
                if eth_type != 0x0800:      # not IPv4
                    continue

                ip_start = 14
                if len(raw) < ip_start + 20:
                    continue

                ihl = (raw[ip_start] & 0x0F) * 4
                protocol = raw[ip_start + 9]
                src_ip = socket.inet_ntoa(raw[ip_start + 12: ip_start + 16])
                dst_ip = socket.inet_ntoa(raw[ip_start + 16: ip_start + 20])
                ips.add(src_ip)
                ips.add(dst_ip)

                tcp_start = ip_start + ihl
                if protocol == 6:           # TCP
                    if len(raw) >= tcp_start + 14:
                        flags = raw[tcp_start + 13]
                        if flags & 0x02:    # SYN flag
                            syn_count += 1
                elif protocol == 17:        # UDP
                    udp_count += 1

    except Exception as exc:
        print(f"[TrafficCollector] pcap parse error: {exc}")

    packet_count = len(sizes)
    features["packet_count"] = packet_count
    features["avg_packet_size"] = sum(sizes) / packet_count if packet_count else 0.0
    features["tcp_syn_count"] = syn_count
    features["udp_count"] = udp_count
    features["unique_ips"] = len(ips)
    return features


# ---------------------------------------------------------------------------
# tcpdump-based capture
# ---------------------------------------------------------------------------

def _capture_with_tcpdump(
    target_ip: str,
    duration: int,
    tcpdump_bin: str,
) -> Dict:
    """
    Run tcpdump for *duration* seconds filtering on *target_ip*, write a
    pcap file, parse it with _parse_pcap, and return the feature dict.

    tcpdump flags used:
      -w <file>   write raw pcap (no ASCII decode needed)
      -G <secs>   rotate file every N seconds (used here to auto-stop)
      -W 1        write only 1 file then exit
      host <ip>   BPF filter — only packets to/from the target
      -n          no DNS resolution (faster)
      -s 96       snaplen 96 bytes (enough for IP+TCP headers, avoids large pcaps)
    """
    features = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0,
    }

    pcap_file = None
    proc = None
    try:
        fd, pcap_file = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)

        cmd = [
            tcpdump_bin,
            "-w", pcap_file,
            "-G", str(duration),
            "-W", "1",
            "-n",
            "-s", "96",
            f"host {target_ip}",
        ]

        print(f"[tcpdump] Capturing {duration}s of traffic from/to {target_ip}...")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for tcpdump to finish (it auto-exits after -G seconds with -W 1)
        try:
            _, stderr = proc.communicate(timeout=duration + 5)
            if stderr and "packets captured" in stderr.lower():
                # e.g. "42 packets captured"
                for line in stderr.splitlines():
                    if "packets captured" in line:
                        print(f"[tcpdump] {line.strip()}")
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=3)

        features = _parse_pcap(pcap_file)
        print(
            f"[tcpdump] Parsed pcap: {features['packet_count']} pkts | "
            f"SYNs: {features['tcp_syn_count']} | "
            f"UDP: {features['udp_count']} | "
            f"Unique IPs: {features['unique_ips']}"
        )

    except Exception as exc:
        print(f"[tcpdump] Capture error: {exc}")
        if proc and proc.poll() is None:
            proc.terminate()
    finally:
        if pcap_file and os.path.exists(pcap_file):
            try:
                os.unlink(pcap_file)
            except Exception:
                pass

    return features


# ---------------------------------------------------------------------------
# Scapy fallback capture (sequential — NOT concurrent, avoids Npcap deadlock)
# ---------------------------------------------------------------------------

def _capture_with_scapy(target_ip: str, iface: str, duration: int) -> Dict:
    """Scapy-based packet capture. Called only when tcpdump is unavailable."""
    features = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0,
    }

    captured = []
    bpf = f"host {target_ip}" if target_ip else ""

    try:
        sniff(
            iface=iface,
            filter=bpf,
            timeout=duration,
            prn=lambda pkt: captured.append(pkt),
            store=0,
        )
    except Exception as exc:
        print(f"[Scapy] Capture error: {exc}")
        return features

    if not captured:
        return features

    sizes, syn_count, udp_count = [], 0, 0
    ips: set = set()
    for pkt in captured:
        if pkt.haslayer(IP):
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
            sizes.append(len(pkt))
            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:
                    syn_count += 1
            elif pkt.haslayer(UDP):
                udp_count += 1

    count = len(captured)
    features.update({
        "packet_count": count,
        "avg_packet_size": sum(sizes) / count if count else 0.0,
        "tcp_syn_count": syn_count,
        "udp_count": udp_count,
        "unique_ips": len(ips),
    })
    print(
        f"[Scapy] {count} packets | SYNs: {syn_count} | "
        f"UDP: {udp_count} | Unique IPs: {len(ips)}"
    )
    return features


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def capture_traffic(target_subdomain: str, duration: int = 5) -> Dict:
    """
    Capture network traffic for *target_subdomain* and return feature dict.

    Engine selection (first available wins):
      1. tcpdump  — subprocess + BPF filter + raw pcap parsing
                    (most reliable; avoids Scapy/Npcap threading conflicts)
      2. Scapy    — fallback when tcpdump binary is not installed

    Both engines return the same feature dict:
      { packet_count, avg_packet_size, tcp_syn_count, udp_count, unique_ips }
    """
    empty = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0,
    }

    # Resolve target IP for BPF filtering
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target_subdomain)
    except socket.gaierror:
        print(f"[TrafficCollector] Cannot resolve {target_subdomain} — skipping capture")
        return empty

    # ── Engine 1: tcpdump ─────────────────────────────────────────────────
    tcpdump_bin = _find_tcpdump()
    if tcpdump_bin:
        print(f"[TrafficCollector] Using tcpdump: {tcpdump_bin}")
        return _capture_with_tcpdump(target_ip, duration, tcpdump_bin)

    # ── Engine 2: Scapy fallback ──────────────────────────────────────────
    if _SCAPY_AVAILABLE:
        iface = _detect_active_interface()
        if iface:
            print(f"[TrafficCollector] tcpdump not found — using Scapy on {iface}")
            return _capture_with_scapy(target_ip, iface, duration)
        print("[TrafficCollector] No active interface detected — skipping capture")
        return empty

    print("[TrafficCollector] No capture engine available (install tcpdump or Scapy)")
    return empty
