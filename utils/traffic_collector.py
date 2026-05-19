"""
ReconX - Traffic Feature Collector
Simulates tcpdump functionality using Scapy.
Requires: Scapy and Npcap (on Windows)
"""

import socket
import time
from typing import Dict, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_addr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _detect_active_interface() -> Optional[str]:
    """
    Returns the Scapy interface name whose IP matches the machine's outbound address.
    On Windows, Scapy's default interface is often a dead/virtual adapter (IP 0.0.0.0).
    We resolve the correct one by matching the local IP used for internet traffic.
    """
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


def capture_traffic(target_subdomain: str, duration: int = 5) -> Dict:
    """
    Captures network traffic related to target_subdomain and extracts features.
    Automatically selects the active network interface so packets are actually seen.
    Falls back to zero-features gracefully when Scapy or Npcap is unavailable.
    """
    features = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0
    }

    if not SCAPY_AVAILABLE:
        print("[!] Scapy not installed. Skipping traffic analysis.")
        return features

    # Resolve target IP for BPF filter
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target_subdomain)
    except socket.gaierror:
        pass

    # Auto-detect the interface that actually carries traffic
    active_iface = _detect_active_interface()
    if not active_iface:
        print("[!] Could not detect active network interface. Skipping traffic capture.")
        return features

    bpf_filter = f"host {target_ip}" if target_ip else ""
    print(f"[*] Capturing traffic on {active_iface} for {target_subdomain}"
          f"{' (' + target_ip + ')' if target_ip else ''} — {duration}s ...")

    captured_packets = []

    try:
        sniff(
            iface=active_iface,
            filter=bpf_filter,
            timeout=duration,
            prn=lambda pkt: captured_packets.append(pkt),
            store=0
        )
    except Exception as e:
        print(f"[!] Traffic capture error: {e}")
        return features

    if not captured_packets:
        print(f"[!] No packets captured for {target_subdomain} in {duration}s.")
        return features

    sizes = []
    syn_count = 0
    udp_count = 0
    ips = set()

    for pkt in captured_packets:
        if pkt.haslayer(IP):
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
            sizes.append(len(pkt))

            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:   # SYN flag
                    syn_count += 1
            elif pkt.haslayer(UDP):
                udp_count += 1

    features["packet_count"] = len(captured_packets)
    features["avg_packet_size"] = sum(sizes) / len(sizes) if sizes else 0.0
    features["tcp_syn_count"] = syn_count
    features["udp_count"] = udp_count
    features["unique_ips"] = len(ips)

    print(f"[+] Capture complete: {len(captured_packets)} packets | "
          f"SYNs: {syn_count} | Unique IPs: {len(ips)}")

    return features
