import os
import sys

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from utils.traffic_collector import capture_traffic, SCAPY_AVAILABLE

def test_permissions():
    print("=== Traffic Analysis Verification ===")
    
    if not SCAPY_AVAILABLE:
        print("[!] ERROR: Scapy is not installed. Run: pip install scapy")
        return

    print("[*] Checking permissions...")
    try:
        # Try a very short capture
        result = capture_traffic("google.com", duration=2)
        print(f"[+] Success! Captured {result['packet_count']} packets.")
        print(f"[+] Data summary: {result}")
        
    except Exception as e:
        print(f"[!] FAILED: {str(e)}")
        print("[!] Tip: Make sure you are running this terminal as ADMINISTRATOR.")

if __name__ == "__main__":
    test_permissions()
