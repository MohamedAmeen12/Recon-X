"""
Quick test script to check if the server endpoint works
"""
import request
import json

def test_scan_endpoint():
    url = "http://localhost:5000/scan_domain"
    data = {
        "domain": "example.com"
    }
    
    print("Testing scan endpoint...")
    print(f"URL: {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(url, json=data, timeout=30)
        print(f"\n✅ Status Code: {response.status_code}")
        print(f"Response: {response.text[:500]}")  # First 500 chars
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to server!")
        print("   Make sure Flask server is running: python app.py")
    except requests.exceptions.Timeout:
        print("\n⏱️  ERROR: Request timed out (scan taking too long)")
    except Exception as e:
        print(f"\n❌ ERROR: {type(e).__name__}: {e}")

if __name__ == "__main__":
    test_scan_endpoint()

