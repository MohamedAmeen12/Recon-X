import os
import sys

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from utils.nvd_api_tool import get_nvd_client

def test_nvd():
    print(f"Checking NVD_API_KEY environment variable...")
    key = os.getenv("NVD_API_KEY")
    if not key:
        print("ERROR: NVD_API_KEY not found in environment!")
        return
    
    print(f"Key found: {key[:4]}...{key[-4:]}")
    
    try:
        client = get_nvd_client()
        print("Client initialized. Searching for 'Apache 2.4.41'...")
        df = client.search_by_keyword("Apache 2.4.41", results_per_page=1)
        
        if df is not None and not df.empty:
            print("SUCCESS! API returned data.")
            print(df.iloc[0][['cve_id', 'cvss_score', 'severity']])
        else:
            print("FAILED: API returned no records or error.")
            
    except Exception as e:
        print(f"EXCEPTION: {str(e)}")

if __name__ == "__main__":
    test_nvd()
