import requests
import time
from urllib.parse import urlparse
from utils.logger import get_logger

logger = get_logger(__name__)

# Constants for exact requirement checks
VERIFIED = "VERIFIED"
FILE_NOT_FOUND = "FILE_NOT_FOUND"
MISMATCH = "MISMATCH"
CONNECTION_ERROR = "CONNECTION_ERROR"

def verify_domain_token(domain: str, expected_token: str) -> str:
    """
    Performs an HTTP GET request to verify if the correct token
    is placed at [domain]/reconx-verification.txt
    
    Returns one of the constant states.
    """
    # 1. VERIFY URL CONSTRUCTION
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain
        
    url = f"{domain.rstrip('/')}/reconx-verification.txt"
    # Append random query to perfectly bust aggressive edge caches 
    fetch_url = f"{url}?_t={int(time.time() * 1000)}"
    
    try:
        # 2. HTTP REQUEST HANDLING
        response = requests.get(fetch_url, timeout=5)
        
        # 4. DEBUG LOGGING
        print("URL:", url)
        print("Status:", response.status_code)
        print("Content:", repr(response.text))
        print("Token:", repr(expected_token))
        
        # 5. ERROR HANDLING
        if response.status_code != 200:
            return FILE_NOT_FOUND
            
        # 3. TOKEN COMPARISON FIX (CRITICAL)
        # Stripping whitespace from response
        content = response.text.strip()
        # Stripping whitespace from stored token
        token = expected_token.strip()
        
        # Ensuring exact string comparison
        if content == token:
            return VERIFIED
        else:
            return MISMATCH
            
    except requests.exceptions.RequestException as e:
        print("[Verification Error] Connection error for", url, ":", e)
        return CONNECTION_ERROR
