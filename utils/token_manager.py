import secrets
import datetime
from threading import Lock

# In-memory token store
# Structure: { "domain": {"token": "...", "expires": datetime_object} }
_token_store = {}
_store_lock = Lock()

TOKEN_LIFETIME_MINUTES = 10

def generate_token(domain: str) -> str:
    """
    Generates a secure, 32-character hex token (16 bytes) for the given domain.
    Stores it in memory with an expiration time.
    """
    token = secrets.token_hex(16)
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    
    with _store_lock:
        _token_store[domain] = {
            "token": token,
            "expires": expires
        }
    return token

def get_token_info(domain: str) -> dict:
    """
    Retrieves the token info for a domain if it exists and is not expired.
    If it is expired, returns None and removes it from the store.
    """
    with _store_lock:
        info = _token_store.get(domain)
        if info:
            if datetime.datetime.utcnow() > info["expires"]:
                del _token_store[domain]
                return None
            return info
    return None

def clear_token(domain: str) -> None:
    """
    Removes the token from the store after successful verification.
    """
    with _store_lock:
        if domain in _token_store:
            del _token_store[domain]
