import os
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from utils.logger import get_logger

logger = get_logger(__name__)

def _cli_bypass_enabled() -> bool:
    """CLI bypass is enabled when DEV_MODE=true OR CLI_BYPASS=true."""
    dev_mode = os.getenv("DEV_MODE", "").strip().lower() == "true"
    cli_bypass = os.getenv("CLI_BYPASS", "").strip().lower() == "true"
    return dev_mode or cli_bypass

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Support CLI bypass for local lab testing (DEV_MODE or CLI_BYPASS env var)
        if _cli_bypass_enabled() and request.headers.get("X-CLI-Bypass") == "reconx_cli_mode":
            session["user_id"] = "cli_dummy_user_id"
            session["role"] = "admin"
            session["username"] = "admin"

        # Use user_id as the primary source of truth for session
        if not session.get("user_id"):
            logger.warning(f"Unauthorized access attempt to {request.path} - Redirecting or returning 401.")
            
            # Detect JSON/AJAX requests
            if request.headers.get('Accept') == 'application/json' or \
               request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": "Authentication required", "status": "unauthenticated"}), 401
                
            return redirect(url_for("views.login_page"))
            
        return f(*args, **kwargs)
    return decorated
