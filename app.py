"""
ReconX Flask Application - Main Entry Point
MVC Architecture
"""
import os
import sys
from datetime import timedelta
from flask import Flask
from flask_cors import CORS

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; env vars must be set manually

# Initialize logging before anything else
from utils.logger import setup_logging, get_logger
setup_logging()
logger = get_logger("reconx")

# ====================================================
# PATH CONFIGURATION
# ====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "models"))
sys.path.insert(0, os.path.join(BASE_DIR, "utils"))

# ====================================================
# FLASK APP INITIALIZATION
# ====================================================
app = Flask(__name__,
            template_folder='views',
            static_folder='static',
            static_url_path='/static')
app.secret_key = os.environ.get("SECRET_KEY", "reconx_super_secret_key_123")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,      # localhost only
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
CORS(
    app,
    origins=["http://localhost:5000", "http://127.0.0.1:5000"],
    supports_credentials=True
)

# ====================================================
# RATE LIMITING
# ====================================================
from utils.extensions import limiter
limiter.init_app(app)

# Return JSON for rate-limit errors so the frontend can display a real message
from flask import jsonify as _jsonify
@app.errorhandler(429)
def ratelimit_handler(e):
    return _jsonify(error=f"Rate limit exceeded: {e.description}. Wait a few minutes and try again."), 429


# ====================================================
# DATABASE INITIALIZATION
# ====================================================
# Import database config (this will initialize MongoDB connection)
from config.database import connect_mongodb

# Only connect once (prevents double-connection and double-logging in debug mode)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
    connect_mongodb()

# ====================================================
# GLOBAL SECURITY HOOK (CLOSED-BY-DEFAULT)
# ====================================================
from flask import session, redirect, url_for, request, jsonify

@app.before_request
def enforce_strict_auth():
    """
    Enforces authentication across ALL routes unless explicitly whitelisted.
    This ensures that new routes are secure by default.
    """
    # ── 1. Define Public Whitelist ──
    # Routes that do NOT require authentication
    whitelist = [
        'auth.login',
        'auth.signup',
        'auth.auth_status',  # Needed for frontend guard
        'auth.forgot_password',
        'auth.reset_password',
        'views.login_page',
        'views.signup_page',
        'views.index',
        'views.forgot_password_page',
        'static'
    ]

    # Normalize current endpoint
    endpoint = request.endpoint
    
    # ── 2. Allow Whitelisted Routes ──
    if endpoint in whitelist or (endpoint and endpoint.startswith('static')):
        return None

    # ── 3. CLI Lab Mode Bypass ──
    from middlewares.auth_middleware import _cli_bypass_enabled
    if _cli_bypass_enabled() and request.headers.get("X-CLI-Bypass") == "reconx_cli_mode":
        # Create a dummy admin session for the CLI
        session["user_id"] = "cli_dummy_user_id"
        session["role"] = "admin"
        session["username"] = "admin"

    # ── 4. Check Authentication ──
    if not session.get("user_id"):
        logger.warning(f"BLOCKED: Unauthenticated access to {request.path} [Endpoint: {endpoint}]")
        
        # Detect API/JSON requests
        if request.headers.get('Accept') == 'application/json' or \
           request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "Authentication required", "status": "unauthenticated"}), 401
            
        return redirect(url_for("views.login_page"))

    return None

# ====================================================
# REGISTER BLUEPRINTS (CONTROLLERS)
# ====================================================
from controllers.view_controller import view_bp
from controllers.auth_controller import auth_bp
from controllers.scan_controller import scan_bp
from controllers.report_controller import report_bp
from controllers.admin_controller import admin_bp
from controllers.ai_controller import ai_bp

app.register_blueprint(view_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(report_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(ai_bp)

# ====================================================
# SECURE REPORT DOWNLOAD ROUTE
# ====================================================
from flask import send_from_directory, abort
from werkzeug.utils import secure_filename

@app.route('/download/<path:filename>')
def download_file(filename):
    """
    Secure file download endpoint. Enforces path traversal checks.
    """
    # 1. Reject path traversal sequences explicitly
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.warning(f"BLOCKED: Path traversal attempt: '{filename}'")
        return jsonify({"error": "Path traversal attempt blocked"}), 400

    safe_name = secure_filename(filename)
    if safe_name != filename:
        logger.warning(f"BLOCKED: Sanitization mismatch: '{filename}' != '{safe_name}'")
        return jsonify({"error": "Invalid filename format"}), 400

    # Ensure reports directory is resolved absolutely at workspace root
    reports_dir = os.path.abspath(os.path.join(app.root_path, "reports"))
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.abspath(os.path.join(reports_dir, safe_name))
    
    # 2. Enforce directory containment
    if not file_path.startswith(reports_dir):
        logger.warning(f"BLOCKED: Directory containment check failed for: {file_path}")
        return jsonify({"error": "Access denied"}), 403

    if not os.path.isfile(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_from_directory(reports_dir, safe_name, as_attachment=True)

# ====================================================
# MAIN
# ====================================================
if __name__ == "__main__":
    # Prevent [WinError 10038] "An operation was attempted on something that is not a socket"
    # which frequently happens during Werkzeug development server shutdown on Windows.
    import threading
    _original_excepthook = threading.excepthook
    def _patch_winerror_10038(args):
        if issubclass(args.exc_type, OSError) and "[WinError 10038]" in str(args.exc_value):
            return
        _original_excepthook(args)
    threading.excepthook = _patch_winerror_10038

    logger.info("=" * 60)
    logger.info("Starting ReconX Flask Server...")
    logger.info("=" * 60)
    logger.info("Server running on: http://localhost:5000")
    logger.info("Access the application at:")
    logger.info("   Login:     http://localhost:5000/login")
    logger.info("   Signup:    http://localhost:5000/signup")
    logger.info("   Home:      http://localhost:5000/home")
    logger.info("   Scan:      http://localhost:5000/scan")
    logger.info("   Report:    http://localhost:5000/report")
    logger.info("   Admin:     http://localhost:5000/admin")
    logger.info("=" * 60)
    try:
        # use_reloader=False prevents Werkzeug from spawning a child process that
        # conflicts with Scapy/Npcap raw sockets on Windows (causes SIGSEGV/exit 139).
        # Debug features (error pages, auto-reload on code change) remain active.
        app.run(debug=True, host='0.0.0.0', port=5000, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Server stopped by user (KeyboardInterrupt).")
        sys.exit(0)
