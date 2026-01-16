"""
ReconX Flask Application - Main Entry Point
MVC Architecture
"""
import os
import sys
from flask import Flask
from flask_cors import CORS

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
CORS(app)

# ====================================================
# DATABASE INITIALIZATION
# ====================================================
# Import database config (this will initialize MongoDB connection)
from config.database import connect_mongodb
connect_mongodb()

# ====================================================
# REGISTER BLUEPRINTS (CONTROLLERS)
# ====================================================
from controllers.view_controller import view_bp
from controllers.auth_controller import auth_bp
from controllers.scan_controller import scan_bp
from controllers.report_controller import report_bp
from controllers.admin_controller import admin_bp

app.register_blueprint(view_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(report_bp)
app.register_blueprint(admin_bp)

# ====================================================
# MAIN
# ====================================================
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting ReconX Flask Server...")
    print("=" * 60)
    print("📍 Server running on: http://localhost:5000")
    print("📍 Access the application at:")
    print("   • Login:     http://localhost:5000/login")
    print("   • Signup:    http://localhost:5000/signup")
    print("   • Home:      http://localhost:5000/home")
    print("   • Scan:      http://localhost:5000/scan")
    print("   • Report:    http://localhost:5000/report")
    print("   • Admin:     http://localhost:5000/admin")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
