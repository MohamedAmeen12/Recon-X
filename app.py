import os
import sys
import time
import datetime
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash


# ====================================================
# FIX PYTHON PATHS (THIS SOLVES MODULE NOT FOUND)
# ====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Add backend/, backend/model/, backend/tools/ to import path
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "model"))
sys.path.insert(0, os.path.join(BASE_DIR, "tools"))

# Import Model 1: Subdomain Discovery
from model.model1 import run_subdomain_discovery
# Import Model 2: Port Scanning
from model.model2 import run_port_scanning
# Import Model 3: Technology Fingerprinting
from model.model3 import run_technology_fingerprinting_for_subdomains


# ====================================================
# FLASK APP
# ====================================================
app = Flask(__name__, 
            template_folder='Templates',
            static_folder='.',
            static_url_path='')
CORS(app)


# ====================================================
# MONGO CONNECTION
# ====================================================
MONGO_URI = "mongodb+srv://youssef2203723_db_user:SQmEU8rJv4amXR38@cluster0.tfybtes.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Try to connect to MongoDB with retries
client = None
max_retries = 3
retry_delay = 2

for attempt in range(max_retries):
    try:
        print(f"Attempting MongoDB connection (attempt {attempt + 1}/{max_retries})...")
        client = MongoClient(
            MONGO_URI, 
            serverSelectionTimeoutMS=10000,  # Increased timeout to 10 seconds
            connectTimeoutMS=10000,
            socketTimeoutMS=10000
        )
        # Test connection
        client.server_info()
        print("✅ MongoDB connection successful!")
        break
    except Exception as e:
        print(f"❌ MongoDB connection attempt {attempt } failed: {e}")
        if attempt < max_retries - 1:
            print(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
        else:
            print("\n" + "="*60)
            print("⚠️  WARNING: MongoDB connection failed after all retries!")
            print("="*60)
            print("Possible solutions:")
            print("1. Check your internet connection")
            print("2. Verify MongoDB Atlas cluster is running and not paused")
            print("3. Check if your IP address is whitelisted in MongoDB Atlas")
            print("4. Verify the connection string is correct")
            print("5. Check firewall settings")
            print("\nThe application will continue but database features will not work.")
            print("="*60 + "\n")
            # Don't exit - allow app to run without DB for testing
            client = None

# Initialize database collections (only if client is connected)
if client:
    db = client["reconx_db"]
    users_collection = db["users"]
    domains_collection = db["domains"]
    reports_collection = db["reports"]
    user_logs_collection = db["user_logs"]
    subdomains_collection = db["subdomains"]
    technologies_collection = db["technologies"]  # Model 3: Technology fingerprints
    vulnerabilities_collection = db["vulnerabilities"]  # Model 3: CVE data
else:
    # Create dummy collections to prevent errors (will fail on actual DB operations)
    class DummyCollection:
        def find_one(self, *args, **kwargs): return None
        def find(self, *args, **kwargs): return []
        def insert_one(self, *args, **kwargs): return None
        def update_one(self, *args, **kwargs): return None
        def delete_one(self, *args, **kwargs): return None
    
    users_collection = DummyCollection()
    domains_collection = DummyCollection()
    reports_collection = DummyCollection()
    user_logs_collection = DummyCollection()
    subdomains_collection = DummyCollection()
    technologies_collection = DummyCollection()
    vulnerabilities_collection = DummyCollection()


# Helper function to check MongoDB connection
def is_mongodb_connected():
    """Check if MongoDB is connected and working."""
    if not client:
        return False
    try:
        client.server_info()
        return True
    except:
        return False


# ====================================================
# SIGNUP  (UNCHANGED)
# ====================================================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return jsonify({"message": "All fields are required!"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already registered!"}), 409

    hashed_pw = generate_password_hash(password)

    users_collection.insert_one({
        "email": email,
        "username": username,
        "password": hashed_pw,
        "status": "pending",                   # <-- IMPORTANT
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User registered successfully and is now pending admin approval."}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    ip_address = request.remote_addr or "Unknown IP"

    # Admin Login (UNCHANGED)
    if email == "ReconX@gmail.com" and password == "reconx1234":
        user_logs_collection.insert_one({
            "username": "Admin",
            "email": email,
            "status": "Success",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Admin login successful!", "email": email, "role": "admin"}), 200

    # Regular User
    user = users_collection.find_one({"email": email})
    if not user:
        user_logs_collection.insert_one({
            "username": "Unknown",
            "email": email,
            "status": "Failed - User not found",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "User not found!"}), 404

    # 🔥 NEW — Check if user is pending (BLOCK LOGIN)
    if user.get("status", "pending") != "active":
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Pending approval",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Account awaiting admin approval"}), 403

    # Password Check (UNCHANGED)
    stored_password = user.get("password")
    if stored_password == password or check_password_hash(stored_password, password):
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Success",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Login successful!", "email": user["email"], "role": "user"}), 200
    else:
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Wrong password",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Incorrect password!"}), 401


# ====================================================
# STATIC PAGES - HTML ROUTES
# ====================================================
@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index():
    return render_template("index.html")

@app.route("/login")
@app.route("/login.html")
def login_page():
    return render_template("login.html")

@app.route("/signup")
@app.route("/signup.html")
def signup_page():
    return render_template("signup.html")

@app.route("/home")
@app.route("/home.html")
@app.route("/dashboard")
def home():
    return render_template("home.html")

@app.route("/scan")
@app.route("/scan.html")
def scan_page():
    return render_template("scan.html")

@app.route("/report")
@app.route("/report.html")
def report_page():
    return render_template("report.html")

@app.route("/admin")
@app.route("/Admin.html")
def admin_page():
    return render_template("Admin.html")

@app.route("/pending_users")
@app.route("/pending_users.html")
def pending_users_page():
    return render_template("pending_users.html")

@app.route("/user_logs")
@app.route("/user_logs.html")
def user_logs_page():
    return render_template("user_logs.html")

@app.route("/user_edit")
@app.route("/user_edit.html")
def user_edit_page():
    return render_template("user_edit.html")


# ====================================================
# ADD DOMAIN  (UNCHANGED)
# ====================================================
@app.route("/add_domain", methods=["POST"])
def add_domain():
    data = request.get_json()
    domain_name = data.get("domain")

    if not domain_name:
        return jsonify({"message": "Domain name is required!"}), 400

    domains_collection.insert_one({"domain": domain_name})
    return jsonify({"message": "Domain saved successfully!"}), 201


# ====================================================
# SCAN DOMAIN (MODEL 1)
# ====================================================
@app.route("/scan_domain", methods=["POST"])
def scan_domain():
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()
        include_tech_scan = data.get("include_tech_scan", False)  # Optional: skip Model 3 by default

        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        start = time.time()
        print(f"Starting scan for domain: {domain}")

        result = run_subdomain_discovery(domain)
        print(f"Model 1 completed in {time.time() - start:.2f} seconds")

        # Store results into DB
        for sub in result.get("raw_docs", []):
            sub["domain"] = domain
            sub["scanned_at"] = datetime.datetime.utcnow()
            subdomains_collection.update_one(
                {"domain": domain, "subdomain": sub["subdomain"]},
                {"$set": sub},
                upsert=True
            )

        # Model 3: Technology Fingerprinting & Vulnerability Detection (Non-blocking)
        # Run Model 3 in background to avoid blocking the scan response
        tech_results = []
        if include_tech_scan:  # Only run if explicitly requested
            try:
                print("Starting Model 3 (Technology Fingerprinting)...")
                # Prepare data for Model 3 (only for live HTTP subdomains, limit to 5 for speed)
                live_subdomains = [sub for sub in result.get("raw_docs", []) if sub.get("live_http")]
                
                if live_subdomains:
                    # Use existing port scan data instead of re-scanning
                    subdomains_data = []
                    for sub_doc in live_subdomains[:5]:  # Limit to 5 for faster response
                        subdomain = sub_doc.get("subdomain")
                        ip = sub_doc.get("ip")
                        url = f"http://{subdomain}" if subdomain else None
                        
                        # Use existing port data - no need to re-scan with nmap
                        # Model 3 will extract from HTTP headers which is fast
                        subdomains_data.append({
                            "subdomain": subdomain,
                            "url": url,
                            "nmap_data": None,  # Skip slow nmap version scan
                            "ip": ip
                        })
                    
                    # Run Model 3 with timeout (non-blocking)
                    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
                    executor = ThreadPoolExecutor(max_workers=1)
                    future = executor.submit(run_technology_fingerprinting_for_subdomains, subdomains_data)
                    
                    try:
                        # Wait max 30 seconds for Model 3
                        tech_results = future.result(timeout=30)
                    except FutureTimeoutError:
                        print("Model 3 timed out after 30 seconds - skipping")
                        tech_results = []
                    except Exception as e:
                        print(f"Model 3 error: {e}")
                        tech_results = []
                    
                    # Store technology fingerprints in MongoDB
                    for tech_result in tech_results:
                        url = tech_result.get("url")
                        subdomain = tech_result.get("url", "").replace("http://", "").replace("https://", "")
                        
                        for tech in tech_result.get("technologies", []):
                            tech_doc = {
                                "domain": domain,
                                "subdomain": subdomain,
                                "url": url,
                                "technology": tech.get("technology"),
                                "version": tech.get("version"),
                                "category": tech.get("category"),
                                "source": tech.get("source"),
                                "vulnerability_status": tech.get("vulnerability_status"),
                                "confidence": tech.get("confidence"),
                                "max_cvss": tech.get("max_cvss"),
                                "similarity_score": tech.get("similarity_score"),
                                "scanned_at": datetime.datetime.utcnow()
                            }
                            
                            technologies_collection.update_one(
                                {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version")
                                },
                                {"$set": tech_doc},
                                upsert=True
                            )
                            
                            # Store CVE details separately
                            for cve in tech.get("cves", []):
                                cve_doc = {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version"),
                                    "cve_id": cve.get("cve"),
                                    "cvss_score": cve.get("cvss"),
                                    "description": cve.get("description"),
                                    "severity": cve.get("severity", "UNKNOWN"),
                                    "published_date": cve.get("published_date"),
                                    "cwe": cve.get("cwe", "N/A"),
                                    "scanned_at": datetime.datetime.utcnow()
                                }
                                
                                vulnerabilities_collection.update_one(
                                    {
                                        "domain": domain,
                                        "subdomain": subdomain,
                                        "cve_id": cve.get("cve")
                                    },
                                    {"$set": cve_doc},
                                    upsert=True
                                )
            except Exception as e:
                print(f"Model 3 error: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("Model 3 skipped (set include_tech_scan=true to enable)")

        report = {
            "domain": domain,
            "total_candidates": result.get("total_candidates", 0),
            "resolved": result.get("resolved", 0),
            "live_http": result.get("live_http", 0),
            "elapsed_seconds": time.time() - start,
            "examples": result.get("examples", []),
            "clusters": result.get("clusters", []),
            "raw_docs": result.get("raw_docs", []),
            "ports_summary": result.get("ports_summary", {}),
            "technology_fingerprints": tech_results if tech_results else []  # Model 3 results (may be empty if timed out)
        }

        reports_collection.update_one(
            {"domain": domain},
            {"$set": {"result": report}},
            upsert=True
        )

        return jsonify({"message": "Scan complete", "report": report}), 200
    except Exception as e:
        print(f"Error in scan_domain: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


# ====================================================
# GET TECHNOLOGIES (MODEL 3)
# ====================================================
@app.route("/get_technologies", methods=["GET"])
def get_technologies():
    """Get technology fingerprints and vulnerabilities for a domain from MongoDB."""
    domain = request.args.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    try:
        technologies = list(technologies_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("scanned_at", -1))
        
        vulnerabilities = list(vulnerabilities_collection.find(
            {"domain": domain},
            {"_id": 0}
        ).sort("cvss_score", -1))
        
        return jsonify({
            "domain": domain,
            "technologies": technologies,
            "vulnerabilities": vulnerabilities,
            "total_technologies": len(technologies),
            "total_vulnerabilities": len(vulnerabilities)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ====================================================
# GET REPORT
# ====================================================
@app.route("/get_report", methods=["GET"])
def get_report():
    domain = request.args.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    record = reports_collection.find_one({"domain": domain})
    if not record:
        return jsonify({"message": "No report found"}), 404

    # If technology_fingerprints is missing or empty, fetch from MongoDB
    if not record.get("result", {}).get("technology_fingerprints") or len(record.get("result", {}).get("technology_fingerprints", [])) == 0:
        try:
            # Fetch technologies from MongoDB
            technologies = list(technologies_collection.find(
                {"domain": domain},
                {"_id": 0}
            ).sort("scanned_at", -1))
            
            # Fetch vulnerabilities from MongoDB
            vulnerabilities = list(vulnerabilities_collection.find(
                {"domain": domain},
                {"_id": 0}
            ).sort("cvss_score", -1))
            
            # Group technologies by subdomain/url
            tech_by_url = {}
            for tech in technologies:
                url = tech.get("url", f"http://{tech.get('subdomain', '')}")
                if url not in tech_by_url:
                    tech_by_url[url] = {
                        "url": url,
                        "technologies": []
                    }
                
                # Check if technology already exists in the list
                existing_tech = next(
                    (t for t in tech_by_url[url]["technologies"] 
                     if t.get("technology") == tech.get("technology") and t.get("version") == tech.get("version")),
                    None
                )
                
                if not existing_tech:
                    # Get CVEs for this technology
                    tech_cves = [
                        {
                            "cve": v.get("cve_id"),
                            "cvss": v.get("cvss_score"),
                            "description": v.get("description", ""),
                            "severity": v.get("severity", "UNKNOWN"),
                            "published_date": v.get("published_date"),
                            "cwe": v.get("cwe", "N/A")
                        }
                        for v in vulnerabilities
                        if v.get("subdomain") == tech.get("subdomain") and 
                           v.get("technology") == tech.get("technology") and
                           v.get("version") == tech.get("version")
                    ]
                    
                    tech_by_url[url]["technologies"].append({
                        "technology": tech.get("technology"),
                        "version": tech.get("version"),
                        "category": tech.get("category", "Unknown"),
                        "source": tech.get("source", "Unknown"),
                        "vulnerability_status": tech.get("vulnerability_status", "unknown"),
                        "confidence": tech.get("confidence", 0.0),
                        "max_cvss": tech.get("max_cvss", 0.0),
                        "similarity_score": tech.get("similarity_score", 0.0),
                        "cves": tech_cves
                    })
            
            # Convert to list format expected by frontend
            technology_fingerprints = list(tech_by_url.values())
            
            # Update the record's result with technology fingerprints
            if "result" not in record:
                record["result"] = {}
            record["result"]["technology_fingerprints"] = technology_fingerprints
            
            # Update the stored report in MongoDB
            reports_collection.update_one(
                {"domain": domain},
                {"$set": {"result": record["result"]}}
            )
            
        except Exception as e:
            print(f"Error fetching technologies for report: {e}")
            import traceback
            traceback.print_exc()
            # Continue without technology data if there's an error

    record["_id"] = str(record["_id"])
    return jsonify(record)


# ====================================================
# GET USERS
# ====================================================
@app.route("/get_users", methods=["GET"])
def get_users():
    users = []
    for u in users_collection.find():
        users.append({
            "_id": str(u["_id"]),
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "company": u.get("company", ""),
            "created_at": str(u.get("created_at", "")),
        })
    return jsonify(users)


# ====================================================
# ADD USER (ADMIN)
# ====================================================
@app.route("/add_user", methods=["POST"])
def add_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    company = data.get("company")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists!"}), 409

    hashed_pw = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "email": email,
        "company": company,
        "password": hashed_pw,
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User added successfully!"}), 201


# ====================================================
# DELETE USER
# ====================================================
@app.route("/delete_user/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"message": "User deleted successfully"}), 200


# ====================================================
# GET USER LOGS
# ====================================================
@app.route("/get_user_logs", methods=["GET"])
def get_user_logs():
    logs = []
    for log in user_logs_collection.find().sort("login_time", -1):
        logs.append({
            "_id": str(log["_id"]),
            "username": log.get("username", "Unknown"),
            "email": log.get("email", "N/A"),
            "status": log.get("status", "Unknown"),
            "ip": log.get("ip", "N/A"),
            "login_time": log.get("login_time").strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify(logs)

@app.route("/get_pending_users", methods=["GET"])
def get_pending_users():
    """
    Returns all users where status = 'pending'
    """
    pending_users = []
    for u in users_collection.find({"status": "pending"}):
        pending_users.append({
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "company": u.get("company", "N/A"),
            "created_at": str(u.get("created_at", "")),
        })

    return jsonify({"users": pending_users}), 200

@app.route("/approve_user", methods=["POST"])
def approve_user():
    """
    Admin approves or declines a pending user.
    Frontend sends:
    { "email": "...", "action": "approve" | "decline" }
    """

    data = request.get_json()
    email = data.get("email")
    action = data.get("action")

    if not email or not action:
        return jsonify({"message": "Email and action required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    # --- APPROVE ---
    if action == "approve":
        users_collection.update_one(
            {"email": email},
            {"$set": {"status": "active"}}
        )
        return jsonify({"message": "User approved successfully"}), 200

    # --- DECLINE ---
    if action == "decline":
        users_collection.delete_one({"email": email})
        return jsonify({"message": "User declined and removed"}), 200

    # --- INVALID ACTION ---
    return jsonify({"message": "Invalid action"}), 400

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
