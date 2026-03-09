"""
Auth Controller - Handles authentication (login, signup)
"""
import datetime
from flask import request, jsonify, Blueprint, session
from werkzeug.security import generate_password_hash, check_password_hash
from config.database import users_collection, user_logs_collection
from utils.domain_validator import normalize_domains
from middlewares.auth_middleware import login_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")
    raw_domains = data.get("domains")

    if not email or not username or not password:
        return jsonify({"message": "All fields are required!"}), 400

    if raw_domains is None:
        return jsonify({"message": "Domains to scan are required."}), 400

    try:
        allowed_domains = normalize_domains(raw_domains)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already registered!"}), 409

    hashed_pw = generate_password_hash(password)

    users_collection.insert_one({
        "email": email,
        "username": username,
        "password": hashed_pw,
        "status": "pending",
        "role": "user",
        "created_at": datetime.datetime.utcnow(),
        "allowed_domains": allowed_domains,
    })

    return jsonify(
        {
            "message": "User registered successfully and is now pending admin approval.",
            "status": "pending",
        }
    ), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Unified login endpoint for both regular users and admin.

    Admin credentials are stored in the database like any other user, with:
    - role: "admin"
    - password: securely hashed (see utils/seed_admin.py)
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    ip_address = request.remote_addr or "Unknown IP"

    # Look up user (admin and regular users share the same collection)
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

    # Check if user is pending (BLOCK LOGIN for non-admin users)
    if user.get("role") != "admin" and user.get("status", "pending") != "active":
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Pending approval",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Account awaiting admin approval"}), 403

    # Password Check (hashed password only)
    stored_password = user.get("password") or ""
    if check_password_hash(stored_password, password):
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Success",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        session["logged_in"] = True
        session["user_id"] = str(user["_id"])
        session["role"] = user.get("role", "user")
        session["email"] = user.get("email")
        role = user.get("role", "user")
        return jsonify({"message": "Login successful!", "email": user["email"], "role": role}), 200
    else:
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Wrong password",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Incorrect password!"}), 401


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/user/profile", methods=["GET"])
def get_user_profile():
    """Get current logged-in user's profile (username, email, role, allowed domains)."""
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")

    try:
        from bson.objectid import ObjectId

        query_id = ObjectId(user_id)
        user = users_collection.find_one(
            {"_id": query_id},
            {"username": 1, "email": 1, "role": 1, "allowed_domains": 1},
        )

        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        return jsonify(
            {
                "username": user.get("username"),
                "email": user.get("email"),
                "role": user.get("role", "user"),
                "allowed_domains": user.get("allowed_domains", []),
            }
        ), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route("/verify-password", methods=["POST"])
def verify_password():
    """Verify user's current password for account settings access."""
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    data = request.get_json()
    password = data.get("password") if data else None
    
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400

    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": query_id}, {"password": 1})
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        stored_password = user.get("password")
        
        # Check hashed password
        if stored_password and check_password_hash(stored_password, password):
            return jsonify({"success": True, "message": "Password verified"}), 200
        else:
            return jsonify({"success": False, "error": "Incorrect password"}), 401
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route("/change-username", methods=["POST"])
def change_username():
    """
    Endpoint for a logged-in user to change their username.
    
    Request body:
    {
        "new_username": "new_username_here"
    }
    
    Validation rules:
    - No spaces or special characters (letters, numbers, underscore only)
    - Min 3 chars, max 20 chars
    - Cannot be only numbers (e.g., "123" rejected, "user123" allowed)
    - Cannot be "admin" or "reconx" (reserved)
    - Username must not already exist in DB
    """
    from bson.objectid import ObjectId
    
    # Check if user is logged in
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    
    # Get request data
    data = request.get_json()
    new_username = data.get("new_username", "").strip() if data else ""
    
    # Validation 1: Not empty
    if not new_username:
        return jsonify({"success": False, "error": "Username cannot be empty"}), 400
    
    # Validation 2: Length 3-20
    if len(new_username) < 3 or len(new_username) > 20:
        return jsonify({"success": False, "error": "Username must be between 3 and 20 characters"}), 400
    
    # Validation 3: Alphanumeric + underscore only
    if not all(c.isalnum() or c == "_" for c in new_username):
        return jsonify({"success": False, "error": "Username can only contain letters, numbers, and underscore"}), 400
    
    # Validation 4: Cannot be only numbers
    if new_username.isdigit():
        return jsonify({"success": False, "error": "Username cannot be only numbers"}), 400
    
    # Validation 5: Reserved usernames
    if new_username.lower() in ["admin", "reconx"]:
        return jsonify({"success": False, "error": "This username is reserved"}), 400
    
    # Validation 6: Username not already taken
    existing_user = users_collection.find_one({"username": new_username})
    if existing_user:
        return jsonify({"success": False, "error": "Username already taken"}), 409
    
    # Update username in DB
    try:
        # Handle both admin and regular user IDs
        if user_id == "admin":
            return jsonify({"success": False, "error": "Admin cannot change username this way"}), 403
        
        query_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        result = users_collection.update_one(
            {"_id": query_id},
            {"$set": {"username": new_username, "updated_at": datetime.datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return jsonify({"success": False, "error": "Failed to update username"}), 500
        
        return jsonify({"success": True, "message": "Username changed successfully"}), 200
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({'success': False, 'error': 'Both current and new passwords are required'}), 400

    if len(new_password) < 8:
        return jsonify({'success': False, 'error': 'New password must be at least 8 characters'}), 400

    user_id = session.get('user_id')

    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        user = users_collection.find_one({'_id': query_id})
    except Exception:
        user = None

    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    stored_password = user.get('password', '')
    # Check hashed password only
    if not (stored_password and check_password_hash(stored_password, current_password)):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 403

    # All checks passed — update password hash
    new_hash = generate_password_hash(new_password)
    users_collection.update_one({'_id': query_id}, {'$set': {'password': new_hash}})

    return jsonify({'success': True, 'message': 'Password changed successfully'})


@auth_bp.route("/subusers", methods=["POST"])
@login_required
def create_subuser():
    """
    Allow a main user to create a sub-user and assign domains.
    Domains must be a subset of the main user's allowed domains.
    """
    parent_id = session.get("user_id")
    parent = users_collection.find_one({"_id": __import__("bson").ObjectId(parent_id)})

    if not parent or parent.get("role", "user") != "user":
        return jsonify({"message": "Only main users can create sub-users."}), 403

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    raw_domains = data.get("domains")

    if not name or not email or not password or raw_domains is None:
        return jsonify({"message": "Name, email, password, and domains are required."}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists."}), 409

    try:
        assigned_domains = normalize_domains(raw_domains)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    parent_allowed = set((parent.get("allowed_domains") or []))
    if not parent_allowed:
        return jsonify({"message": "Main user has no allowed domains to assign."}), 400

    if not set(assigned_domains).issubset(parent_allowed):
        return jsonify(
            {"message": "Sub-user domains must be a subset of your allowed domains."}
        ), 400

    hashed_pw = generate_password_hash(password)

    users_collection.insert_one(
        {
            "email": email,
            "username": name,
            "password": hashed_pw,
            "role": "sub_user",
            "parent_id": parent["_id"],
            "status": "active",
            "allowed_domains": assigned_domains,
            "created_at": datetime.datetime.utcnow(),
        }
    )

    return jsonify({"message": "Sub-user created successfully."}), 201