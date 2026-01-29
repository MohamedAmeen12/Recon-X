"""
Auth Controller - Handles authentication (login, signup)
"""
import datetime
from flask import request, jsonify, Blueprint , session
from werkzeug.security import generate_password_hash, check_password_hash
from config.database import users_collection, user_logs_collection

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/signup", methods=["POST"])
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
        "status": "pending",
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User registered successfully and is now pending admin approval.",
                     "status": "pending"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    ip_address = request.remote_addr or "Unknown IP"

    # Admin Login
    if email == "ReconX@gmail.com" and password == "reconx1234":
        user_logs_collection.insert_one({
            "username": "Admin",
            "email": email,
            "status": "Success",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        session["logged_in"] = True
        session["user_id"] = "admin"
        session["role"] = "admin"
        session["email"] = email
        print("SESSION AFTER LOGIN:", dict(session))
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

    # Check if user is pending (BLOCK LOGIN)
    if user.get("status", "pending") != "active":
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Pending approval",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        return jsonify({"message": "Account awaiting admin approval"}), 403

    # Password Check
    stored_password = user.get("password")
    if stored_password == password or check_password_hash(stored_password, password):
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


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/user/profile", methods=["GET"])
def get_user_profile():
    """Get current logged-in user's profile (username, email, role)."""
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    
    if user_id == "admin":
        return jsonify({"username": "Admin", "email": session.get("email"), "role": "admin"}), 200
    
    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": query_id}, {"username": 1, "email": 1, "role": 1})
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        return jsonify({
            "username": user.get("username"),
            "email": user.get("email"),
            "role": user.get("role", "user")
        }), 200
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
    
    # Admin account
    if user_id == "admin":
        admin_password = "reconx1234"
        if password == admin_password:
            return jsonify({"success": True, "message": "Password verified"}), 200
        else:
            return jsonify({"success": False, "error": "Incorrect password"}), 401
    
    # Regular user
    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": query_id}, {"password": 1})
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        stored_password = user.get("password")
        
        # Check plain or hashed password
        if stored_password == password or check_password_hash(stored_password, password):
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

