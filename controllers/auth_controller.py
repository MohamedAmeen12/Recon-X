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

