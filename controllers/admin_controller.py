"""
Admin Controller - Handles admin operations
"""
import datetime
from flask import request, jsonify, Blueprint
from bson import ObjectId
from werkzeug.security import generate_password_hash
from config.database import (
    users_collection,
    user_logs_collection,
    reports_collection,
)
from utils.domain_validator import normalize_domains

from middlewares.admin_middleware import admin_required

admin_bp = Blueprint(
    'admin',
    __name__,
    url_prefix="/admin"   # ⭐ VERY IMPORTANT
)


@admin_bp.route("/get_users", methods=["GET"])
@admin_required
def get_users():
    users = []
    for u in users_collection.find():
        users.append({
            "_id": str(u["_id"]),
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "created_at": str(u.get("created_at", "")),
            "role": u.get("role", "user"),
        })
    return jsonify(users)


@admin_bp.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists!"}), 409

    hashed_pw = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_pw,
        "role": "user",
        "status": "active",
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User added successfully!"}), 201


@admin_bp.route("/delete_user/<user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"message": "User deleted successfully"}), 200


@admin_bp.route("/get_user_logs", methods=["GET"])
@admin_required
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


@admin_bp.route("/get_pending_users", methods=["GET"])
@admin_required
def get_pending_users():
    """Returns all users where status = 'pending'"""
    pending_users = []
    for u in users_collection.find({"status": "pending"}):
        pending_users.append({
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "created_at": str(u.get("created_at", "")),
        })

    return jsonify({"users": pending_users}), 200


@admin_bp.route("/approve_user", methods=["POST"])
@admin_required
def approve_user():
    """Admin approves or declines a pending user."""
    data = request.get_json()
    email = data.get("email")
    action = data.get("action")

    if not email or not action:
        return jsonify({"message": "Email and action required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    # APPROVE
    if action == "approve":
        users_collection.update_one(
            {"email": email},
            {"$set": {"status": "active"}}
        )
        return jsonify({"message": "User approved successfully"}), 200

    # DECLINE
    if action == "decline":
        users_collection.delete_one({"email": email})
        return jsonify({"message": "User declined and removed"}), 200

    return jsonify({"message": "Invalid action"}), 400


@admin_bp.route("/update_user_domains", methods=["POST"])
@admin_required
def update_user_domains():
    """
    Admin endpoint to update the allowed scan domains for a specific user.

    Expected JSON body:
    {
        "email": "user@example.com",
        "domains": "example.com, sub.example.com"
        // or
        "domains": ["example.com", "sub.example.com"]
    }
    """
    data = request.get_json() or {}
    email = data.get("email")
    raw_domains = data.get("domains")

    if not email or raw_domains is None:
        return jsonify({"message": "Email and domains are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    try:
        allowed_domains = normalize_domains(raw_domains)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    result = users_collection.update_one(
        {"email": email},
        {
            "$set": {
                "allowed_domains": allowed_domains,
                "updated_at": datetime.datetime.utcnow(),
            }
        },
    )

    if result.modified_count == 0:
        # No-op update, but treat as success for idempotency
        return jsonify({"message": "Domains unchanged", "allowed_domains": allowed_domains}), 200

    return jsonify(
        {"message": "Allowed domains updated successfully", "allowed_domains": allowed_domains}
    ), 200


@admin_bp.route("/get_user_domains/<user_id>", methods=["GET"])
@admin_required
def get_user_domains(user_id):
    """
    Return an overview of a user's domains:
      - allowed_domains (from user document)
      - scanned_domains (distinct domains from reports)
    """
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        allowed_domains = user.get("allowed_domains", [])

        # Collect distinct domains scanned by this user
        scanned_set = set()
        for doc in reports_collection.find({"user_id": user_id}, {"domain": 1}):
            d = (doc.get("domain") or "").strip().lower()
            if d:
                scanned_set.add(d)

        return jsonify(
            {
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "role": user.get("role", "user"),
                "allowed_domains": allowed_domains,
                "scanned_domains": sorted(scanned_set),
            }
        ), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
