from functools import wraps
from flask import session, redirect, url_for, jsonify, request

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # Check for user_id in session
        if not session.get("user_id"):
            print(f"[ADMIN-AUTH] Unauthorized access attempt to {request.path} - Redirecting to login.")
            return redirect(url_for("views.login_page"))

        # Check for admin role
        if session.get("role") != "admin":
            print(f"[ADMIN-AUTH] Non-admin access attempt to {request.path} by {session.get('email')}")
            return jsonify({"error": "Unauthorized. Admin role required."}), 403

        return f(*args, **kwargs)
    return decorated
