from functools import wraps
from flask import session, redirect, url_for, jsonify

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # Not logged in
        if not session.get("logged_in"):
            return redirect(url_for("auth.login"))

        # Not admin
        if session.get("role") != "admin":
            return jsonify({"error": "Unauthorized"}), 403

        return f(*args, **kwargs)
    return decorated
