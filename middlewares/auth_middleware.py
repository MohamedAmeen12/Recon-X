from functools import wraps
from flask import session, redirect, url_for, request

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Use user_id as the primary source of truth for session
        if not session.get("user_id"):
            print(f"[AUTH] Unauthorized access attempt to {request.path} - Redirecting to login.")
            return redirect(url_for("views.login_page"))
        return f(*args, **kwargs)
    return decorated
