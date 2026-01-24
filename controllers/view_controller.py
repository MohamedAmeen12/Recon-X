"""
View Controller - Handles all HTML page rendering
"""
from flask import render_template, Blueprint
from middlewares.admin_middleware import admin_required
from middlewares.auth_middleware import login_required
view_bp = Blueprint('views', __name__)


@view_bp.route("/")
@view_bp.route("/index")
@view_bp.route("/index.html")
def index():
    return render_template("index.html")


@view_bp.route("/login")
@view_bp.route("/login.html")
def login_page():
    return render_template("login.html")


@view_bp.route("/signup")
@view_bp.route("/signup.html")
def signup_page():
    return render_template("signup.html")


@view_bp.route("/home")
@view_bp.route("/home.html")
@view_bp.route("/dashboard")
@login_required
def home():
    return render_template("home.html")


@view_bp.route("/scan")
@view_bp.route("/scan.html")
@login_required
def scan_page():
    return render_template("scan.html")



@view_bp.route("/report")
@view_bp.route("/report.html")
@login_required
def report_page():
    return render_template("report.html")


@view_bp.route("/history")
@view_bp.route("/history.html")
@login_required
def history_page():
    return render_template("history.html")

@view_bp.route("/admin")
@admin_required
def admin_page():
    return render_template("admin/Admin.html")


@view_bp.route("/admin/pending-users")
@admin_required
def pending_users_page():
    return render_template("admin/pending_users.html")


@view_bp.route("/admin/user-logs")
@admin_required
def user_logs_page():
    return render_template("admin/user_logs.html")


@view_bp.route("/admin/user-edit")
@admin_required
def user_edit_page():
    return render_template("admin/user_edit.html")