"""
View Controller - Handles all HTML page rendering
"""
from flask import render_template, Blueprint

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
def home():
    return render_template("home.html")


@view_bp.route("/scan")
@view_bp.route("/scan.html")
def scan_page():
    return render_template("scan.html")


@view_bp.route("/report")
@view_bp.route("/report.html")
def report_page():
    return render_template("report.html")


@view_bp.route("/admin")
@view_bp.route("/Admin.html")
def admin_page():
    return render_template("Admin.html")


@view_bp.route("/pending_users")
@view_bp.route("/pending_users.html")
def pending_users_page():
    return render_template("pending_users.html")


@view_bp.route("/user_logs")
@view_bp.route("/user_logs.html")
def user_logs_page():
    return render_template("user_logs.html")


@view_bp.route("/user_edit")
@view_bp.route("/user_edit.html")
def user_edit_page():
    return render_template("user_edit.html")
