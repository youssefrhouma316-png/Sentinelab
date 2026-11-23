from flask import Blueprint, render_template, request

from collectors.security_logger import log_auth_event

web = Blueprint("web", __name__)


@web.route("/")
def index():
    return render_template("index.html")


@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        log_auth_event(
            source_ip=request.remote_addr or "unknown",
            success=False,
        )

        username = request.form.get("username", "")
        return f"Login attempt received for: {username}"

    return render_template("login.html")


@web.route("/health")
def health():
    return {
        "status": "running",
        "application": "SentinelLab"
    }