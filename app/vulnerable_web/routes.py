from flask import Blueprint, render_template, request

web = Blueprint("web", __name__)


@web.route("/")
def index():
    return render_template("index.html")


@web.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username", "")

        return f"Login attempt received for: {username}"

    return render_template("login.html")


@web.route("/health")
def health():
    return {
        "status": "running",
        "application": "SentinelLab"
    }