from collections import Counter

from flask import Blueprint, render_template, request, abort

from collectors.security_logger import log_auth_event
from response.alert_storage import load_alerts

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


@web.route("/dashboard")
def dashboard():
    alerts = load_alerts()

    severity_counts = Counter(
        alert.get("severity", "unknown").lower()
        for alert in alerts
    )

    type_counts = Counter(
        alert.get("alert_type", "unknown")
        for alert in alerts
    )

    recent_alerts = sorted(
        alerts,
        key=lambda alert: alert.get("timestamp", ""),
        reverse=True
    )[:10]

    return render_template(
        "dashboard.html",
        total_alerts=len(alerts),
        severity_counts=severity_counts,
        type_counts=type_counts,
        recent_alerts=recent_alerts,
    )

@web.route("/alerts/<alert_id>")
def alert_details(alert_id):
    """
    Display detailed information about a specific security alert.
    """

    alerts = load_alerts()

    alert = next(
        (
            item for item in alerts
            if item.get("alert_id") == alert_id
        ),
        None
    )

    if alert is None:
        abort(404)

    return render_template(
        "alert_details.html",
        alert=alert
    )