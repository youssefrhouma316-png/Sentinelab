
from datetime import datetime, timezone
from uuid import uuid4
import hashlib
import json


def generate_fingerprint(alert):
    """
    Generate a deterministic fingerprint for a detection event.
    """

    evidence = alert.get("evidence", {})

    identity = {
        "alert_type": alert.get("alert_type"),
        "source_ip": alert.get("source_ip"),
        "timestamp": alert.get("timestamp"),
        "window_seconds": alert.get(
            "window_seconds",
            evidence.get("window_seconds")
        ),
    }

    # Do not generate a fingerprint without the essential fields.
    if not all(identity[field] for field in (
        "alert_type", "source_ip", "timestamp"
    )):
        return None

    serialized = json.dumps(identity, sort_keys=True)

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def normalize_alert(raw_alert):
    """
    Convert a raw detection alert into a standardized alert.
    """

    alert_type = raw_alert.get("alert_type", "unknown")
    source_ip = raw_alert.get("source_ip", "unknown")
    severity = raw_alert.get("severity", "medium")

    timestamp = raw_alert.get("timestamp")

    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    descriptions = {
        "brute_force": (
            f"Multiple failed authentication attempts "
            f"detected from {source_ip}."
        ),
        "request_burst": (
            f"High HTTP request volume detected from {source_ip}."
        ),
        "reconnaissance": (
            f"Possible web reconnaissance detected from {source_ip}."
        ),
    }

    standard_fields = {
        "alert_type",
        "source_ip",
        "severity",
        "timestamp",
    }

    evidence = {
        key: value
        for key, value in raw_alert.items()
        if key not in standard_fields
    }

    normalized = {
        "alert_id": f"ALERT-{uuid4().hex[:12].upper()}",
        "alert_type": alert_type,
        "source_ip": source_ip,
        "severity": severity,
        "timestamp": timestamp,
        "description": descriptions.get(
            alert_type,
            f"Security event detected from {source_ip}."
        ),
        "evidence": evidence,
    }

    normalized["fingerprint"] = generate_fingerprint(normalized)

    return normalized


def normalize_alerts(raw_alerts):
    """
    Normalize a list of raw detection alerts.
    """

    return [
        normalize_alert(alert)
        for alert in raw_alerts
    ]
