
import json
from pathlib import Path

from response.alert_manager import generate_fingerprint


def _get_alert_key(alert):
    """
    Get a stable key for duplicate detection.
    Prefer the event fingerprint; fall back to alert_id.
    """

    fingerprint = alert.get("fingerprint")

    if not fingerprint:
        fingerprint = generate_fingerprint(alert)

    if fingerprint:
        return ("fingerprint", fingerprint)

    alert_id = alert.get("alert_id")

    if alert_id:
        return ("alert_id", alert_id)

    return None


def save_alerts(alerts, alert_file="logs/alerts.jsonl"):
    """
    Append only new standardized alerts to a JSONL file.

    Returns the number of alerts actually saved.
    """

    if not alerts:
        return 0

    path = Path(alert_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build a set of keys for previously stored alerts.
    existing_alerts = load_alerts(path)

    existing_keys = {
        key
        for alert in existing_alerts
        if (key := _get_alert_key(alert)) is not None
    }

    saved_count = 0

    with path.open("a", encoding="utf-8") as file:
        for alert in alerts:
            key = _get_alert_key(alert)

            if key is not None and key in existing_keys:
                continue

            file.write(json.dumps(alert) + "\n")
            saved_count += 1

            if key is not None:
                existing_keys.add(key)

    return saved_count


def load_alerts(alert_file="logs/alerts.jsonl"):
    """
    Load standardized alerts from a JSONL file.
    Malformed lines are skipped.
    """

    path = Path(alert_file)

    if not path.exists():
        return []

    alerts = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                alert = json.loads(line)

                if isinstance(alert, dict):
                    alerts.append(alert)

            except json.JSONDecodeError:
                continue

    return alerts
