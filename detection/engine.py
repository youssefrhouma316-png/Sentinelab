
from detection.brute_force import detect_brute_force
from detection.request_burst import detect_request_burst
from detection.reconnaissance import detect_reconnaissance

from response.alert_manager import normalize_alerts
from response.alert_storage import save_alerts


def run_detection(log_file):
    """
    Run all detection rules, normalize alerts,
    save new alerts, and return them.
    """

    raw_alerts = []

    raw_alerts.extend(detect_brute_force(log_file))
    raw_alerts.extend(detect_request_burst(log_file))
    raw_alerts.extend(detect_reconnaissance(log_file))

    alerts = normalize_alerts(raw_alerts)

    if alerts:
        save_alerts(alerts)

    return alerts
