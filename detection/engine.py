
from detection.brute_force import detect_brute_force
from detection.request_burst import detect_request_burst
from detection.reconnaissance import detect_reconnaissance

def run_detection(log_file):
    """
    Run all detection rules and return a unified list of alerts.
    """

    alerts = []

    # Brute-force detection
    alerts.extend(detect_brute_force(log_file))

    # Request-burst detection
    alerts.extend(detect_request_burst(log_file))

    # Reconnaissance detection
    alerts.extend(detect_reconnaissance(log_file))

    return alerts
