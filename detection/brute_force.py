import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def detect_brute_force(
    log_file,
    threshold=5,
    window_seconds=60,
):
    """
    Detect repeated failed authentication attempts from a single IP.

    Args:
        log_file: Path to JSONL security event file.
        threshold: Number of failures required to trigger an alert.
        window_seconds: Time window in seconds.

    Returns:
        List of alert dictionaries.
    """

    log_file = Path(log_file)

    if not log_file.exists():
        return []

    failed_attempts = defaultdict(list)
    alerts = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "authentication":
                continue

            if event.get("success") is not False:
                continue

            source_ip = event.get("source_ip")
            timestamp_str = event.get("timestamp")

            if not source_ip or not timestamp_str:
                continue

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError:
                continue

            failed_attempts[source_ip].append(timestamp)

    for source_ip, timestamps in failed_attempts.items():
        timestamps.sort()

        for current_time in timestamps:
            window_start = current_time - timedelta(seconds=window_seconds)

            recent_attempts = [
                attempt
                for attempt in timestamps
                if window_start <= attempt <= current_time
            ]

            if len(recent_attempts) >= threshold:
                alerts.append({
                    "alert_type": "brute_force",
                    "source_ip": source_ip,
                    "attempts": len(recent_attempts),
                    "window_seconds": window_seconds,
                    "timestamp": current_time.isoformat(),
                    "severity": "high",
                })

                # One alert per IP for this run
                break

    return alerts