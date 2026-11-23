import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def detect_request_burst(
    log_file,
    threshold=30,
    window_seconds=10,
):
    """Detect high HTTP request volume from a single source IP."""

    log_file = Path(log_file)

    if not log_file.exists():
        return []

    requests_by_ip = defaultdict(list)

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "http_request":
                continue

            source_ip = event.get("source_ip")
            timestamp_str = event.get("timestamp")

            if not source_ip or not timestamp_str:
                continue

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                continue

            requests_by_ip[source_ip].append(timestamp)

    alerts = []

    for source_ip, timestamps in requests_by_ip.items():
        timestamps.sort()

        left = 0

        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
                > timedelta(seconds=window_seconds)
            ):
                left += 1

            request_count = right - left + 1

            if request_count >= threshold:
                alerts.append({
                    "alert_type": "request_burst",
                    "source_ip": source_ip,
                    "requests": request_count,
                    "window_seconds": window_seconds,
                    "timestamp": timestamps[right].isoformat(),
                    "severity": "medium",
                })
                break

    return alerts