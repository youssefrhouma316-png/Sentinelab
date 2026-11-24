
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def detect_reconnaissance(
    log_file,
    threshold=10,
    window_seconds=60,
):
    """
    Detect possible web reconnaissance based on the number
    of unique paths accessed by a single source IP.
    """

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
            path = event.get("path")
            timestamp_str = event.get("timestamp")

            if not source_ip or not path or not timestamp_str:
                continue

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                continue

            requests_by_ip[source_ip].append((timestamp, path))

    alerts = []

    for source_ip, requests in requests_by_ip.items():
        requests.sort(key=lambda item: item[0])

        left = 0

        for right in range(len(requests)):
            while (
                requests[right][0] - requests[left][0]
                > timedelta(seconds=window_seconds)
            ):
                left += 1

            recent_paths = {
                requests[index][1]
                for index in range(left, right + 1)
            }

            if len(recent_paths) >= threshold:
                alerts.append({
                    "alert_type": "reconnaissance",
                    "source_ip": source_ip,
                    "unique_paths": len(recent_paths),
                    "window_seconds": window_seconds,
                    "timestamp": requests[right][0].isoformat(),
                    "severity": "medium",
                })
                break

    return alerts
