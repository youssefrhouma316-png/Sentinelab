
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from threading import Lock

# Project root: parent of the collectors directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "security_events.jsonl"

_lock = Lock()


def log_http_event(
    method,
    path,
    status_code,
    source_ip,
    user_agent,
    duration_ms,
):
    """Write one structured HTTP security event to a JSONL file."""

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "http_request",
        "method": method,
        "path": path,
        "status_code": status_code,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "duration_ms": round(duration_ms, 2),
    }

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with _lock:
        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

    return event
