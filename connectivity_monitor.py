"""Nonblocking internet availability checks shared by the UI and agent."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import socket
import threading
import time

from app_paths import get_app_paths


CHECK_INTERVAL = 5
CONNECTION_TIMEOUT = 1.5
STATUS_MAX_AGE_SECONDS = 20
OFFLINE_FAILURES_REQUIRED = 2
TEST_SERVERS = (("www.microsoft.com", 443), ("www.cloudflare.com", 443), ("www.google.com", 443))
STATUS_FILE = get_app_paths().internet_status
LOG_FILE = get_app_paths().security_log

_thread = None
_stop_event = threading.Event()
_lock = threading.RLock()
_status = {"status": "UNKNOWN", "connected": False, "checked_at": None,
           "consecutive_failures": 0, "offline_confirmed": False, "error": None}


def check_internet_connection():
    """Return whether a public internet endpoint is reachable; DNS errors are ordinary failures."""
    errors = []
    for host, port in TEST_SERVERS:
        try:
            with socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT):
                return True, None
        except (OSError, socket.gaierror) as error:
            errors.append(f"{host}: {error}")
    return False, "; ".join(errors)[:500]


def _read_status_file():
    try:
        value = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
        checked = datetime.fromisoformat(value["checked_at"])
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - checked.astimezone(timezone.utc)).total_seconds()
        if age < -5 or age > STATUS_MAX_AGE_SECONDS:
            return None
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return None


def get_internet_status():
    """Read the latest fresh result, failing closed if no recent check exists."""
    value = _read_status_file()
    if value is None:
        return {"status": "UNKNOWN", "connected": False, "fresh": False,
                "offline_confirmed": True, "error": "No recent internet check is available."}
    return {**value, "fresh": True, "connected": value.get("status") == "ONLINE"}


def internet_is_available():
    status = get_internet_status()
    return status.get("fresh") and status.get("status") == "ONLINE"


def internet_loss_confirmed():
    """True when a running session must stop (confirmed loss or stale checker)."""
    status = get_internet_status()
    return not status.get("fresh") or bool(status.get("offline_confirmed"))


def _publish_status(connected, error):
    global _status
    with _lock:
        failures = 0 if connected else _status["consecutive_failures"] + 1
        old_status = _status["status"]
        status = "ONLINE" if connected else "OFFLINE"
        _status = {
            "status": status,
            "connected": connected,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "consecutive_failures": failures,
            "offline_confirmed": (not connected and failures >= OFFLINE_FAILURES_REQUIRED),
            "error": error,
        }
        payload = dict(_status)
    temporary = STATUS_FILE.with_name(f".{STATUS_FILE.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATUS_FILE)
    except OSError as write_error:
        print(f"[CONNECTIVITY STATUS ERROR] {write_error}", flush=True)
        temporary.unlink(missing_ok=True)
    if old_status != status:
        message = ("Internet connectivity restored." if connected
                   else "No internet connection detected.")
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO INTERNET_{status} | {message}"
        print(line, flush=True)
        try:
            with LOG_FILE.open("a", encoding="utf-8") as log:
                log.write(line + "\n")
        except OSError:
            pass


def monitor_internet():
    while not _stop_event.is_set():
        try:
            connected, error = check_internet_connection()
            _publish_status(connected, error)
        except Exception as error:
            _publish_status(False, str(error))
        _stop_event.wait(CHECK_INTERVAL)


def start_connectivity_monitor():
    """Start the shared checker once, without delaying Streamlit rendering."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return True, "Connectivity monitoring is already running."
        _stop_event.clear()
        # Do not reuse a recent ONLINE result from a previous app session.
        with _lock:
            _status.update({
                "status": "UNKNOWN", "connected": False,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "consecutive_failures": 0, "offline_confirmed": False,
                "error": "Connectivity check in progress.",
            })
            payload = dict(_status)
        temporary = STATUS_FILE.with_name(f".{STATUS_FILE.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, STATUS_FILE)
        except OSError as error:
            print(f"[CONNECTIVITY STATUS ERROR] {error}", flush=True)
            temporary.unlink(missing_ok=True)
        _thread = threading.Thread(target=monitor_internet, name="InternetConnectivityMonitor", daemon=True)
        _thread.start()
    return True, "Internet connectivity monitoring started."


def stop_connectivity_monitor():
    global _thread
    _stop_event.set()
    thread = _thread
    if thread is not None:
        thread.join(timeout=2)
    _thread = None
    return True, "Internet connectivity monitoring stopped."


def get_connectivity_monitor_status():
    status = get_internet_status()
    return {"running": _thread is not None and _thread.is_alive(), **status}
