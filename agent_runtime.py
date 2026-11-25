"""Independent supervisor for process, packet, and connectivity monitors."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import threading
import time
import traceback

from app_paths import get_app_paths
from connectivity_monitor import (
    get_connectivity_monitor_status,
    start_connectivity_monitor,
    stop_connectivity_monitor,
)
from monitor_engine import monitor_loop
from network_monitor import (
    get_network_monitor_status,
    start_network_monitor,
    stop_network_monitor,
)


APP_PATHS = get_app_paths()
STATUS_INTERVAL = 1.0
COMPONENT_RETRY_SECONDS = 30.0
stop_event = threading.Event()
state_lock = threading.Lock()
components = {
    "process": {"status": "STARTING", "running": False, "error": None},
    "network": {"status": "STARTING", "running": False, "error": None},
    "connectivity": {"status": "STARTING", "running": False, "error": None},
}
started_at = None


def _now():
    return datetime.now(timezone.utc).isoformat()


def _set_component(name, status, error=None, **details):
    with state_lock:
        component = {
            **components.get(name, {}),
            "status": status,
            "running": status == "RUNNING",
            "error": str(error)[:500] if error else None,
            "updated_at": _now(),
            **details,
        }
        components[name] = component


def _atomic_write_status(payload):
    status_path = APP_PATHS.agent_status
    temp_path = status_path.with_name(
        f".{status_path.name}.{os.getpid()}.tmp"
    )
    try:
        with temp_path.open("w", encoding="utf-8") as status_file:
            json.dump(payload, status_file, ensure_ascii=False)
            status_file.flush()
            os.fsync(status_file.fileno())
        os.replace(temp_path, status_path)
    except OSError as error:
        print(f"[AGENT STATUS ERROR] {error}", flush=True)
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def publish_status(final_status=None, error=None):
    with state_lock:
        snapshot = {name: dict(state) for name, state in components.items()}
    worker_running = snapshot["process"]["running"]
    network_running = snapshot["network"]["running"]
    status = final_status or (
        "RUNNING" if worker_running and network_running else
        "DEGRADED" if worker_running else "STARTING"
    )
    _atomic_write_status({
        "pid": os.getpid(),
        "status": status,
        "error": str(error)[:500] if error else None,
        "started_at": started_at,
        "updated_at": _now(),
        "components": snapshot,
    })


def _process_component():
    try:
        _set_component("process", "RUNNING", last_check_at=_now())

        def cycle_completed():
            _set_component("process", "RUNNING", last_check_at=_now())

        monitor_loop(stop_event, on_cycle=cycle_completed)
    except Exception as error:
        _set_component("process", "ERROR", error)
        print("[PROCESS MONITOR ERROR]", traceback.format_exc(), flush=True)


def _start_network_component():
    try:
        result = start_network_monitor()
        success = bool(result[0]) if isinstance(result, tuple) else result is not False
        message = str(result[1]) if isinstance(result, tuple) and len(result) > 1 else None
        status = get_network_monitor_status()
        running = bool(status.get("running")) if isinstance(status, dict) else success
        error = status.get("error") if isinstance(status, dict) else None
        if not success or not running:
            _set_component("network", "UNAVAILABLE", error or message or "Packet capture did not start.")
            print("[NETWORK MONITOR UNAVAILABLE]", error or message, flush=True)
            return
        _set_component("network", "RUNNING")
    except Exception as error:
        _set_component("network", "UNAVAILABLE", error)
        print(f"[NETWORK MONITOR UNAVAILABLE] {error}", flush=True)


def _start_connectivity_component():
    try:
        result = start_connectivity_monitor()
        success = bool(result[0]) if isinstance(result, tuple) else result is not False
        message = str(result[1]) if isinstance(result, tuple) and len(result) > 1 else None
        status = get_connectivity_monitor_status()
        running = bool(status.get("running")) if isinstance(status, dict) else success
        if not success or not running:
            _set_component("connectivity", "UNAVAILABLE", status.get("error") or message)
            return
        _set_component(
            "connectivity",
            "RUNNING",
            internet_status=status.get("status", "UNKNOWN"),
        )
    except Exception as error:
        _set_component("connectivity", "UNAVAILABLE", error)
        print(f"[CONNECTIVITY MONITOR UNAVAILABLE] {error}", flush=True)


def run_agent():
    """Start component monitors and supervise them until a stop request arrives."""
    global started_at
    started_at = _now()
    stop_event.clear()
    # The controller clears stale requests before spawning this process. Do
    # not clear again here: Stop may arrive while Python is still importing
    # the worker's (notably Scapy's) dependencies.
    if APP_PATHS.agent_stop_request.exists():
        for name in components:
            _set_component(name, "STOPPED")
        publish_status(final_status="STOPPED")
        APP_PATHS.agent_stop_request.unlink(missing_ok=True)
        return

    def start_process_thread():
        thread = threading.Thread(
            target=_process_component,
            name="ProcessMonitor",
            daemon=True,
        )
        thread.start()
        return thread

    process_thread = start_process_thread()
    _start_network_component()
    _start_connectivity_component()
    next_network_retry = time.monotonic() + COMPONENT_RETRY_SECONDS
    next_connectivity_retry = next_network_retry

    try:
        while not stop_event.is_set():
            if APP_PATHS.agent_stop_request.exists():
                stop_event.set()
                break

            network = get_network_monitor_status()
            if isinstance(network, dict):
                if network.get("running"):
                    _set_component("network", "RUNNING")
                elif components["network"]["status"] == "RUNNING":
                    _set_component(
                        "network",
                        "UNAVAILABLE",
                        network.get("error") or "Packet capture worker stopped unexpectedly.",
                    )
                if not network.get("running") and time.monotonic() >= next_network_retry:
                    _start_network_component()
                    next_network_retry = time.monotonic() + COMPONENT_RETRY_SECONDS

            connectivity = get_connectivity_monitor_status()
            if connectivity.get("running"):
                _set_component(
                    "connectivity",
                    "RUNNING",
                    internet_status=connectivity.get("status", "UNKNOWN"),
                    error=None,
                )
            elif components["connectivity"]["status"] == "RUNNING":
                _set_component("connectivity", "UNAVAILABLE", connectivity.get("error"))
            if not connectivity.get("running") and time.monotonic() >= next_connectivity_retry:
                _start_connectivity_component()
                next_connectivity_retry = time.monotonic() + COMPONENT_RETRY_SECONDS

            if not process_thread.is_alive() and not stop_event.is_set():
                _set_component(
                    "process",
                    "STARTING",
                    "Process monitor stopped unexpectedly; restarting it.",
                )
                process_thread = start_process_thread()

            publish_status()
            stop_event.wait(STATUS_INTERVAL)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        try:
            stop_network_monitor()
        except Exception as error:
            print(f"[NETWORK MONITOR STOP ERROR] {error}", flush=True)
        try:
            stop_connectivity_monitor()
        except Exception as error:
            print(f"[CONNECTIVITY MONITOR STOP ERROR] {error}", flush=True)
        process_thread.join(timeout=5)
        for name in components:
            _set_component(name, "STOPPED")
        publish_status(final_status="STOPPED")
        APP_PATHS.agent_stop_request.unlink(missing_ok=True)


if __name__ == "__main__":
    run_agent()
