"""Start, inspect, and stop the independent local monitoring supervisor."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil

from app_paths import get_app_paths, runtime_lock


BASE_DIR = Path(__file__).resolve().parent
APP_PATHS = get_app_paths()
WORKER_SCRIPT = BASE_DIR / "agent_runtime.py"
LEGACY_MONITOR_SCRIPT = BASE_DIR / "monitor_engine.py"
PID_FILE = APP_PATHS.monitor_pid
LOG_FILE = APP_PATHS.agent_log
CONTROLLER_LOCK = "agent_controller.lock.sqlite"
STARTUP_WAIT_SECONDS = 0.35
STOP_WAIT_SECONDS = 15


def _script_kind(process):
    try:
        expected = {
            os.path.normcase(str(WORKER_SCRIPT.resolve())): "worker",
            os.path.normcase(str(LEGACY_MONITOR_SCRIPT.resolve())): "legacy",
        }
        for argument in process.cmdline():
            if argument == "--monitor-worker":
                try:
                    if os.path.normcase(process.exe()) == os.path.normcase(sys.executable):
                        return "worker"
                except (psutil.Error, OSError):
                    return None
            try:
                candidate = os.path.normcase(str(Path(argument).resolve()))
            except (OSError, ValueError):
                continue
            if candidate in expected:
                return expected[candidate]
    except (psutil.Error, OSError):
        return None
    return None


def _get_agent_process():
    """Return only a PID that still belongs to a recognized project worker."""
    if not PID_FILE.exists():
        return None
    try:
        stored = json.loads(PID_FILE.read_text(encoding="utf-8"))
        if isinstance(stored, dict):
            pid = int(stored["pid"])
            expected_created = float(stored["created"])
        else:
            # Accept old PID files, but only after validating the command line.
            pid = int(stored)
            expected_created = None
        process = psutil.Process(pid)
        if (
            not process.is_running()
            or process.status() == psutil.STATUS_ZOMBIE
            or _script_kind(process) is None
            or (expected_created is not None and abs(process.create_time() - expected_created) > 0.01)
        ):
            PID_FILE.unlink(missing_ok=True)
            return None
        return process
    except (ValueError, psutil.Error, OSError):
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        return None


def _read_worker_status():
    try:
        with APP_PATHS.agent_status.open("r", encoding="utf-8") as status_file:
            value = json.load(status_file)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def _stopped_status(reason=None, previous=None):
    previous_components = (previous or {}).get("components", {})
    components = {}
    for name in ("process", "network", "connectivity"):
        old = previous_components.get(name, {})
        components[name] = {
            **old,
            "previous_status": old.get("status"),
            "status": "STOPPED",
            "running": False,
        }
    return {
        "status": "STOPPED",
        "running": False,
        "error": reason or (previous or {}).get("error"),
        "components": components,
        "started_at": (previous or {}).get("started_at"),
        "updated_at": (previous or {}).get("updated_at"),
    }


def get_agent_status():
    """Return supervisor state and the last reported health of each component."""
    previous = _read_worker_status()
    process = _get_agent_process()
    if process is None:
        reason = None
        if previous and previous.get("status") not in ("STOPPED", None):
            reason = "Monitoring worker exited unexpectedly; use Start to restart it."
        return _stopped_status(reason, previous)

    kind = _script_kind(process)
    if kind == "legacy":
        return {
            "status": "LEGACY_RUNNING",
            "running": True,
            "error": "An older process-only monitor is active. Stop it before restarting monitoring.",
            "components": {
                "process": {"status": "RUNNING", "running": True, "error": None},
                "network": {"status": "UNKNOWN", "running": False, "error": None},
                "connectivity": {"status": "UNKNOWN", "running": False, "error": None},
            },
        }

    if previous and previous.get("pid") == process.pid:
        try:
            updated_at = previous.get("updated_at")
            if updated_at:
                from datetime import datetime, timezone
                last_update = datetime.fromisoformat(updated_at)
                if (datetime.now(timezone.utc) - last_update).total_seconds() > 10:
                    return {
                        **previous,
                        "status": "UNRESPONSIVE",
                        "running": True,
                        "error": "Monitoring worker has not refreshed its health status recently.",
                    }
        except (TypeError, ValueError):
            pass
        return {**previous, "running": previous.get("status") in ("RUNNING", "DEGRADED", "STARTING")}

    return {
        "status": "STARTING",
        "running": True,
        "pid": process.pid,
        "error": None,
        "components": {
            name: {"status": "STARTING", "running": False, "error": None}
            for name in ("process", "network", "connectivity")
        },
    }


def _write_pid(pid):
    temporary = PID_FILE.with_name(f".{PID_FILE.name}.{pid}.tmp")
    with temporary.open("w", encoding="utf-8") as pid_file:
        process = psutil.Process(pid)
        json.dump({"pid": pid, "created": process.create_time()}, pid_file)
        pid_file.flush()
        os.fsync(pid_file.fileno())
    os.replace(temporary, PID_FILE)


def _stop_process(process):
    try:
        process.terminate()
        try:
            process.wait(timeout=STOP_WAIT_SECONDS)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        return True
    except (psutil.Error, OSError):
        return False


def start_agent():
    """Launch one detached supervisor; packet-capture failure is non-fatal."""
    try:
        with runtime_lock(APP_PATHS, CONTROLLER_LOCK):
            current = _get_agent_process()
            if current is not None:
                if _script_kind(current) == "legacy":
                    return False, (
                        "The previous process-only monitor is still running. "
                        "Stop it before starting the new monitoring supervisor."
                    )
                return False, "Monitoring is already running."

            APP_PATHS.agent_stop_request.unlink(missing_ok=True)
            try:
                with LOG_FILE.open("a", encoding="utf-8") as log:
                    creation_flags = (
                        subprocess.CREATE_NEW_PROCESS_GROUP
                        if sys.platform == "win32"
                        else 0
                    )
                    worker_command = (
                        [sys.executable, "--monitor-worker"]
                        if getattr(sys, "frozen", False)
                        else [sys.executable, str(WORKER_SCRIPT)]
                    )
                    process = subprocess.Popen(
                        worker_command,
                        cwd=BASE_DIR,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        creationflags=creation_flags,
                        close_fds=True,
                    )
                _write_pid(process.pid)
            except (OSError, subprocess.SubprocessError) as error:
                return False, f"Could not launch the monitoring worker: {error}"

            time.sleep(STARTUP_WAIT_SECONDS)
            if process.poll() is not None:
                PID_FILE.unlink(missing_ok=True)
                return (
                    False,
                    "Monitoring worker exited during startup. Check "
                    f"{LOG_FILE} for details.",
                )

            return True, (
                "Monitoring is starting on this computer. Component status "
                "will update shortly; packet capture may be unavailable if "
                "Npcap or capture permissions are missing."
            )
    except Exception as error:
        return False, f"Could not start monitoring: {error}"


def stop_agent():
    """Request a graceful shutdown, with a bounded forced-stop fallback."""
    try:
        with runtime_lock(APP_PATHS, CONTROLLER_LOCK):
            process = _get_agent_process()
            if process is None:
                APP_PATHS.agent_stop_request.unlink(missing_ok=True)
                PID_FILE.unlink(missing_ok=True)
                return True, "Monitoring was already stopped."

            if _script_kind(process) == "legacy":
                stopped = _stop_process(process)
                PID_FILE.unlink(missing_ok=True)
                return (
                    stopped,
                    "Previous process-only monitoring stopped."
                    if stopped else "Could not stop the previous monitoring process.",
                )

            try:
                APP_PATHS.agent_stop_request.write_text(
                    "stop\n",
                    encoding="utf-8",
                )
                process.wait(timeout=STOP_WAIT_SECONDS)
                message = "Monitoring stopped cleanly."
            except psutil.TimeoutExpired:
                stopped = _stop_process(process)
                message = (
                    "Monitoring worker did not stop in time and was terminated."
                    if stopped else "Monitoring worker did not stop cleanly."
                )
                if not stopped:
                    return False, message
            except (OSError, psutil.Error) as error:
                return False, f"Could not request monitoring shutdown: {error}"

            PID_FILE.unlink(missing_ok=True)
            APP_PATHS.agent_stop_request.unlink(missing_ok=True)
            return True, message
    except Exception as error:
        return False, f"Could not stop monitoring: {error}"
