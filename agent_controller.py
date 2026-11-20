import subprocess
import sys
import time
import psutil

from pathlib import Path
from network_monitor import (
    start_network_monitor,
    stop_network_monitor,
    get_network_monitor_status
)

from connectivity_monitor import (
    start_connectivity_monitor,
    stop_connectivity_monitor,
    get_internet_status
)

BASE_DIR = Path(__file__).resolve().parent
MONITOR_SCRIPT = BASE_DIR / "monitor_engine.py"

PID_FILE = BASE_DIR / "monitor_engine.pid"
LOG_FILE = BASE_DIR / "agent_runtime.log"


def _get_agent_process():

    if not PID_FILE.exists():
        return None

    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        process = psutil.Process(pid)

        if not process.is_running():
            PID_FILE.unlink(missing_ok=True)
            return None

        command = process.cmdline()
        expected_script = str(MONITOR_SCRIPT.resolve()).lower()

        if not any(
            str(argument).lower() == expected_script
            for argument in command
        ):
            PID_FILE.unlink(missing_ok=True)
            return None

        if process.status() == psutil.STATUS_ZOMBIE:
            PID_FILE.unlink(missing_ok=True)
            return None

        return process

    except (ValueError, psutil.Error, OSError):
        PID_FILE.unlink(missing_ok=True)
        return None


def _network_is_running():

    try:
        status = get_network_monitor_status()

        if isinstance(status, dict):
            return bool(status.get("running", False))

        if isinstance(status, str):
            return status.upper() in ("RUNNING", "ACTIVE")

        return bool(status)

    except Exception:
        return False


def _start_network():

    result = start_network_monitor()

    # Support either (success, message) or a simple boolean return.
    if isinstance(result, tuple):
        success = bool(result[0])
        message = str(result[1]) if len(result) > 1 else ""

        if not success:
            raise RuntimeError(message or "Network monitor failed to start.")

    elif result is False:
        raise RuntimeError("Network monitor failed to start.")

    # Verify that the monitor actually started.
    time.sleep(0.5)

    if not _network_is_running():
        raise RuntimeError(
            "TShark network monitor did not enter the running state."
        )


def get_agent_status():

    process = _get_agent_process()

    if process is None:
        return "STOPPED"

    return "RUNNING"


def start_agent():

    if get_agent_status() == "RUNNING":
        return False, "Monitoring is already running."

    process = None

    try:

        # STEP 1: Start process monitoring.
        with LOG_FILE.open("a", encoding="utf-8") as log:

            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP
                if sys.platform == "win32"
                else 0
            )

            process = subprocess.Popen(
                [sys.executable, str(MONITOR_SCRIPT)],
                cwd=BASE_DIR,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=creation_flags
            )

        PID_FILE.write_text(
            str(process.pid),
            encoding="utf-8"
        )

        time.sleep(0.5)

        if process.poll() is not None:
            PID_FILE.unlink(missing_ok=True)

            return (
                False,
                "Process monitor failed to start. Check agent_runtime.log."
            )

        # STEP 2: Start network monitoring.
        # STEP 2: Start network monitoring.
        _start_network()

        # STEP 3: Start internet connectivity monitoring.
        start_connectivity_monitor()

        return True, (
            "Process monitoring, TShark network monitoring "
            "and internet connectivity monitoring started successfully."
        )

    except Exception as error:

        # Roll back process monitoring if network startup fails.
        if process is not None:

            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        PID_FILE.unlink(missing_ok=True)

        # Also attempt to clean up a partially started network monitor.
        try:
            stop_network_monitor()
        except Exception:
            pass

        return False, f"Could not start monitoring: {error}"


def stop_agent():

    messages = []

    # STEP 0: Stop internet connectivity monitoring.
    try:
        stop_connectivity_monitor()
        messages.append("Internet connectivity monitoring stopped.")
    except Exception as error:
        messages.append(f"Connectivity monitor error: {error}")

    # STEP 1: Stop network monitoring.
    try:
        stop_network_monitor()
        messages.append("Network monitoring stopped.")
    except Exception as error:
        messages.append(f"Network monitor error: {error}")

    # STEP 2: Stop process monitoring.
    process = _get_agent_process()

    if process is not None:

        try:
            process.terminate()

            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            messages.append("Process monitoring stopped.")

        except psutil.Error as error:
            messages.append(f"Process monitor error: {error}")

    else:
        messages.append("Process monitoring was already stopped.")

    PID_FILE.unlink(missing_ok=True)

    return True, " ".join(messages)
