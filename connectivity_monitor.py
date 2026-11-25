import socket
import threading
import time
from datetime import datetime
from app_paths import get_app_paths


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

CHECK_INTERVAL = 10
CONNECTION_TIMEOUT = 1

TEST_SERVERS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 443)
]

LOG_FILE = get_app_paths().security_log


# --------------------------------------------------
# MONITORING STATE
# --------------------------------------------------

internet_status = "UNKNOWN"

monitor_thread = None
stop_event = threading.Event()
status_lock = threading.Lock()


# --------------------------------------------------
# CHECK INTERNET CONNECTION
# --------------------------------------------------

def check_internet_connection():

    for host, port in TEST_SERVERS:

        try:

            connection = socket.create_connection(
                (host, port),
                timeout=CONNECTION_TIMEOUT
            )

            connection.close()

            return True

        except OSError:
            continue

    return False


# --------------------------------------------------
# LOG CONNECTION EVENTS
# --------------------------------------------------

def log_connection_event(status):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if status == "ONLINE":

        message = (
            f"[{timestamp}] INFO INTERNET_RESTORED | "
            "Internet connectivity restored."
        )

    else:

        message = (
            f"[{timestamp}] ERROR INTERNET_DISCONNECTED | "
            "No internet connection detected."
        )

    print(message)

    try:

        with LOG_FILE.open("a", encoding="utf-8") as log:

            log.write(message + "\n")

    except OSError as error:

        print("Connectivity log error:", error)


# --------------------------------------------------
# CONTINUOUS INTERNET MONITOR
# --------------------------------------------------

def monitor_internet():

    global internet_status

    print("[CONNECTIVITY MONITOR STARTED]")

    while not stop_event.is_set():

        try:

            print("[CHECKING INTERNET CONNECTION...]")

            connected = check_internet_connection()

            new_status = (
                "ONLINE" if connected else "OFFLINE"
            )

            with status_lock:

                previous_status = internet_status
                internet_status = new_status

            print("[INTERNET STATUS]:", new_status)

            # Log only when connectivity changes.
            if previous_status != new_status:

                log_connection_event(new_status)

        except Exception as error:

            print("Internet monitoring error:", error)

        stop_event.wait(CHECK_INTERVAL)



# --------------------------------------------------
# START CONNECTIVITY MONITOR
# --------------------------------------------------

def start_connectivity_monitor():

    global monitor_thread, internet_status
    if monitor_thread is not None and monitor_thread.is_alive():
        return True, "Connectivity monitoring is already running."

    stop_event.clear()

    # Set an initial status before the dashboard renders. This avoids waiting
    # for its periodic refresh to pick up the monitor thread's first result.
    try:
        connected = check_internet_connection()
        initial_status = "ONLINE" if connected else "OFFLINE"
        with status_lock:
            previous_status = internet_status
            internet_status = initial_status
        if previous_status != initial_status:
            log_connection_event(initial_status)
    except Exception as error:
        print("Initial internet check failed:", error)

    monitor_thread = threading.Thread(
        target=monitor_internet,
        daemon=True,
        name="InternetConnectivityMonitor"
    )

    monitor_thread.start()
    return True, "Internet connectivity monitoring started."


# --------------------------------------------------
# STOP CONNECTIVITY MONITOR
# --------------------------------------------------

def stop_connectivity_monitor():

    global monitor_thread
    stop_event.set()
    if monitor_thread is not None:

        monitor_thread.join(timeout=2)

    monitor_thread = None

    return True, "Internet connectivity monitoring stopped."


# --------------------------------------------------
# GET INTERNET STATUS
# --------------------------------------------------

def get_internet_status():

    with status_lock:

        return {
            "status": internet_status,
            "connected": internet_status == "ONLINE"
        }
# --------------------------------------------------
# GET CONNECTIVITY MONITOR STATUS
# --------------------------------------------------

def get_connectivity_monitor_status():

    global monitor_thread

    with status_lock:
        current_status = internet_status

    running = (
        monitor_thread is not None
        and monitor_thread.is_alive()
        and not stop_event.is_set()
    )

    return {
        "running": running,
        "status": current_status,
        "connected": current_status == "ONLINE",
        "error": None
    }
