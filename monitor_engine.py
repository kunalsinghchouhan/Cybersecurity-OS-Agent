import time
import psutil
from datetime import datetime
from app_paths import get_app_paths
from connectivity_monitor import internet_is_available, internet_loss_confirmed
from detection_engine import detect_process_events
from risk_engine import calculate_risk
from alert_manager import AlertManager

CPU_Threshold = 80
Memory_Threshold = 500
Poll_Interval = 3
Alert_Cooldown = 60

Log_File = get_app_paths().security_log

# last_alerts = {}
alert_manager = AlertManager(cooldown=Alert_Cooldown)
known_connections = set()
connection_monitor_warning_shown = False

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_event(event_type, severity, message):
    event =(
        f"{timestamp()} |  {severity} "
        f"{event_type}  |  {message}"
    )
    print(event,flush =True)

    with Log_File.open("a",encoding="utf-8") as log_file:
        log_file.write(event + "\n") 

# Prevent from generating the same alert too frequently
# def should_alert(key):
#     now = time.monotonic()
#     previous = last_alerts.get(key) 

#     if previous is None or now - previous >= Alert_Cooldown:
#         last_alerts[key] = now
#         return True

#     return False

def monitor_processes():
    for process in psutil.process_iter(
        ["pid", "name", "memory_info"]
    ):
        try:
            pid = process.info["pid"]
            name = process.info["name"] or "Unknown"

            cpu = process.cpu_percent(interval=None)
            memory = process.info["memory_info"]

            if memory is None:
                memory_mb = process.memory_info().rss / (1024 * 1024)
            else:
                memory_mb = memory.rss / (1024 * 1024)

            events = detect_process_events(pid, name, cpu, memory_mb)

            if events:
                score, severity = calculate_risk(events)
            
                for event in events:
                    alert_manager.send_alert(event, score, severity)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

def monitor_connections():
    global known_connections, connection_monitor_warning_shown

    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError, RuntimeError) as error:
        if not connection_monitor_warning_shown:
            print(
                "TCP connection details are unavailable for this account: "
                f"{error}",
                flush=True,
            )
            connection_monitor_warning_shown = True
        return

    current_connections = set()

    for connection in connections:
        pid = connection.pid

        local_address = (
            f"{connection.laddr.ip}:{connection.laddr.port}"
            if connection.laddr
            else "N/A"
        )
        remote_address = (
            f"{connection.raddr.ip}:{connection.raddr.port}"
            if connection.raddr
            else "N/A"
        )

        connection_key = (
            pid,
            local_address,
            remote_address,
            connection.status,
        )
        current_connections.add(connection_key)

        if connection_key not in known_connections:
            process_name = "Unknown"

            if pid is not None:
                try:
                    process_name = psutil.Process(pid).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    pass

            if connection.status == "LISTEN":
                alert_manager.record_event(
                    "LISTENING_CONNECTION",
                    pid,
                    process_name,
                    f"Local={local_address}"
                )

            elif connection.raddr:
                alert_manager.record_event(
                    "NEW_TCP_CONNECTION",
                    pid,
                    process_name,
                    f"Local={local_address} Remote={remote_address} "
                    f"Status={connection.status}"
                )
    known_connections = current_connections


def monitor_loop(stop_event, on_cycle=None):

    if not internet_is_available():
        print("Internet connection required. Process monitoring cannot be started.", flush=True)
        return

    print("Cybersecurity OS Agent - Integrated Monitor", flush=True)
    print("Monitoring processes and TCP connections.", flush=True)

    # Prime CPU counters
    for process in psutil.process_iter():
        try:
            process.cpu_percent(interval=None)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass

    while not stop_event.is_set():

        if internet_loss_confirmed():
            print("Internet status unavailable or disconnected; process monitoring stopped.", flush=True)
            stop_event.set()
            break

        monitor_processes()
        monitor_connections()

        # Notify supervisor that one monitoring cycle completed
        if on_cycle:
            on_cycle()

        # Wait while allowing the supervisor to stop us immediately
        if stop_event.wait(Poll_Interval):
            break

    print("[PROCESS MONITOR STOPPED]", flush=True)


def main():

    import threading

    stop_event = threading.Event()

    try:
        monitor_loop(stop_event)

    except KeyboardInterrupt:
        stop_event.set()
        print("\nMonitoring stopped safely.", flush=True)


if __name__ == "__main__":
    main()
