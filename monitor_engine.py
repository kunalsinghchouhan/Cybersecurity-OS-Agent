import time
import psutil
from datetime import datetime
from pathlib import Path
from detection_engine import detect_process_events
from risk_engine import calculate_risk
from alert_manager import AlertManager

CPU_Threshold = 80
Memory_Threshold = 500
Poll_Interval = 3
Alert_Cooldown = 60

Log_File = Path(__file__).with_name("security_events.log")

# last_alerts = {}
alert_manager = AlertManager(cooldown=Alert_Cooldown)
known_connections = set()

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
    global known_connections

    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError) as error:
        print(f"Unable to read TCP connections: {error}", flush=True)
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


def main():
    print("Cybersecurity OS Agent - Integrated Monitor")
    print("Monitoring processes and TCP connections.")
    print("Press Ctrl+C to stop.\n")

    # Prime CPU counters so the first reading is not treated as a real measurement.
    for process in psutil.process_iter():
        try:
            process.cpu_percent(interval=None)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass

    try:
        while True:
            monitor_processes()
            monitor_connections()
            time.sleep(Poll_Interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped safely.", flush=True)


if __name__ == "__main__":
    main()
