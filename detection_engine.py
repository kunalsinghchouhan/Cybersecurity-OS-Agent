def detect_process_events(pid, name, cpu, memory_mb):
    events = []

    if cpu > 80:
        events.append({
            "pid": pid,
            "process": name,
            "type": "HIGH_CPU",
            "description": f"CPU usage is {cpu:.2f}%",
            "risk_points": 25
        })

    if memory_mb > 500:
        events.append({
            "pid": pid,
            "process": name,
            "type": "HIGH_MEMORY",
            "description": f"Memory usage is {memory_mb:.2f} MB",
            "risk_points": 25
        })

    return events


# ---------------- NETWORK THREAT DETECTION ----------------

def detect_port_scan(source_ip, unique_ports, window_seconds):
    events = []

    if unique_ports >= 15 and window_seconds <= 10:
        events.append({
            "pid": None,
            "process": "NETWORK",
            "type": "NETWORK_PORT_SCAN",
            "description": (
                f"Possible port scan detected from {source_ip}. "
                f"{unique_ports} different ports targeted "
                f"within {window_seconds} seconds."
            ),
            "risk_points": 70
        })

    return events


def detect_high_network_traffic(source_ip, bytes_per_second,
                                threshold=5000000):
    events = []

    if bytes_per_second > threshold:
        events.append({
            "pid": None,
            "process": "NETWORK",
            "type": "HIGH_NETWORK_TRAFFIC",
            "description": (
                f"High network traffic detected from {source_ip}. "
                f"Traffic rate: {bytes_per_second / 1000000:.2f} MB/s"
            ),
            "risk_points": 30
        })

    return events
