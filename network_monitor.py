from scapy.sendrecv import AsyncSniffer
from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from collections import defaultdict, deque, Counter
from datetime import datetime
from threading import RLock
import time
import json
import ctypes
import sys

from MITRE_mapping import enrich_event_with_mitre

from database import (
    initialize_database,
    save_alert,
    save_network_packet
)

from detection_engine import (
    detect_port_scan,
    detect_high_network_traffic
)

from risk_engine import calculate_risk
from app_paths import get_app_paths


# ==================================================
# CONFIGURATION
# ==================================================

SCAN_WINDOW = 10
SCAN_THRESHOLD = 15

TRAFFIC_WINDOW = 10
TRAFFIC_THRESHOLD = 5000000

ALERT_COOLDOWN = 60
DNS_COOLDOWN = 10

MAX_RAW_BYTES = 2048
MAX_DETAILS_LENGTH = 12000

LOG_FILE = get_app_paths().security_log


# ==================================================
# MONITORING STATE
# ==================================================

packet_counts = Counter()
byte_counts = Counter()

port_history = defaultdict(deque)
traffic_history = defaultdict(deque)

last_alert_time = {}
last_dns_time = {}

last_stats_time = time.monotonic()

network_sniffer = None
network_monitor_running = False
network_monitor_error = None

monitor_lock = RLock()


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def safe_text(value):

    try:

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")

        return str(value)

    except Exception:

        return "UNAVAILABLE"


def serialize_value(value):

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    if isinstance(value, (list, tuple)):
        return [serialize_value(item) for item in value]

    try:
        return str(value)

    except Exception:
        return "UNAVAILABLE"


def get_packet_layers(packet):

    try:

        return [
            layer.__name__
            for layer in packet.layers()
        ]

    except Exception:
        return []


def get_packet_details(packet):

    try:

        details = packet.show(dump=True)

        return details[:MAX_DETAILS_LENGTH]

    except Exception as error:

        return f"Packet dissection error: {error}"


def get_protocol_name(packet, layers):

    layer_names = set(layers)

    priority = [
        "DNS",
        "BOOTP",
        "DHCP",
        "ARP",
        "ICMPv6EchoRequest",
        "ICMPv6EchoReply",
        "ICMPv6ND_NS",
        "ICMPv6ND_NA",
        "ICMPv6ND_RS",
        "ICMPv6ND_RA",
        "ICMP",
        "IGMP",
        "GRE",
        "ESP"
    ]

    for name in priority:

        if name in layer_names:

            if name == "BOOTP":
                return "DHCP"

            return name

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    if IP in packet:
        return "IPv4"

    if IPv6 in packet:
        return "IPv6"

    if ARP in packet:
        return "ARP"

    if Ether in packet:
        return "Ethernet"

    if layers:
        return layers[-1]

    return "OTHER"


def get_packet_addresses(packet):

    source_ip = "Unknown"
    destination_ip = "Unknown"

    source_mac = None
    destination_mac = None

    if Ether in packet:

        source_mac = packet[Ether].src
        destination_mac = packet[Ether].dst

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:

        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    elif ARP in packet:

        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst

        source_mac = packet[ARP].hwsrc
        destination_mac = packet[ARP].hwdst

    return (
        source_ip,
        destination_ip,
        source_mac,
        destination_mac
    )


def get_payload_data(packet):

    try:

        if Raw in packet:
            payload = bytes(packet[Raw].load)

        else:
            payload = bytes(packet.payload)

        preview_bytes = payload[:100]

        payload_preview = preview_bytes.decode(
            "utf-8",
            errors="replace"
        )

        payload_hex = preview_bytes.hex(" ")

        return payload_preview, payload_hex

    except Exception:

        return "", ""


def get_hex_dump(raw_packet):

    captured = raw_packet[:MAX_RAW_BYTES]

    return captured.hex(" ")


def get_ascii_dump(raw_packet):

    captured = raw_packet[:MAX_RAW_BYTES]

    return "".join(
        chr(byte) if 32 <= byte <= 126 else "."
        for byte in captured
    )


def get_protocol_fields(packet):

    result = {}

    try:

        for layer in packet.layers():

            layer_name = layer.__name__
            layer_object = packet.getlayer(layer)

            if layer_object is None:
                continue

            fields = {}

            for field_name, value in layer_object.fields.items():

                fields[field_name] = serialize_value(value)

            result[layer_name] = fields

    except Exception as error:

        result["dissection_error"] = str(error)

    return json.dumps(
        result,
        indent=2,
        ensure_ascii=False
    )


# ==================================================
# LOG EVENT
# ==================================================

def write_log(message):

    try:

        with LOG_FILE.open(
            "a",
            encoding="utf-8"
        ) as log_file:

            log_file.write(message + "\n")

    except OSError as error:

        print("Log writing error:", error)


# ==================================================
# GENERATE SECURITY ALERT
# ==================================================

def generate_alert(
    event_type,
    source_ip,
    description,
    risk_score,
    severity
):

    key = f"{event_type}:{source_ip}"
    now = time.monotonic()

    if now - last_alert_time.get(key, 0) < ALERT_COOLDOWN:
        return

    last_alert_time[key] = now

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    alert = {
        "timestamp": timestamp,
        "pid": None,
        "process": "NETWORK",
        "type": event_type,
        "description": description,
        "risk_score": risk_score,
        "severity": severity
    }

    try:

        alert = enrich_event_with_mitre(alert)

        save_alert(alert)

        write_log(
            f"[{timestamp}] {severity} {event_type} | "
            f"{description}"
        )

        print("\n" + "!" * 55)
        print("NETWORK SECURITY ALERT")
        print("Event       :", event_type)
        print("Severity    :", severity)
        print("Risk Score  :", risk_score)
        print("MITRE ID    :", alert.get("mitre_id", "Not mapped"))
        print("MITRE Name  :", alert.get("mitre_name", "Not mapped"))
        print("Description :", description)
        print("!" * 55)

    except Exception as error:

        print("Alert storage error:", error)


# ==================================================
# RECORD DNS EVENT
# ==================================================

def record_dns_event(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    domain
):

    now = time.monotonic()
    key = f"{source_ip}:{domain}"

    if now - last_dns_time.get(key, 0) < DNS_COOLDOWN:
        return

    last_dns_time[key] = now

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    description = (
        f"DNS query for {domain} | "
        f"Source: {source_ip}:{source_port} | "
        f"Destination: {destination_ip}:{destination_port}"
    )

    alert = {
        "timestamp": timestamp,
        "pid": None,
        "process": "NETWORK",
        "type": "DNS_QUERY",
        "description": description,
        "risk_score": 0,
        "severity": "INFO"
    }

    try:

        save_alert(alert)

        write_log(
            f"[{timestamp}] INFO DNS_QUERY | "
            f"{description}"
        )

        print("\n[DNS EVENT SAVED]")
        print("Domain:", domain)

    except Exception as error:

        print("DNS recording error:", error)


# ==================================================
# PROCESS DETECTION EVENTS
# ==================================================

def process_detection_events(events, source_ip):

    if not events:
        return

    for event in events:

        try:

            risk_score, severity = calculate_risk([event])

            generate_alert(
                event_type=event["type"],
                source_ip=source_ip,
                description=event["description"],
                risk_score=risk_score,
                severity=severity
            )

        except Exception as error:

            print("Detection processing error:", error)


# ==================================================
# ANALYZE EVERY CAPTURED PACKET
# ==================================================

def analyze_packet(packet):

    global last_stats_time

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    timestamp_epoch = time.time()

    try:

        # ------------------------------------------
        # BASIC PACKET INFORMATION
        # ------------------------------------------

        layers = get_packet_layers(packet)

        protocol = get_protocol_name(
            packet,
            layers
        )

        (
            source_ip,
            destination_ip,
            source_mac,
            destination_mac
        ) = get_packet_addresses(packet)

       

        source_port = None
        destination_port = None
        tcp_flags = None

        ip_version = None
        ether_type = None

        if IP in packet:
            ip_version = 4

        elif IPv6 in packet:
            ip_version = 6

        if Ether in packet:
            ether_type = hex(packet[Ether].type)

        # ------------------------------------------
        # TRANSPORT INFORMATION
        # ------------------------------------------

        if TCP in packet:

            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)

            transport = "TCP"

        elif UDP in packet:

            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

            transport = "UDP"

        elif ICMP in packet:

            transport = "ICMP"

        else:

            transport = "OTHER"

        # ------------------------------------------
        # PACKET SIZE AND RAW DATA
        # ------------------------------------------

        raw_packet = bytes(packet)

        packet_size = len(raw_packet)

        raw_hex = get_hex_dump(raw_packet)
        ascii_dump = get_ascii_dump(raw_packet)

        payload_preview, payload_hex = get_payload_data(
            packet
        )

        packet_summary = safe_text(packet.summary())

        packet_details = get_packet_details(packet)

        protocol_fields = get_protocol_fields(packet)

        # ------------------------------------------
        # PROTOCOL STATISTICS
        # ------------------------------------------

        packet_counts[protocol] += 1
        byte_counts[protocol] += packet_size

        # ------------------------------------------
        # DNS EXTRACTION
        # ------------------------------------------

        dns_domain = None

        if DNS in packet and DNSQR in packet:

            try:

                dns = packet[DNS]

                if dns.qr == 0:

                    qname = packet[DNSQR].qname

                    if isinstance(qname, bytes):

                        dns_domain = qname.decode(
                            "utf-8",
                            errors="replace"
                        ).rstrip(".")

                    else:

                        dns_domain = str(qname).rstrip(".")

            except Exception as error:

                print("DNS parsing error:", error)

        # ------------------------------------------
        # SAVE EVERY PACKET TO SQLITE
        # ------------------------------------------

        packet_record = {

            "timestamp": timestamp,
            "timestamp_epoch": timestamp_epoch,

            "source_ip": source_ip,
            "destination_ip": destination_ip,

            "protocol": protocol,
            "protocol_stack": ", ".join(layers),
            "layers": ", ".join(layers),

            "source_port": source_port,
            "destination_port": destination_port,

            "packet_size": packet_size,
            "captured_length": packet_size,

            "tcp_flags": tcp_flags,

            "dns_query": dns_domain,

            "payload_preview": payload_preview,
            "payload_hex": payload_hex,

            "source_mac": source_mac,
            "destination_mac": destination_mac,

            "ip_version": ip_version,
            "ether_type": ether_type,

            "transport": transport,

            "packet_summary": packet_summary,
            "packet_details": packet_details,
            "protocol_fields": protocol_fields,

            "raw_hex": raw_hex,
            "ascii_dump": ascii_dump,

            "interface": str(conf.iface)
        }

        try:

            save_network_packet(packet_record)

        except Exception as error:

            print("Network packet storage error:", error)

        # ------------------------------------------
        # DISPLAY PACKET
        # ------------------------------------------

        print("\n" + "-" * 70)

        print("Timestamp       :", timestamp)
        print("Protocol        :", protocol)
        print("Packet Size     :", packet_size, "bytes")

        print("Source IP       :", source_ip)
        print("Destination IP  :", destination_ip)

        print("Source MAC      :", source_mac)
        print("Destination MAC :", destination_mac)

        print("Protocol Layers :", " -> ".join(layers))

        if source_port is not None:
            print("Source Port     :", source_port)

        if destination_port is not None:
            print("Destination Port:", destination_port)

        if tcp_flags:
            print("TCP Flags       :", tcp_flags)

        if dns_domain:

            print("\n[DNS QUERY DETECTED]")
            print("Requested Domain:", dns_domain)

            record_dns_event(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                dns_domain
            )

        print("\nPacket Summary:")
        print(packet_summary)

        print("-" * 70)

        # ==================================================
        # SECURITY DETECTIONS
        # ==================================================

        current_time = time.monotonic()

        # ------------------------------------------
        # PORT SCAN DETECTION
        # ------------------------------------------

        if TCP in packet and source_ip != "Unknown":

            tcp_flags_value = int(packet[TCP].flags)

            syn_only = (
                (tcp_flags_value & 0x02) != 0
                and (tcp_flags_value & 0x10) == 0
            )

            if syn_only:

                history = port_history[source_ip]

                history.append(
                    (current_time, destination_port)
                )

                while (
                    history
                    and current_time - history[0][0] > SCAN_WINDOW
                ):

                    history.popleft()

                unique_ports = len({
                    port for _, port in history
                })

                actual_window = (
                    current_time - history[0][0]
                    if history else 0
                )

                if unique_ports >= SCAN_THRESHOLD:

                    events = detect_port_scan(
                        source_ip,
                        unique_ports,
                        actual_window
                    )

                    process_detection_events(
                        events,
                        source_ip
                    )

        # ------------------------------------------
        # HIGH NETWORK TRAFFIC DETECTION
        # ------------------------------------------

        if source_ip != "Unknown":

            history = traffic_history[source_ip]

            history.append(
                (current_time, packet_size)
            )

            while (
                history
                and current_time - history[0][0] > TRAFFIC_WINDOW
            ):

                history.popleft()

            if history:

                total_bytes = sum(
                    size for _, size in history
                )

                elapsed = max(
                    current_time - history[0][0],
                    1
                )

                bytes_per_second = total_bytes / elapsed

                events = detect_high_network_traffic(
                    source_ip,
                    bytes_per_second,
                    TRAFFIC_THRESHOLD
                )

                process_detection_events(
                    events,
                    source_ip
                )

        # ------------------------------------------
        # PERIODIC STATISTICS
        # ------------------------------------------

        if current_time - last_stats_time >= 30:

            print("\n========== NETWORK STATISTICS ==========")

            for proto, count in packet_counts.most_common():

                print(
                    f"{proto}: "
                    f"{count} packets | "
                    f"{byte_counts[proto]} bytes"
                )

            print("========================================")

            last_stats_time = current_time

    except Exception as error:

        print("Packet analysis error:", error)


# ==================================================
# START NETWORK MONITOR
# ==================================================

def start_network_monitor():

    global network_sniffer
    global network_monitor_running
    global network_monitor_error

    with monitor_lock:

        if network_monitor_running:
            return False, "Network monitoring is already running."

        if network_sniffer is not None:

            try:

                if network_sniffer.running:
                    return False, "Network monitoring is already running."

            except Exception:
                pass

            network_sniffer = None

        try:

            if sys.platform == "win32":
                try:
                    ctypes.WinDLL("wpcap.dll")
                except OSError as dependency_error:
                    raise RuntimeError(
                        "Windows packet capture is unavailable. Install Npcap "
                        "with WinPcap API-compatible mode enabled, then restart "
                        "Cybersecurity OS Agent. Packet capture may also require "
                        "the Npcap service to allow this user to access the driver. "
                        f"Details: {dependency_error}"
                    ) from dependency_error

            print("\n" + "=" * 60)
            print(" CYBERSECURITY OS AGENT - ADVANCED NETWORK MONITOR")
            print("=" * 60)

            print("Interface:", conf.iface)
            print("Capture Mode: ALL PACKETS")
            print("Capture Filter: NONE")

            print(
                "Analysis: Ethernet | ARP | IPv4 | IPv6 | "
                "TCP | UDP | ICMP | DNS | DHCP | Other"
            )

            print(
                "Detection: Port Scanning | High Network Traffic"
            )

            print(
                "Storage: SQLite NetworkPackets + Alerts"
            )

            print("Log File:", LOG_FILE)

            initialize_database()

            network_monitor_error = None

            network_sniffer = AsyncSniffer(
                iface=conf.iface,
                prn=analyze_packet,
                store=False
            )

            network_sniffer.start()

            time.sleep(0.5)

            if not network_sniffer.running:

                network_sniffer = None

                raise RuntimeError(
                    "Packet capture did not enter the running state."
                )

            network_monitor_running = True

            print("[NETWORK MONITOR STARTED]")

            return True, "Network monitoring started successfully."

        except Exception as error:

            network_sniffer = None
            network_monitor_running = False
            network_monitor_error = str(error)

            print("Network monitoring startup error:", error)

            return False, str(error)


# ==================================================
# STOP NETWORK MONITOR
# ==================================================

def stop_network_monitor():

    global network_sniffer
    global network_monitor_running

    with monitor_lock:

        if network_sniffer is None:

            network_monitor_running = False

            return True, "Network monitoring is already stopped."

        try:

            if network_sniffer.running:
                # Some Windows capture drivers can block while waiting for a
                # packet. Request Scapy's break loop without an unbounded join.
                network_sniffer.stop(join=False)
                capture_thread = getattr(network_sniffer, "thread", None)
                if capture_thread is not None:
                    capture_thread.join(timeout=5)
                    if capture_thread.is_alive():
                        raise TimeoutError(
                            "Packet capture did not stop within 5 seconds. "
                            "Check the Npcap service and capture permissions."
                        )

            network_sniffer = None
            network_monitor_running = False

            print("[NETWORK MONITOR STOPPED]")

            return True, "Network monitoring stopped successfully."

        except Exception as error:

            network_monitor_running = False
            network_monitor_error = str(error)

            print("Network shutdown error:", error)

            return False, str(error)


# ==================================================
# NETWORK MONITOR STATUS
# ==================================================

def get_network_monitor_status():

    global network_monitor_running
    global network_monitor_error

    with monitor_lock:

        if network_sniffer is not None:

            try:

                network_monitor_running = network_sniffer.running

            except Exception:

                network_monitor_running = False
                if getattr(network_sniffer, "exception", None) is not None:
                    network_monitor_error = str(network_sniffer.exception)

        else:

            network_monitor_running = False

        return {
            "running": network_monitor_running,
            "error": network_monitor_error
        }


# ==================================================
# STANDALONE EXECUTION
# ==================================================

if __name__ == "__main__":

    success, message = start_network_monitor()

    print(message)

    if success:

        try:

            while get_network_monitor_status()["running"]:
                time.sleep(1)

        except KeyboardInterrupt:

            print("\nStopping network monitoring...")

        finally:

            stop_network_monitor()
