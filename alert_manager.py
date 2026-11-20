
import time
import json
from datetime import datetime
from pathlib import Path

from database import initialize_database, save_alert
from MITRE_mapping import enrich_event_with_mitre


class AlertManager:

    def __init__(self, cooldown=60):
        self.cooldown = cooldown
        self.last_alerts = {}

        self.log_file = Path(__file__).with_name("security_events.log")
        self.json_file = Path(__file__).with_name("security_events.json")

        initialize_database()

    # --------------------------------------------------
    # JSON STORAGE
    # --------------------------------------------------

    def save_to_json(self, event):

        alerts = []

        if self.json_file.exists():
            try:
                with self.json_file.open("r", encoding="utf-8") as file:
                    alerts = json.load(file)

                if not isinstance(alerts, list):
                    raise ValueError("JSON root must be a list")

            except (json.JSONDecodeError, OSError, ValueError) as error:
                print(f"[JSON ERROR] Could not read existing events: {error}")
                return False

        alerts.append(event)

        try:
            with self.json_file.open("w", encoding="utf-8") as file:
                json.dump(
                    alerts,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            return True

        except OSError as error:
            print(f"[JSON ERROR] Could not save event: {error}")
            return False

    # --------------------------------------------------
    # LOG STORAGE
    # --------------------------------------------------

    def write_log(self, message):

        try:
            with self.log_file.open("a", encoding="utf-8") as file:
                file.write(message + "\n")

        except OSError as error:
            print(f"[LOG ERROR] {error}")

    # --------------------------------------------------
    # SEND SECURITY ALERT
    # --------------------------------------------------

    def send_alert(self, event, score, severity):

        key = (event["pid"], event["type"])
        now = time.monotonic()

        previous = self.last_alerts.get(key)

        if previous is not None and now - previous < self.cooldown:
            return

        self.last_alerts[key] = now

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert = {
            "timestamp": timestamp,
            "pid": event["pid"],
            "process": event["process"],
            "type": event["type"],
            "description": event["description"],
            "risk_score": score,
            "severity": severity
        }

        # MITRE ATT&CK enrichment
        alert = enrich_event_with_mitre(alert)

        message = (
            f"[{timestamp}] {severity} | {event['type']} | "
            f"Process={event['process']} | PID={event['pid']} | "
            f"{event['description']} | Risk Score={score}"
        )

        print(message, flush=True)

        # Save to log file
        self.write_log(message)

        # Save to SQLite database
        try:
            save_alert(alert)
        except Exception as error:
            print(f"[DATABASE ERROR] {error}")

        # Save to JSON
        self.save_to_json(alert)

    # --------------------------------------------------
    # RECORD INFORMATIONAL EVENTS
    # --------------------------------------------------

    def record_event(self, event_type, pid, process, description):

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        event = {
            "timestamp": timestamp,
            "pid": pid,
            "process": process,
            "type": event_type,
            "description": description,
            "risk_score": 0,
            "severity": "INFO"
        }

        # MITRE ATT&CK enrichment
        event = enrich_event_with_mitre(event)

        message = (
            f"[{timestamp}] INFO | {event_type} | "
            f"Process={process} | PID={pid} | {description}"
        )

        print(message, flush=True)

        # Save to log file
        self.write_log(message)

        # Save to SQLite database
        try:
            save_alert(event)
        except Exception as error:
            print(f"[DATABASE ERROR] {error}")

        # Save to JSON
        self.save_to_json(event)
