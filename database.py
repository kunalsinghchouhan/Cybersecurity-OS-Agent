import sqlite3
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime


# ==================================================
# CONFIGURATION
# ==================================================

DB_FILE = (
    Path(__file__).resolve().parent
    / "security_agent.db"
)

DATABASE_TIMEOUT = 15


# ==================================================
# DATABASE CONNECTION
# ==================================================

@contextmanager
def get_connection():

    connection = sqlite3.connect(
        DB_FILE,
        timeout=DATABASE_TIMEOUT
    )

    connection.row_factory = sqlite3.Row

    try:

        connection.execute(
            "PRAGMA busy_timeout = 15000"
        )

        connection.execute(
            "PRAGMA synchronous = NORMAL"
        )

        yield connection

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def initialize_database():

    with get_connection() as connection:

        cursor = connection.cursor()

        # ------------------------------------------
        # ENABLE SQLITE WAL MODE
        # ------------------------------------------

        try:

            cursor.execute(
                "PRAGMA journal_mode = WAL"
            )

        except sqlite3.OperationalError as error:

            print("WAL mode warning:", error)

        # ------------------------------------------
        # SECURITY ALERTS TABLE
        # ------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                pid INTEGER,
                process TEXT,

                event_type TEXT,
                description TEXT,

                risk_score INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'INFO',

                mitre_id TEXT,
                mitre_name TEXT,
                mitre_tactic TEXT,
                mitre_url TEXT,
                mitre_confidence TEXT,
                mitre_status TEXT,

                investigation_status TEXT DEFAULT 'New'
            )
        """)

        # ------------------------------------------
        # NETWORK PACKETS TABLE
        # ------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS NetworkPackets (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,
                timestamp_epoch REAL,

                source_ip TEXT,
                destination_ip TEXT,

                protocol TEXT,
                protocol_stack TEXT,
                transport TEXT,

                source_port INTEGER,
                destination_port INTEGER,

                packet_size INTEGER,
                captured_length INTEGER,

                tcp_flags TEXT,

                dns_query TEXT,

                payload_preview TEXT,
                payload_hex TEXT,

                source_mac TEXT,
                destination_mac TEXT,

                ip_version INTEGER,
                ether_type TEXT,

                layers TEXT,

                packet_summary TEXT,
                packet_details TEXT,
                protocol_fields TEXT,

                raw_hex TEXT,
                ascii_dump TEXT,

                interface TEXT
            )
        """)

        # ==================================================
        # ALERT TABLE MIGRATIONS
        # ==================================================

        alert_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(Alerts)"
            ).fetchall()
        }

        alert_migrations = {

            "timestamp": "TEXT",
            "pid": "INTEGER",
            "process": "TEXT",

            "event_type": "TEXT",
            "description": "TEXT",

            "risk_score": "INTEGER DEFAULT 0",
            "severity": "TEXT DEFAULT 'INFO'",

            "mitre_id": "TEXT",
            "mitre_name": "TEXT",
            "mitre_tactic": "TEXT",
            "mitre_url": "TEXT",
            "mitre_confidence": "TEXT",
            "mitre_status": "TEXT",

            "investigation_status": "TEXT DEFAULT 'New'"
        }

        for column, definition in alert_migrations.items():

            if column not in alert_columns:

                cursor.execute(
                    f"ALTER TABLE Alerts ADD COLUMN "
                    f"{column} {definition}"
                )

        # ------------------------------------------
        # SUPPORT OLD ALERT DATABASES
        # ------------------------------------------

        alert_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(Alerts)"
            ).fetchall()
        }

        if "type" in alert_columns:

            cursor.execute("""
                UPDATE Alerts
                SET event_type = type
                WHERE event_type IS NULL
                   OR event_type = ''
            """)

        # ==================================================
        # NETWORK PACKET TABLE MIGRATIONS
        # ==================================================

        packet_migrations = {

            "timestamp": "TEXT",
            "timestamp_epoch": "REAL",

            "source_ip": "TEXT",
            "destination_ip": "TEXT",

            "protocol": "TEXT",
            "protocol_stack": "TEXT",
            "transport": "TEXT",

            "source_port": "INTEGER",
            "destination_port": "INTEGER",

            "packet_size": "INTEGER",
            "captured_length": "INTEGER",

            "tcp_flags": "TEXT",

            "dns_query": "TEXT",

            "payload_preview": "TEXT",
            "payload_hex": "TEXT",

            "source_mac": "TEXT",
            "destination_mac": "TEXT",

            "ip_version": "INTEGER",
            "ether_type": "TEXT",

            "layers": "TEXT",

            "packet_summary": "TEXT",
            "packet_details": "TEXT",
            "protocol_fields": "TEXT",

            "raw_hex": "TEXT",
            "ascii_dump": "TEXT",

            "interface": "TEXT"
        }

        packet_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(NetworkPackets)"
            ).fetchall()
        }

        for column, definition in packet_migrations.items():

            if column not in packet_columns:

                cursor.execute(
                    f"ALTER TABLE NetworkPackets ADD COLUMN "
                    f"{column} {definition}"
                )

        # ==================================================
        # DATABASE INDEXES
        # ==================================================

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_timestamp
            ON Alerts(timestamp)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_severity
            ON Alerts(severity)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_event_type
            ON Alerts(event_type)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_network_timestamp
            ON NetworkPackets(timestamp_epoch)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_network_source_ip
            ON NetworkPackets(source_ip)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_network_destination_ip
            ON NetworkPackets(destination_ip)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_network_protocol
            ON NetworkPackets(protocol)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_network_dns
            ON NetworkPackets(dns_query)
        """)

        connection.commit()

    print("[DATABASE] Initialization completed.")


# ==================================================
# SAVE SECURITY ALERT
# ==================================================

def save_alert(alert):

    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary.")

    event_type = alert.get(
        "event_type",
        alert.get("type", "UNKNOWN")
    )

    timestamp = alert.get("timestamp")

    if not timestamp:

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO Alerts (

                timestamp,
                pid,
                process,

                event_type,
                description,

                risk_score,
                severity,

                mitre_id,
                mitre_name,
                mitre_tactic,
                mitre_url,
                mitre_confidence,
                mitre_status,

                investigation_status
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (

            timestamp,
            alert.get("pid"),
            alert.get("process"),

            event_type,
            alert.get("description", ""),

            alert.get("risk_score", 0),
            alert.get("severity", "INFO"),

            alert.get("mitre_id"),
            alert.get("mitre_name"),
            alert.get("mitre_tactic"),
            alert.get("mitre_url"),
            alert.get("mitre_confidence"),
            alert.get("mitre_status"),

            alert.get("investigation_status", "New")
        ))

        return cursor.lastrowid


# ==================================================
# RETRIEVE SECURITY ALERTS
# ==================================================

def get_recent_alerts(limit=100):

    limit = max(1, min(int(limit), 10000))

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM Alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return [
            dict(row)
            for row in cursor.fetchall()
        ]


# ==================================================
# RETRIEVE SINGLE ALERT
# ==================================================

def get_alert_by_id(alert_id):

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM Alerts
            WHERE id = ?
        """, (alert_id,))

        row = cursor.fetchone()

        return dict(row) if row else None


# ==================================================
# UPDATE INVESTIGATION STATUS
# ==================================================

def update_investigation_status(alert_id, status):

    allowed_statuses = {

        "New",
        "Under Investigation",
        "Resolved",
        "False Positive"
    }

    if status not in allowed_statuses:
        raise ValueError("Invalid investigation status.")

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            UPDATE Alerts
            SET investigation_status = ?
            WHERE id = ?
        """, (status, alert_id))

        return cursor.rowcount > 0


# ==================================================
# DELETE ALERT
# ==================================================

def delete_alert(alert_id):

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            DELETE FROM Alerts
            WHERE id = ?
        """, (alert_id,))

        return cursor.rowcount > 0


# ==================================================
# SAVE NETWORK PACKET
# ==================================================

def save_network_packet(packet_data):

    if not isinstance(packet_data, dict):
        raise TypeError(
            "Network packet data must be a dictionary."
        )

    # Only these known database columns can be inserted.
    columns = [

        "timestamp",
        "timestamp_epoch",

        "source_ip",
        "destination_ip",

        "protocol",
        "protocol_stack",
        "transport",

        "source_port",
        "destination_port",

        "packet_size",
        "captured_length",

        "tcp_flags",

        "dns_query",

        "payload_preview",
        "payload_hex",

        "source_mac",
        "destination_mac",

        "ip_version",
        "ether_type",

        "layers",

        "packet_summary",
        "packet_details",
        "protocol_fields",

        "raw_hex",
        "ascii_dump",

        "interface"
    ]

    # Preserve compatibility with older packet records.
    values = [
        packet_data.get(column)
        for column in columns
    ]

    placeholders = ", ".join(
        ["?"] * len(columns)
    )

    column_names = ", ".join(columns)

    query = f"""
        INSERT INTO NetworkPackets (
            {column_names}
        )
        VALUES (
            {placeholders}
        )
    """

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute(query, values)

        return cursor.lastrowid


# ==================================================
# RETRIEVE NETWORK PACKETS
# ==================================================

def get_recent_network_packets(limit=1000):

    limit = max(1, min(int(limit), 50000))

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM NetworkPackets
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return [
            dict(row)
            for row in cursor.fetchall()
        ]


# ==================================================
# RETRIEVE NETWORK PACKET BY ID
# ==================================================

def get_network_packet_by_id(packet_id):

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM NetworkPackets
            WHERE id = ?
        """, (packet_id,))

        row = cursor.fetchone()

        return dict(row) if row else None


# ==================================================
# NETWORK PACKET COUNT
# ==================================================

def get_network_packet_count():

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM NetworkPackets
        """)

        row = cursor.fetchone()

        return row["total"] if row else 0


# ==================================================
# NETWORK PROTOCOL STATISTICS
# ==================================================

def get_network_protocol_stats():

    with get_connection() as connection:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                protocol,
                COUNT(*) AS packet_count,
                SUM(packet_size) AS total_bytes

            FROM NetworkPackets

            GROUP BY protocol

            ORDER BY packet_count DESC
        """)

        return [
            dict(row)
            for row in cursor.fetchall()
        ]


# ==================================================
# DATABASE INITIALIZATION ON IMPORT
# ==================================================

initialize_database()
