import json
import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from agent_controller import (
    start_agent,
    stop_agent,
    get_agent_status
)

from database import (
    initialize_database,
    get_recent_alerts,
    get_recent_network_packets,
    update_investigation_status
)

from MITRE_mapping import get_mitre_mapping
from ai_analyzer import analyze_alert

from connectivity_monitor import (
    start_connectivity_monitor,
    get_internet_status
)

from auth import (
    init_auth_db,
    get_current_user,
    render_auth_page,
    logout_user
)


# ==================================================
# 1. PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Cybersecurity OS Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Authentication
init_auth_db()
current_user = get_current_user()

if current_user is None:
    render_auth_page()
    st.stop()

# Initialize security database after authentication
initialize_database()
if "connectivity_started" not in st.session_state:

    start_connectivity_monitor()

    st.session_state.connectivity_started = True

# ==================================================
# INTERNET CONNECTION ERROR DISPLAY
# ==================================================

internet = get_internet_status()

if internet["status"] == "OFFLINE":

    st.error(
        "Internet Connection Lost! "
        "Please check your internet connection and try again."
    )

elif internet["status"] == "UNKNOWN":

    st.warning("Checking internet connectivity...")

else:

    st.success("Internet Connection: Connected")

# ==================================================
# 2. CUSTOM CSS
# ==================================================

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #263247;
}

[data-testid="stMetric"] {
    background-color: #111c30;
    border: 1px solid #263247;
    padding: 16px;
    border-radius: 12px;
}

[data-testid="stMetricLabel"] {
    color: #94a3b8;
}

[data-testid="stMetricValue"] {
    color: #38bdf8;
}

div.stButton > button {
    border-radius: 8px;
    border: 1px solid #334155;
    font-weight: 600;
}

div.stButton > button:hover {
    border-color: #38bdf8;
    color: #38bdf8;
}

.section-description {
    color: #94a3b8;
    font-size: 14px;
    margin-top: -10px;
    margin-bottom: 22px;
}

.main-header {
    font-size: 30px;
    font-weight: 750;
    color: #f8fafc;
}

.main-subtitle {
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 22px;
}
</style>
""", unsafe_allow_html=True)


# ==================================================
# 3. HELPER FUNCTIONS
# ==================================================

def section_header(title, description):
    st.title(title)

    st.markdown(
        f'<div class="section-description">{description}</div>',
        unsafe_allow_html=True
    )


def show_empty_message(message):
    st.info(message)


def format_agent_status(status):
    if isinstance(status, dict):
        return str(
            status.get(
                "status",
                status.get("running", status)
            )
        )

    return str(status)


def safe_value(value, fallback="N/A"):
    if value is None:
        return fallback

    try:
        if pd.isna(value):
            return fallback
    except (TypeError, ValueError):
        pass

    return value


def format_bytes(value):
    value = float(value or 0)

    if value < 1024:
        return f"{value:.0f} B"

    if value < 1024 ** 2:
        return f"{value / 1024:.2f} KB"

    if value < 1024 ** 3:
        return f"{value / (1024 ** 2):.2f} MB"

    return f"{value / (1024 ** 3):.2f} GB"


def format_mac(value):
    """
    Replace colons with hyphens for display.
    This avoids Streamlit interpreting sequences such as :cd:
    as emoji shortcodes in certain display contexts.
    """
    value = safe_value(value, "N/A")

    if value == "N/A":
        return value

    return str(value).replace(":", "-")


def searchable_text(row, columns):
    parts = []

    for column in columns:
        value = row.get(column, "")

        if value is not None:
            parts.append(str(value))

    return " ".join(parts).lower()


# ==================================================
# 4. LOAD DATABASE DATA
# ==================================================

try:
    alerts = get_recent_alerts(1000)
    packets = get_recent_network_packets(2000)

    alerts_df = pd.DataFrame(alerts)
    network_df = pd.DataFrame(packets)
    st.write("PROTOCOL DEBUG:")
    if not network_df.empty:
        st.write(network_df["protocol"].value_counts())
    else:
        st.write("No network packets found.")

except Exception as error:
    st.error(f"Database retrieval error: {error}")

    alerts_df = pd.DataFrame()
    network_df = pd.DataFrame()


# ==================================================
# 5. NORMALIZE ALERT DATA
# ==================================================

alert_defaults = {
    "id": None,
    "timestamp": "",
    "pid": None,
    "process": "",
    "event_type": "UNKNOWN",
    "description": "",
    "risk_score": 0,
    "severity": "INFO",
    "mitre_id": None,
    "mitre_name": None,
    "mitre_tactic": None,
    "mitre_url": None,
    "mitre_confidence": None,
    "mitre_status": None,
    "investigation_status": "New"
}

for column, default in alert_defaults.items():
    if column not in alerts_df.columns:
        alerts_df[column] = default


if not alerts_df.empty:

    alerts_df["risk_score"] = pd.to_numeric(
        alerts_df["risk_score"],
        errors="coerce"
    ).fillna(0)

    alerts_df["severity"] = (
        alerts_df["severity"]
        .fillna("INFO")
        .astype(str)
        .str.upper()
    )

    alerts_df["event_type"] = (
        alerts_df["event_type"]
        .fillna("UNKNOWN")
        .astype(str)
    )

    alerts_df["investigation_status"] = (
        alerts_df["investigation_status"]
        .fillna("New")
        .astype(str)
    )


# ==================================================
# 6. NORMALIZE NETWORK DATA
# ==================================================

network_defaults = {
    "id": None,
    "timestamp": "",
    "source_ip": "",
    "destination_ip": "",
    "protocol": "OTHER",
    "source_port": None,
    "destination_port": None,
    "packet_size": 0,
    "tcp_flags": "",
    "dns_query": "",
    "payload_preview": "",
    "payload_hex": "",
    "source_mac": "",
    "destination_mac": "",
    "ip_version": None,
    "ether_type": "",
    "layers": "",
    "packet_summary": "",
    "packet_details": "",
    "protocol_fields": "",
    "raw_hex": "",
    "ascii_dump": "",
    "captured_length": 0
}

for column, default in network_defaults.items():
    if column not in network_df.columns:
        network_df[column] = default


if not network_df.empty:

    network_df["packet_size"] = pd.to_numeric(
        network_df["packet_size"],
        errors="coerce"
    ).fillna(0)

    network_df["protocol"] = (
        network_df["protocol"]
        .fillna("OTHER")
        .astype(str)
        .str.upper()
    )


# ==================================================
# 7. SIDEBAR NAVIGATION
# ==================================================

st.sidebar.markdown("""
<div style="padding: 8px 0 18px 0;">
    <h2 style="color:#38bdf8; margin-bottom:0;">
        🛡️ CYBERSECURITY OS
    </h2>
    <span style="color:#94a3b8; font-size:12px;">
        SECURITY MONITORING PLATFORM
    </span>
</div>
""", unsafe_allow_html=True)

st.sidebar.caption(
    f"Signed in: {current_user['username']} · {current_user['role']}"
)

if st.sidebar.button("Log out", use_container_width=True):
    logout_user()
    st.rerun()

st.sidebar.divider()

selected_page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Overview",
        "Security Alerts",
        "Investigations",
        "MITRE ATT&CK",
        "Network Monitoring",
        "AI Analysis"
    ]
)


# ==================================================
# 8. AGENT CONTROL CENTER
# ==================================================

st.sidebar.divider()
st.sidebar.subheader("Agent Control")

try:
    current_agent_status = get_agent_status()
    status_text = format_agent_status(current_agent_status)

except Exception as error:
    status_text = f"Unavailable: {error}"

st.sidebar.caption("Current Agent Status")
st.sidebar.info(status_text)

if current_user["role"] == "Admin":

    control_col1, control_col2 = st.sidebar.columns(2)

    with control_col1:

        if st.button("▶ Start", use_container_width=True):

            try:
                success, message = start_agent()

                if success:
                    st.sidebar.success(message)
                else:
                    st.sidebar.warning(message)

                st.rerun()

            except Exception as error:
                st.sidebar.error(f"Start failed: {error}")

    with control_col2:

        if st.button("⏹ Stop", use_container_width=True):

            try:
                success, message = stop_agent()

                if success:
                    st.sidebar.success(message)
                else:
                    st.sidebar.warning(message)

                st.rerun()

            except Exception as error:
                st.sidebar.error(f"Stop failed: {error}")

else:
    st.sidebar.info(
        "Agent controls are available to Admin users only."
    )

st.sidebar.divider()

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.rerun()


# ==================================================
# 9. MAIN HEADER
# ==================================================

st.markdown(
    '<div class="main-header">Cybersecurity OS Agent</div>',
    unsafe_allow_html=True
)

st.markdown(
    f'<div class="main-subtitle">'
    f'Security Operations Center / {selected_page}'
    f'</div>',
    unsafe_allow_html=True
)


# ==================================================
# PAGE 1: OVERVIEW
# ==================================================

if selected_page == "Overview":

    section_header(
        "Security Overview",
        "Centralized summary of host activity, network traffic "
        "and detected security events."
    )

    total_alerts = len(alerts_df)
    total_packets = len(network_df)

    if total_alerts:

        high_alerts = int(
            (alerts_df["severity"] == "HIGH").sum()
        )

        medium_alerts = int(
            (alerts_df["severity"] == "MEDIUM").sum()
        )

        average_risk = round(
            alerts_df["risk_score"].mean(), 1
        )

        open_investigations = int(
            alerts_df["investigation_status"].isin(
                ["New", "Under Investigation"]
            ).sum()
        )

    else:
        high_alerts = 0
        medium_alerts = 0
        average_risk = 0
        open_investigations = 0

    metric1, metric2, metric3 = st.columns(3)

    metric1.metric("Total Security Alerts", total_alerts)
    metric2.metric("High Severity Alerts", high_alerts)
    metric3.metric("Average Risk Score", average_risk)

    metric4, metric5, metric6 = st.columns(3)

    metric4.metric("Network Packets", total_packets)
    metric5.metric("Open Investigations", open_investigations)
    metric6.metric("Medium Severity Alerts", medium_alerts)

    st.divider()

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        st.subheader("Alert Severity Distribution")

        if not alerts_df.empty:

            severity_data = (
                alerts_df["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )

            fig = px.pie(
                severity_data,
                names="Severity",
                values="Count",
                hole=0.5
            )

            fig.update_layout(template="plotly_dark")

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:
            show_empty_message("No alerts available.")

    with chart_col2:

        st.subheader("Risk Score Distribution")

        if not alerts_df.empty:

            fig = px.histogram(
                alerts_df,
                x="risk_score",
                nbins=10
            )

            fig.update_layout(template="plotly_dark")

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:
            show_empty_message("No risk data available.")

    st.divider()

    st.subheader("Latest Security Events")

    if not alerts_df.empty:

        columns = [
            "id",
            "timestamp",
            "process",
            "event_type",
            "severity",
            "risk_score",
            "investigation_status"
        ]

        st.dataframe(
            alerts_df[columns].head(10),
            use_container_width=True,
            hide_index=True
        )

    else:
        show_empty_message("No security events recorded.")

    st.subheader("Latest Network Activity")

    if not network_df.empty:

        columns = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "packet_size"
        ]

        st.dataframe(
            network_df[columns].head(10),
            use_container_width=True,
            hide_index=True
        )

    else:
        show_empty_message("No network packets captured.")


# ==================================================
# PAGE 2: SECURITY ALERTS
# ==================================================

elif selected_page == "Security Alerts":

    section_header(
        "Security Alerts",
        "Review detected security events, severity levels "
        "and risk scores."
    )

    if alerts_df.empty:

        show_empty_message("No security alerts recorded.")

    else:

        col1, col2 = st.columns(2)

        with col1:

            severity_options = sorted(
                alerts_df["severity"].unique().tolist()
            )

            selected_severities = st.multiselect(
                "Severity",
                severity_options,
                default=severity_options
            )

        with col2:

            event_options = sorted(
                alerts_df["event_type"].unique().tolist()
            )

            selected_events = st.multiselect(
                "Event Type",
                event_options,
                default=event_options
            )

        filtered_alerts = alerts_df[
            alerts_df["severity"].isin(selected_severities)
            & alerts_df["event_type"].isin(selected_events)
        ]

        columns = [
            "id",
            "timestamp",
            "pid",
            "process",
            "event_type",
            "description",
            "risk_score",
            "severity",
            "investigation_status"
        ]

        st.dataframe(
            filtered_alerts[columns],
            use_container_width=True,
            hide_index=True
        )

        st.divider()
        st.subheader("Alert Details")

        valid_alerts = filtered_alerts.dropna(
            subset=["id"]
        )

        if not valid_alerts.empty:

            options = {
                f"#{row['id']} | {row['event_type']} | {row['severity']}":
                row["id"]
                for _, row in valid_alerts.iterrows()
            }

            label = st.selectbox(
                "Select alert",
                list(options.keys())
            )

            alert_id = options[label]

            alert = valid_alerts[
                valid_alerts["id"] == alert_id
            ].iloc[0]

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Alert ID:**", alert["id"])
                st.write("**Timestamp:**", alert["timestamp"])
                st.write("**Event:**", alert["event_type"])

            with col2:
                st.write("**Severity:**", alert["severity"])
                st.write("**Risk Score:**", alert["risk_score"])
                st.write("**Process:**", alert["process"])

            st.write("**Description**")
            st.write(alert["description"])

        else:
            show_empty_message(
                "No valid alert IDs are available for details."
            )


# ==================================================
# PAGE 3: INVESTIGATIONS
# ==================================================

elif selected_page == "Investigations":

    section_header(
        "Alert Investigations",
        "Track alerts and manage their investigation lifecycle."
    )

    if alerts_df.empty:

        show_empty_message("No alerts available.")

    else:

        status_counts = alerts_df[
            "investigation_status"
        ].value_counts()

        cols = st.columns(4)

        statuses = [
            "New",
            "Under Investigation",
            "Resolved",
            "False Positive"
        ]

        for col, status in zip(cols, statuses):

            col.metric(
                status,
                int(status_counts.get(status, 0))
            )

        st.divider()

        status_filter = st.selectbox(
            "Filter investigations",
            ["All"] + statuses
        )

        if status_filter == "All":
            investigation_df = alerts_df.copy()

        else:
            investigation_df = alerts_df[
                alerts_df["investigation_status"] == status_filter
            ]

        st.dataframe(
            investigation_df[
                [
                    "id",
                    "timestamp",
                    "event_type",
                    "severity",
                    "risk_score",
                    "investigation_status"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

        st.divider()
        st.subheader("Update Investigation")

        valid_alerts = alerts_df.dropna(
            subset=["id"]
        )

        if not valid_alerts.empty:

            options = {
                f"#{row['id']} | {row['event_type']} | {row['severity']}":
                row["id"]
                for _, row in valid_alerts.iterrows()
            }

            label = st.selectbox(
                "Choose alert",
                list(options.keys()),
                key="investigation_alert"
            )

            alert_id = options[label]

            alert = valid_alerts[
                valid_alerts["id"] == alert_id
            ].iloc[0]

            st.write(
                "**Description:**",
                alert["description"]
            )

            allowed_statuses = [
                "New",
                "Under Investigation",
                "Resolved",
                "False Positive"
            ]

            current_status = alert["investigation_status"]

            if current_status not in allowed_statuses:
                current_status = "New"

            new_status = st.selectbox(
                "New status",
                allowed_statuses,
                index=allowed_statuses.index(current_status),
                key=f"status_{alert_id}"
            )

            if st.button("Update Status"):

                try:

                    updated = update_investigation_status(
                        alert_id,
                        new_status
                    )

                    if updated:
                        st.success("Status updated successfully.")
                        st.rerun()

                    else:
                        st.warning("No record was updated.")

                except Exception as error:
                    st.error(f"Update failed: {error}")

        else:
            show_empty_message(
                "No valid alert IDs available for investigation."
            )


# ==================================================
# PAGE 4: MITRE ATT&CK
# ==================================================

elif selected_page == "MITRE ATT&CK":

    section_header(
        "MITRE ATT&CK",
        "View candidate ATT&CK techniques associated "
        "with detected events."
    )

    if alerts_df.empty:

        show_empty_message("No alerts available for mapping.")

    else:

        records = []

        for _, alert in alerts_df.iterrows():

            mapping = get_mitre_mapping(
                alert["event_type"]
            )

            if not isinstance(mapping, dict):
                mapping = {}

            records.append({
                "Alert ID": alert["id"],
                "Event Type": alert["event_type"],
                "MITRE ID": (
                    alert.get("mitre_id")
                    or mapping.get("id")
                    or "Not mapped"
                ),
                "Technique": (
                    alert.get("mitre_name")
                    or mapping.get("name")
                    or "Not mapped"
                ),
                "Tactic": (
                    alert.get("mitre_tactic")
                    or mapping.get("tactic")
                    or "Not mapped"
                ),
                "Confidence": (
                    alert.get("mitre_confidence")
                    or mapping.get("confidence")
                    or "N/A"
                ),
                "Status": (
                    alert.get("mitre_status")
                    or mapping.get("status")
                    or "Not mapped"
                ),
                "URL": (
                    alert.get("mitre_url")
                    or mapping.get("url")
                    or ""
                )
            })

        mitre_df = pd.DataFrame(records)

        mapped = int(
            mitre_df["MITRE ID"].ne("Not mapped").sum()
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Events", len(mitre_df))
        col2.metric("Mapped Events", mapped)
        col3.metric("Unmapped Events", len(mitre_df) - mapped)

        st.divider()
        st.subheader("Technique Mapping Table")

        st.dataframe(
            mitre_df.drop(columns=["URL"]),
            use_container_width=True,
            hide_index=True
        )

        st.divider()
        st.subheader("Technique Details")

        mapped_df = mitre_df[
            mitre_df["MITRE ID"] != "Not mapped"
        ]

        if not mapped_df.empty:

            options = {
                f"{row['MITRE ID']} | {row['Technique']}": index
                for index, row in mapped_df.iterrows()
            }

            label = st.selectbox(
                "Select technique",
                list(options.keys())
            )

            technique = mapped_df.loc[
                options[label]
            ]

            st.write("**Technique:**", technique["Technique"])
            st.write("**Technique ID:**", technique["MITRE ID"])
            st.write("**Tactic:**", technique["Tactic"])
            st.write("**Confidence:**", technique["Confidence"])
            st.write("**Mapping Status:**", technique["Status"])

            if technique["URL"]:

                st.markdown(
                    f"[Open MITRE ATT&CK reference]({technique['URL']})"
                )

        else:
            show_empty_message("No mapped techniques found.")

        st.caption(
            "Mappings are candidate technique associations, "
            "not proof of malicious activity."
        )


# ==================================================
# PAGE 5: NETWORK MONITORING
# ==================================================

elif selected_page == "Network Monitoring":

    section_header(
        "Network Monitoring",
        "Advanced packet capture, protocol analysis, "
        "packet inspection and network traffic visibility."
    )

    if network_df.empty:

        show_empty_message(
            "No packets captured yet. Start the network monitor "
            "to collect traffic."
        )

    else:

        # ==========================================
        # NETWORK OVERVIEW
        # ==========================================

        st.header("Network Overview")

        total_packets = len(network_df)

        total_bytes = int(
            network_df["packet_size"].sum()
        )

        unique_protocols = network_df[
            "protocol"
        ].nunique()

        unique_sources = network_df[
            "source_ip"
        ].nunique()

        unique_destinations = network_df[
            "destination_ip"
        ].nunique()

        dns_count = int(
            network_df["dns_query"]
            .fillna("")
            .astype(str)
            .str.strip()
            .ne("")
            .sum()
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Packets", total_packets)
        col2.metric("Captured Traffic", format_bytes(total_bytes))
        col3.metric("Identified Protocols", unique_protocols)

        col4, col5, col6 = st.columns(3)

        col4.metric("Source Addresses", unique_sources)
        col5.metric("Destination Addresses", unique_destinations)
        col6.metric("DNS Queries", dns_count)

        st.divider()

        # ==========================================
        # PROTOCOL HIERARCHY
        # ==========================================

        st.header("Protocol Hierarchy")

        protocol_data = (
            network_df["protocol"]
            .value_counts()
            .rename_axis("Protocol")
            .reset_index(name="Packets")
        )

        protocol_data["Percentage"] = (
            protocol_data["Packets"]
            / max(total_packets, 1)
            * 100
        )

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:

            st.subheader("Protocol Distribution")

            fig = px.pie(
                protocol_data,
                names="Protocol",
                values="Packets",
                hole=0.45
            )

            fig.update_layout(template="plotly_dark")

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with chart_col2:

            st.subheader("Protocol Packet Counts")

            fig = px.bar(
                protocol_data,
                x="Protocol",
                y="Packets"
            )

            fig.update_layout(template="plotly_dark")

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        st.dataframe(
            protocol_data,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # ==========================================
        # PACKET EXPLORER AND FILTERING
        # ==========================================

        st.header("Packet Explorer")

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:

            
            st.write("Available protocols:", network_df["protocol"].unique())

            protocol_options = [
                "TCP", "UDP", "DNS", "ICMP", "ICMPv6",
                "ARP", "IPv4", "IPv6", "DHCP", "IGMP",
                "GRE", "ESP", "OTHER"
            ]

            selected_protocols = st.multiselect(
                "Filter by Protocol",
                options=protocol_options,
                default=protocol_options
            )


        with filter_col2:

            ip_search = st.text_input(
                "Search Source or Destination IP"
            ).strip().lower()

        filtered_network = network_df[
            network_df["protocol"].isin(selected_protocols)
        ].copy()

        if ip_search:

            ip_mask = (
                filtered_network["source_ip"]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(ip_search, regex=False)
                |
                filtered_network["destination_ip"]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(ip_search, regex=False)
            )

            filtered_network = filtered_network[ip_mask]

        if not filtered_network.empty:

            # Create a separate display copy.
            # The original database values remain unchanged.
            display_network = filtered_network.copy()

            for column in ["source_mac", "destination_mac"]:

                if column in display_network.columns:

                    display_network[column] = (
                        display_network[column]
                        .apply(format_mac)
                    )

            packet_columns = [
                "id",
                "timestamp",
                "protocol",
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "packet_size",
                "source_mac",
                "destination_mac",
                "layers"
            ]

            # Keep only columns that actually exist.
            available_columns = [
                column
                for column in packet_columns
                if column in display_network.columns
            ]

            st.dataframe(
                display_network[available_columns],
                use_container_width=True,
                hide_index=True
            )

            st.caption(
                f"Showing {len(filtered_network)} matching packets."
            )

            st.divider()

            # ======================================
            # SELECT PACKET
            # ======================================

            st.subheader("Packet Details")

            # Use DataFrame indices as selection values.
            # This also works when packet IDs are missing.
            packet_indices = filtered_network.index.tolist()

            def packet_label(index):
                row = filtered_network.loc[index]

                return (
                    f"Packet #{safe_value(row.get('id'))} | "
                    f"{safe_value(row.get('protocol'))} | "
                    f"{safe_value(row.get('source_ip'))} → "
                    f"{safe_value(row.get('destination_ip'))}"
                )

            selected_index = st.selectbox(
                "Select a packet",
                packet_indices,
                format_func=packet_label,
                key="selected_network_packet"
            )

            packet = filtered_network.loc[selected_index]

            # ======================================
            # GENERAL PACKET INFORMATION
            # ======================================

            st.subheader("General Information")

            info_col1, info_col2, info_col3 = st.columns(3)

            with info_col1:

                st.write("**Packet ID**")
                st.write(safe_value(packet["id"]))

                st.write("**Protocol**")
                st.write(safe_value(packet["protocol"]))

                st.write("**Packet Size**")
                st.write(format_bytes(packet["packet_size"]))

                st.write("**IP Version**")
                st.write(safe_value(packet["ip_version"]))

            with info_col2:

                st.write("**Source IP**")
                st.write(safe_value(packet["source_ip"]))

                st.write("**Source MAC**")
                st.code(format_mac(packet["source_mac"]))

                st.write("**Source Port**")
                st.write(safe_value(packet["source_port"]))

                st.write("**TCP Flags**")
                st.write(safe_value(packet["tcp_flags"]))

            with info_col3:

                st.write("**Destination IP**")
                st.write(safe_value(packet["destination_ip"]))

                st.write("**Destination MAC**")
                st.code(format_mac(packet["destination_mac"]))

                st.write("**Destination Port**")
                st.write(safe_value(packet["destination_port"]))

                st.write("**EtherType**")
                st.write(safe_value(packet["ether_type"]))

            st.write("**Timestamp**")
            st.write(safe_value(packet["timestamp"]))

            st.divider()

            # ======================================
            # PROTOCOL LAYER STACK
            # ======================================

            st.subheader("Protocol Layer Stack")

            layer_text = str(
                safe_value(
                    packet["layers"],
                    "No layer information"
                )
            )

            layers = [
                layer.strip()
                for layer in layer_text.split(",")
                if layer.strip()
            ]

            if layers:

                for index, layer in enumerate(layers, start=1):

                    st.markdown(
                        f"**{index}.** `{layer}`"
                    )

            else:
                st.info("No decoded layer information available.")

            st.divider()

            # ======================================
            # DECODED PACKET DETAILS
            # ======================================

            st.subheader("Decoded Packet Fields")

            packet_details = str(
                safe_value(packet["packet_details"], "")
            )

            if packet_details:

                st.code(
                    packet_details,
                    language="text"
                )

            else:

                show_empty_message(
                    "Decoded packet details are not available "
                    "for this record."
                )

            # ======================================
            # STRUCTURED PROTOCOL FIELDS
            # ======================================

            st.subheader("Structured Protocol Fields")

            protocol_fields = str(
                safe_value(packet["protocol_fields"], "")
            )

            if protocol_fields:

                try:

                    parsed_fields = json.loads(
                        protocol_fields
                    )

                    st.json(parsed_fields)

                except (json.JSONDecodeError, TypeError):

                    st.code(
                        protocol_fields,
                        language="json"
                    )

            else:

                show_empty_message(
                    "Structured protocol fields are not available."
                )

            st.divider()

            # ======================================
            # PAYLOAD INSPECTION
            # ======================================

            st.header("📦 Payload Inspection")

            payload_preview = str(
                safe_value(packet["payload_preview"], "")
            )

            payload_hex = str(
                safe_value(packet["payload_hex"], "")
            )

            if payload_preview or payload_hex:

                st.caption(
                    "This is the stored payload preview, "
                    "not necessarily the complete application data."
                )

                st.text_area(
                    "Payload Preview (ASCII / UTF-8)",
                    value=payload_preview,
                    height=150,
                    disabled=True,
                    key=f"payload_ascii_{selected_index}"
                )

                st.text_area(
                    "Payload Bytes (Hexadecimal)",
                    value=payload_hex,
                    height=120,
                    disabled=True,
                    key=f"payload_hex_{selected_index}"
                )

                payload_download = (
                    payload_preview
                    if payload_preview
                    else payload_hex
                )

                st.download_button(
                    "⬇ Download Payload Preview",
                    data=payload_download,
                    file_name=f"packet_{selected_index}_payload.txt",
                    mime="text/plain"
                )

            else:

                st.info(
                    "No separate payload preview was stored for this packet. "
                    "Some packets contain only headers or protocol control information."
                )

            st.divider()

            # ======================================
            # RAW PACKET BYTES
            # ======================================

            st.header("Raw Packet Bytes")

            raw_hex = str(
                safe_value(packet["raw_hex"], "")
            )

            ascii_dump = str(
                safe_value(packet["ascii_dump"], "")
            )

            if raw_hex:

                st.subheader("Hexadecimal Representation")

                st.code(
                    raw_hex,
                    language="text"
                )

                st.subheader("ASCII Representation")

                st.code(
                    ascii_dump,
                    language="text"
                )

                st.download_button(
                    "⬇ Download Raw Hex Dump",
                    data=raw_hex,
                    file_name=f"packet_{selected_index}_hex.txt",
                    mime="text/plain"
                )

            else:

                show_empty_message(
                    "Raw packet bytes were not stored for this record."
                )

            st.divider()

            # ======================================
            # PACKET SUMMARY
            # ======================================

            st.subheader("Packet Summary")

            st.write(
                safe_value(
                    packet["packet_summary"],
                    "No summary available"
                )
            )

        else:

            show_empty_message(
                "No packets match the selected filters."
            )

        st.divider()

        # ==========================================
        # DNS QUERY HISTORY
        # ==========================================

        st.header("DNS Query History")

        dns_df = network_df[
            network_df["dns_query"]
            .fillna("")
            .astype(str)
            .str.strip()
            .ne("")
        ].copy()

        if not dns_df.empty:

            dns_columns = [
                "timestamp",
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "dns_query"
            ]

            st.dataframe(
                dns_df[dns_columns],
                use_container_width=True,
                hide_index=True
            )

        else:

            show_empty_message(
                "No DNS queries have been captured yet."
            )


# ==================================================
# PAGE 6: AI ANALYSIS
# ==================================================

elif selected_page == "AI Analysis":

    section_header(
        "AI-Assisted Alert Analysis",
        "Analyze selected security alerts using your "
        "existing AI analyzer."
    )

    if alerts_df.empty:

        show_empty_message("No alerts available for analysis.")

    else:

        valid_alerts = alerts_df.dropna(
            subset=["id"]
        )

        if valid_alerts.empty:

            show_empty_message(
                "No valid alert IDs available."
            )

        else:

            options = {
                f"#{row['id']} | {row['event_type']} | {row['severity']}":
                row["id"]
                for _, row in valid_alerts.iterrows()
            }

            label = st.selectbox(
                "Select an alert",
                list(options.keys())
            )

            alert_id = options[label]

            alert = valid_alerts[
                valid_alerts["id"] == alert_id
            ].iloc[0].to_dict()

            st.divider()

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    "**Event:**",
                    alert.get("event_type")
                )

                st.write(
                    "**Process:**",
                    alert.get("process")
                )

                st.write(
                    "**Severity:**",
                    alert.get("severity")
                )

            with col2:

                st.write(
                    "**Risk Score:**",
                    alert.get("risk_score")
                )

                st.write(
                    "**Timestamp:**",
                    alert.get("timestamp")
                )

                st.write(
                    "**MITRE ID:**",
                    alert.get("mitre_id") or "Not mapped"
                )

            st.write("**Description**")
            st.write(alert.get("description", ""))

            st.divider()

            if st.button(
                "Analyze Alert",
                use_container_width=True
            ):

                with st.spinner("Analyzing alert..."):

                    try:

                        analysis = analyze_alert(alert)

                        st.subheader("Analysis Result")

                        if isinstance(analysis, (dict, list)):

                            st.json(analysis)

                        else:

                            st.markdown(str(analysis))

                    except Exception as error:

                        st.error(
                            f"AI analysis failed: {error}"
                        )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.markdown("""
<div style="text-align:center; color:#64748b; padding:12px;">
    <b>Cybersecurity OS Agent</b><br>
    Host Monitoring • Advanced Packet Capture • Protocol Analysis<br>
    Threat Detection • Risk Assessment • MITRE ATT&CK • Alert Investigation
</div>
""", unsafe_allow_html=True)