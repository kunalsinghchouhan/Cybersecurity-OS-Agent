# Cybersecurity OS Agent

A Python-based cybersecurity monitoring system designed to monitor system processes, network activity, and internet connectivity while detecting potentially suspicious behavior.

## Features

- **Process Monitoring:** Monitors running processes and system resource usage.
- **Network Monitoring:** Captures and analyzes network packets.
- **Internet Connectivity Monitoring:** Checks internet connectivity status.
- **Detection Engine:** Identifies potentially suspicious system and network activities.
- **Risk Scoring:** Assigns risk scores and severity levels to detected events.
- **Alert Management:** Stores and manages security alerts.
- **MITRE ATT&CK Mapping:** Maps supported detections to relevant MITRE ATT&CK techniques.
- **SQLite Database:** Stores alerts and network packet information.
- **Streamlit Dashboard:** Provides a graphical interface for monitoring and investigation.
- **Authentication:** Provides user login and role-based access.
- **AI Analysis:** Provides additional analysis of security alerts.

## Technology Stack

- Python
- Streamlit
- Scapy
- Psutil
- SQLite
- Pandas
- Plotly
- MITRE ATT&CK Framework

## Project Structure

```text
Cybersecurity-OS-Agent/
├── main.py
├── dashboard.py
├── agent_controller.py
├── monitor_engine.py
├── network_monitor.py
├── connectivity_monitor.py
├── detection_engine.py
├── risk_engine.py
├── database.py
├── auth.py
├── MITRE_mapping.py
├── ai_analyzer.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/YOUR-USERNAME/Cybersecurity-OS-Agent.git
   ```

2. Navigate to the project directory:

   ```bash
   cd Cybersecurity-OS-Agent
   ```

3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Activate the virtual environment on Windows:

   ```bash
   .venv\Scripts\activate
   ```

5. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Running the Dashboard

```bash
streamlit run dashboard.py
```

## Disclaimer

This project is developed for educational and cybersecurity monitoring purposes. Network monitoring and packet capture should only be performed on systems and networks where appropriate authorization has been obtained.