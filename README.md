# Cybersecurity OS Agent

Cybersecurity OS Agent is a local Windows application for reviewing process and network activity, security alerts, investigations, and candidate MITRE ATT&CK mappings. The dashboard and monitoring worker run on the computer where the application is installed. Monitoring is off until an Admin user starts it from the dashboard.

## Windows installation

Download the latest [Windows installer](https://github.com/kunalsinghchouhan/Cybersecurity-OS-Agent/releases/latest). It creates Start Menu and optional Desktop shortcuts. The application stores each Windows user's records in `%LOCALAPPDATA%\CybersecurityOSAgent`; uninstalling leaves that data in place.

For packet capture, install Npcap separately with WinPcap API-compatible mode enabled. Process monitoring can run without it. See [INSTALLATION.md](INSTALLATION.md).

## First run

1. Launch Cybersecurity OS Agent from Start or the Desktop.
2. Create an account. The first account on that installation receives the Admin role; later accounts receive User access.
3. Monitoring starts off. Select **Start** in Agent Control to begin local monitoring.
4. Select **Stop** to stop it. Use **Exit application** in the dashboard to close the local dashboard server.

The Admin role can control monitoring. All account and monitoring records are local to the Windows account. Passwords use salted PBKDF2-HMAC-SHA256 hashes.

## Features

- Process CPU and memory threshold alerts and TCP connection observations.
- Scapy packet capture and packet inspection when Npcap and permissions are available.
- DNS and network protocol analysis, traffic/port scan rules, and packet storage.
- Alert severity/risk scores, investigation status, and candidate MITRE ATT&CK mapping.
- Local login, saved browser sessions, and an AI analysis page that can use a local Ollama service.

The detections are threshold based and are not a replacement for endpoint protection or a managed SOC. AI analysis requires Ollama and its configured model to be installed separately.

## Source development

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

For development-only direct dashboard use, `streamlit run dashboard.py` is supported. The standalone launcher is `python main.py`; it binds Streamlit to `127.0.0.1` and opens the chosen local port in the default browser.

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the PyInstaller/Inno Setup workflow and current environment limitations. See [USER_GUIDE.md](USER_GUIDE.md) for dashboard use and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common problems.
See [TEST_REPORT.md](TEST_REPORT.md) for completed checks and items that could not be verified here.

## Cloud dashboard

The existing optional Streamlit Cloud mode (`CLOUD_MODE = true`) is a dashboard-only mode. It does not connect to this Windows app or start a remote monitoring agent.
