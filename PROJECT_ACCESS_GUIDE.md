# Cybersecurity OS Agent: Access Guide

This guide explains how to find the project, install the Windows application, and run it. The application and its monitoring data run locally on the Windows computer where it is installed.

## 1. Open the GitHub project

Visit the [Cybersecurity OS Agent repository](https://github.com/kunalsinghchouhan/Cybersecurity-OS-Agent). The **Code** tab contains the source code and documentation. The **Releases** page contains downloadable Windows installers.

## 2. Download and install the Windows application

1. Open [Releases](https://github.com/kunalsinghchouhan/Cybersecurity-OS-Agent/releases/latest).
2. Under **Assets**, download `CybersecurityAgent_Setup.exe`.
3. Open the downloaded installer and approve the Windows permission prompt.
4. Choose whether to create a Desktop shortcut, then complete setup.
5. Start **Cybersecurity OS Agent** from the Start menu or Desktop shortcut.

The installer includes the application runtime; a separate Python installation is not needed. Network packet capture requires Npcap installed separately. See [INSTALLATION.md](INSTALLATION.md) for its configuration and the data-preserving uninstall details.

## 3. Create an account and open the dashboard

1. On first launch, create an account in the dashboard. The first account on that installation is an **Admin**; additional accounts are regular Users.
2. Sign in. The dashboard is available only on the local computer.
3. Check the Overview page's Internet indicator. Monitoring requires an active internet connection.

## 4. Start and stop monitoring

1. An Admin selects **Start** in the sidebar to begin monitoring.
2. If internet is disconnected, the Start control is disabled and the dashboard explains that a connection is required.
3. If internet is lost during monitoring, process and network monitoring stop. When the connection returns, select **Start** again; monitoring does not restart automatically.
4. Select **Stop** to end monitoring at any time.
5. Use **Exit application** in the sidebar when you want to close the local dashboard server.

Process monitoring and alert review can work without Npcap. Packet capture needs Npcap in WinPcap API-compatible mode and may require suitable Windows permissions. The Internet indicator and Network Monitoring status are separate: an online connection does not guarantee packet capture is available.

## 5. Use optional Ollama AI analysis

AI Analysis is optional and runs through a local Ollama service. Install Ollama, then download the project's default model from PowerShell:

```powershell
ollama pull qwen2.5:3b
```

Keep Ollama running, open **AI Analysis**, choose an alert, and select **Analyze Alert**. The response appears as Ollama generates it. The application does not send alert data to a hosted AI service.

## 6. Access the source and run a development copy

Install Git and Python 3.10 or later, then run these commands in PowerShell:

```powershell
git clone https://github.com/kunalsinghchouhan/Cybersecurity-OS-Agent.git
cd Cybersecurity-OS-Agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

If PowerShell blocks virtual-environment activation, use the virtual environment's interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

For dashboard use, feature limitations, troubleshooting, and deployment/build details, see [USER_GUIDE.md](USER_GUIDE.md), [TROUBLESHOOTING.md](TROUBLESHOOTING.md), and [DEPLOYMENT.md](DEPLOYMENT.md).
