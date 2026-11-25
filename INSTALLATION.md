# Installation

## Requirements

- Windows 10 or 11, 64-bit.
- A standard user account for normal application use.
- Administrator permission to install the application under Program Files.
- Npcap for packet capture. Process monitoring and alert review work without Npcap.
- Optional: Ollama and a compatible local model for AI Analysis.

## Installer

1. Download `CybersecurityOSAgent_Setup.exe` from a trusted project release.
2. Run the installer and accept the Windows elevation prompt for Program Files installation.
3. Keep the optional Desktop shortcut selected if desired.
4. If prompted, install Npcap separately from [npcap.com](https://npcap.com/#download). Select WinPcap API-compatible mode. Follow Npcap's own driver and privilege choices.
5. Launch the app from Start or the Desktop.
6. Create a local account. The first account created on that installation is Admin; later accounts are regular Users.

The installer does not create a default password and does not include a development account or database.

## Data and logs

Application data is stored per Windows user at:

```text
%LOCALAPPDATA%\CybersecurityOSAgent\
  data\security_agent.db
  data\security_agent_users.db
  logs\security_events.log
  logs\security_events.json
  logs\agent_runtime.log
  runtime\
  backups\
```

Updates preserve this directory. Uninstalling removes the application files and shortcuts, but intentionally leaves the user's databases, logs, and backups. To remove personal data, first uninstall, then delete `%LOCALAPPDATA%\CybersecurityOSAgent` yourself.

## Development install

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Development dependencies for building the Windows package are listed in `requirements-build.txt`. The Inno Setup compiler is installed separately. Detailed build steps are in [DEPLOYMENT.md](DEPLOYMENT.md).
