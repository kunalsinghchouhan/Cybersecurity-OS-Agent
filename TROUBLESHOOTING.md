# Troubleshooting

## Dashboard does not open

- Check `%LOCALAPPDATA%\CybersecurityOSAgent\logs\agent_runtime.log`.
- Close a stale application from Task Manager and try again. The launcher prevents a second dashboard instance.
- Confirm a local security tool is not blocking `127.0.0.1` connections.
- The launcher selects a free loopback port for each start; it does not expose the dashboard to the network.

## `ModuleNotFoundError: streamlit_cookies_controller`

This happens when the source app is launched with a Python interpreter that does not have the project requirements installed. From the repository folder, create `.venv` first if it does not exist, then install and launch with that interpreter:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

If using VS Code, select `.venv\Scripts\python.exe` as the project interpreter. The standalone Windows installer bundles this dependency; launch the installed app instead of `dashboard.py` when Python should not be required.

## Network monitoring is unavailable

- Install Npcap separately and select WinPcap API-compatible mode.
- Restart Cybersecurity OS Agent after installing Npcap.
- Check the Agent Control component status and `agent_runtime.log` for the specific capture error.
- Depending on Npcap's installation mode and Windows policy, packet capture may require an elevated user or a change to Npcap's service access settings. Use only the permissions required by your environment.
- Process monitoring continues if packet capture is unavailable; the dashboard reports that degraded state.

## Process list or connection details are incomplete

Windows may deny access to protected processes or some system connection details for a standard user. Run with appropriate privileges only when needed and permitted. The application does not terminate processes.

## Login or saved session problem

Use **Log out**, then sign in again. If the session remains invalid, close the browser and relaunch the app. User accounts and sessions are stored in `data\security_agent_users.db`; do not delete it unless you intend to remove all local accounts.

## AI Analysis cannot connect

Install and start Ollama locally, then ensure the configured model (`qwen2.5:3b` by default) is available. AI Analysis is optional and does not affect monitoring or alert storage.

## Database or migration error

Do not delete or replace a database that contains records. The application logs the failing path and preserves a backup when migrating an existing source database. Back up the entire `%LOCALAPPDATA%\CybersecurityOSAgent\data` folder before manual repair or reinstalling.

## App does not stop

Use **Stop** to end monitoring, then **Exit application** to close the dashboard server. If an unexpected crash leaves the dashboard or worker active, restart Windows or close only the verified Cybersecurity OS Agent process shown in Task Manager. Do not terminate a process by PID copied from an old log because Windows may have reused that PID.
