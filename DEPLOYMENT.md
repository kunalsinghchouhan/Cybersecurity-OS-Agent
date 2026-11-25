# Deployment Audit and Build Guide

## Audit summary

The existing project is a Python/Streamlit dashboard backed by SQLite. `dashboard.py` contains Overview, Security Alerts, Investigations, MITRE ATT&CK, Network Monitoring, and AI Analysis pages. `auth.py` implements local account registration, salted PBKDF2 hashes, hashed session tokens, and Admin/User roles. `agent_controller.py` supervises a local worker; `agent_runtime.py` coordinates process, packet capture, and connectivity components. Alert and packet records are written through `database.py` and `alert_manager.py`.

Existing detections are simple threshold rules for process CPU/memory, network port scans, and traffic rate. MITRE entries are candidate mappings. Scapy packet capture requires a Windows capture driver. AI analysis calls a local Ollama HTTP endpoint and is optional.

### Blockers found and changes made

- Database modules originally targeted the project directory. Database initialization now resolves both databases to per-user AppData and performs a verified, non-destructive first-run migration from legacy project databases. Legacy logs are copied without overwriting AppData files.
- Alert, process, network, and connectivity logs now use the centralized AppData paths.
- The dashboard formerly started connectivity monitoring during page load. It now leaves all monitoring stopped until an Admin presses **Start**.
- Monitoring PID records now include process creation time and validate both process identity and creation time before reporting or stopping it. Frozen worker mode is supported, and the supervisor retries components that stop unexpectedly.
- A launcher now starts Streamlit as a separate process on `127.0.0.1`, waits for its health endpoint, opens the browser, prevents duplicate dashboards, logs failures, and supports authenticated **Exit application** shutdown.
- Windows packet capture reports an actionable Npcap message when `wpcap.dll` is absent.
- A one-folder PyInstaller spec, Inno Setup script, icon, and end-user documentation were added. Development databases are not included in packaging inputs.

## Architecture

```text
Start Menu / Desktop shortcut
  -> CybersecurityOSAgent.exe launcher
       -> local Streamlit dashboard process (127.0.0.1)
       -> authenticated Start/Stop control
            -> independent monitoring supervisor
                 -> process monitor thread
                 -> Scapy packet capture (Npcap required on Windows)
                 -> connectivity monitor thread
       -> per-user SQLite databases and logs under %LOCALAPPDATA%
```

Monitoring does not start during installation, launcher startup, dashboard startup, browser refresh, or opening another tab. Dashboard and monitoring worker lifecycles are separate. The launcher stops its own monitoring worker on application exit.

## Package build (Windows)

Use a clean Windows build machine and do not copy local `.db`, `.json`, or `.log` files into the release. One-folder packaging is used because Streamlit assets and Scapy/native components are more reliable to inspect and stage as separate files.

1. Install Python 3.11 or 3.12 (64-bit), then install the project and build requirements:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python -m pip install -r requirements-build.txt
   ```

2. Build from the repository root:

   ```powershell
   pyinstaller --clean --noconfirm CybersecurityOSAgent.spec
   ```

3. Check `dist\CybersecurityOSAgent\CybersecurityOSAgent.exe` on a clean Windows account, from a working directory containing spaces, and without Python installed. Confirm first-run account creation, monitoring off, worker start/stop, browser refresh/multiple tabs, data persistence, logs, and shutdown. This workspace build has passed launcher HTTP smoke checks from a path with spaces; clean-machine and Python-free behavior remain to be checked.

4. Install Inno Setup on the build machine, then compile `installer\CybersecurityOSAgent.iss` with the Inno Setup compiler. The output is `dist\CybersecurityOSAgent_Setup.exe`.

5. Test install, shortcuts, upgrade-in-place, and uninstall. Confirm uninstall leaves `%LOCALAPPDATA%\CybersecurityOSAgent` intact. Test packet capture separately on a machine with Npcap and appropriate permissions.

`CybersecurityOSAgent.spec` bundles Python dependencies and `dashboard.py`; it does not bundle any database or user log. Npcap is a separate driver dependency and is not bundled. The AI page requires a user-installed Ollama service and model.

## Build status for this workspace

The one-folder PyInstaller package and Inno Setup installer compiled successfully. The packaged dashboard passed local HTTP health/static-route checks from a path containing spaces, and the packaged monitoring worker started and stopped. Installer execution, a clean-machine run, Python-free operation, interactive browser authentication, upgrade behavior, and live Npcap packet capture still need validation. See [TEST_REPORT.md](TEST_REPORT.md) for all test outcomes.

## Publishing with GitHub Releases

After a clean Windows build and installation test, create a release tag and attach `dist\CybersecurityOSAgent_Setup.exe` through the repository's GitHub Releases page. Include the version, supported Windows versions, SHA-256 checksum, Npcap note, and known limitations in the release text. Do not upload databases, logs, or user data. Publishing is intentionally left to the repository owner.
