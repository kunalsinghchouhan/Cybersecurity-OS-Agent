# Test Report

Date: 2026-11-25

## Passed

- Python compilation completed for the launcher, dashboard, controller, monitor, authentication, database, and path modules.
- The launcher started Streamlit from a different working directory, selected a loopback port, returned HTTP 200 from the Streamlit health route and dashboard route, handled a second request without starting monitoring, and exited after the local shutdown request.
- Monitoring status began as stopped. The controller started the supervisor and stopped it cleanly, including a stop request issued during worker import. Final status was `STOPPED` with no live worker.
- Process monitoring ran through a monitoring cycle. The local connection-table API returned `GetExtendedTcpTable failed` in this restricted account; the monitor now reports that limitation without crashing the process monitor.
- Authentication checks covered first-account Admin assignment, successful and failed password verification, PBKDF2 hash storage, session creation, and session revocation.
- Database checks covered migration into the configured per-user data path, alert insert/read/delete, packet insert/read/delete, and SQLite integrity.
- The one-folder PyInstaller build completed. The packaged launcher was tested from a path with spaces: `/`, `/index.html`, `/_stcore/health`, and `/manifest.json` returned HTTP 200; monitoring remained stopped; and the shutdown request closed the app cleanly.
- The packaged monitoring worker started in frozen mode, reported its components, and exited after its stop request.
- Inno Setup 7.1.1 compiled `dist\\CybersecurityOSAgent_Setup.exe` successfully. The installer supports x64-compatible Windows and leaves user data outside its installation directory.
- Installer smoke test used an installation folder containing spaces. The Start Menu shortcut targeted the installed executable, the installed dashboard health and root routes returned HTTP 200, and monitoring remained stopped on dashboard worker startup.
- Silent uninstall removed the installed program and Start Menu shortcut while preserving a marker and the database files in the separate user-data directory.
- `git diff --check` completed without whitespace errors. The initial Git index was restored to unstaged state; no commit or push was made.

## Partial or blocked

- Windows packet capture could initialize against the Npcap loopback interface, but this account's Npcap installation is in Admin-only mode and denied capture permission. Live packet collection and packet persistence therefore could not be verified. Synthetic packet database persistence passed.
- The user interface was checked through HTTP, but a full browser sign-up/login interaction and visual multi-tab test were not completed.
- Upgrade-in-place was not tested.
- No clean-machine or independent Windows machine was available. Python-free operation and clean-machine independence remain unverified.

## Environment-specific findings

- Dashboard binding and browser health checks required the approved loopback test run; the restricted run could not access local HTTP sockets.
- The local Windows account could not read `GetExtendedTcpTable` and did not have permission to capture with Npcap's Admin-only mode. These are represented as runtime component limitations and documented for users.
