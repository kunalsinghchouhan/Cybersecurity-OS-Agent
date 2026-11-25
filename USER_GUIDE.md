# User Guide

## Sign in and account setup

On first launch, choose **Create account** and set a unique password of at least 10 characters. The first account on this computer's installation is an Admin and can start or stop monitoring. Later accounts can review the local data but do not have the monitoring controls. There are no built-in credentials.

The browser stores a revocable session token, while the database stores only its hash. Select **Log out** to end the session.

## Monitoring

Monitoring is **off by default**, including after dashboard refresh or application restart. The dashboard server can remain open while monitoring is stopped.

- Choose **Start** in the sidebar's Agent Control to start the local process, network, and connectivity monitors.
- Review the status shown in the sidebar. A component may show unavailable if its required Windows capture dependency or permission is missing.
- Choose **Stop** to request a clean shutdown of the monitoring worker and its components.
- Use **Exit application** to close the local dashboard server. This also requests a monitoring stop.

Only use packet capture on computers and networks where you are authorized to monitor traffic. Packet capture may include sensitive packet metadata or payload previews, which remain in the local database.

## Dashboard pages

- **Overview:** alert and packet totals, charts, recent activity.
- **Security Alerts:** filter and inspect alerts.
- **Investigations:** update alert investigation status.
- **MITRE ATT&CK:** review candidate mappings. A mapping is not proof of malicious activity.
- **Network Monitoring:** inspect captured packets, protocol summaries, addresses, and DNS records.
- **AI Analysis:** request an explanation from Ollama. Ollama and the selected model must be installed and running locally; no cloud model is provided by this application.

## Data, upgrades, and uninstall

Your databases and logs are in `%LOCALAPPDATA%\CybersecurityOSAgent`. Upgrades preserve this folder. Uninstalling leaves it intact. See [INSTALLATION.md](INSTALLATION.md) for the full folder listing.
