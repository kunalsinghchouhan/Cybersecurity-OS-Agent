"""Windows-friendly local launcher for the authenticated Streamlit dashboard."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

from app_paths import get_app_paths, runtime_lock


APP_PATHS = get_app_paths()
BASE_DIR = Path(__file__).resolve().parent
LOCK_NAME = "dashboard_instance.lock.sqlite"
STARTUP_TIMEOUT = 45


def resource_path(name: str) -> Path:
    bundle_root = Path(getattr(sys, "_MEIPASS", BASE_DIR))
    return bundle_root / name


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("cybersecurity_os_agent.launcher")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(APP_PATHS.agent_log, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


def _choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _worker_command(mode: str, *args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, f"--{mode}", *args]
    return [sys.executable, str(BASE_DIR / "launcher.py"), f"--{mode}", *args]


def _run_dashboard_worker(port: int) -> int:
    from streamlit import config
    from streamlit.web import bootstrap

    dashboard = resource_path("dashboard.py")
    if not dashboard.is_file():
        raise FileNotFoundError(f"Dashboard resource is missing: {dashboard}")
    options = {
        # PyInstaller places Streamlit modules outside site-packages; its
        # auto-detection can mistake a frozen app for a development checkout.
        # Production mode is required for Streamlit to mount its bundled UI.
        "global.developmentMode": False,
        "server.address": "127.0.0.1",
        "server.port": port,
        "server.headless": True,
        "server.fileWatcherType": "none",
        "browser.gatherUsageStats": False,
        "server.enableCORS": True,
        "server.enableXsrfProtection": True,
    }
    for name, value in options.items():
        config.set_option(name, value)
    bootstrap.run(
        str(dashboard),
        False,
        [],
        options,
    )
    return 0


def _run_monitor_worker() -> int:
    from agent_runtime import run_agent

    run_agent()
    return 0


def _wait_until_ready(process: subprocess.Popen, url: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    health_url = url + "/_stcore/health"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:
                if response.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    return False


def _stop_child(process: subprocess.Popen | None, logger: logging.Logger) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        logger.warning("Dashboard did not stop in time; forcing shutdown")
        process.kill()
        process.wait(timeout=5)


def launch() -> int:
    logger = _configure_logging()
    server = None
    owns_instance = False
    paths = APP_PATHS
    paths.application_stop_request.unlink(missing_ok=True)

    try:
        # Importing the database module prepares the user database and applies
        # its idempotent schema setup before the dashboard is shown.
        from database import initialize_database
        from auth import init_auth_db

        initialize_database()
        init_auth_db()

        with runtime_lock(paths, LOCK_NAME):
            owns_instance = True
            port = _choose_port()
            url = f"http://127.0.0.1:{port}"
            log_handle = APP_PATHS.agent_log.open("a", encoding="utf-8")
            try:
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                server = subprocess.Popen(
                    _worker_command("dashboard-worker", str(port)),
                    cwd=str(BASE_DIR),
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    creationflags=creation_flags,
                )
            finally:
                log_handle.close()

            if not _wait_until_ready(server, url, STARTUP_TIMEOUT):
                raise RuntimeError(
                    "The local dashboard did not become ready. See "
                    f"{APP_PATHS.agent_log} for details."
                )

            logger.info("Dashboard ready at %s", url)
            webbrowser.open(url, new=2)

            while server.poll() is None:
                if paths.application_stop_request.exists():
                    logger.info("Dashboard shutdown requested from the UI")
                    break
                time.sleep(0.5)

            return_code = server.poll()
            if return_code not in (None, 0):
                raise RuntimeError(
                    f"Dashboard server exited with code {return_code}. "
                    f"See {APP_PATHS.agent_log} for details."
                )
            return 0
    except Exception:
        logger.exception("Application startup or runtime failure")
        return 1
    finally:
        paths.application_stop_request.unlink(missing_ok=True)
        _stop_child(server, logger)
        if owns_instance:
            try:
                from agent_controller import stop_agent

                stop_agent()
            except Exception:
                logger.exception("Could not stop the monitoring worker during shutdown")


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--dashboard-worker":
        return _run_dashboard_worker(int(args[1]))
    if args and args[0] == "--monitor-worker":
        return _run_monitor_worker()
    return launch()


if __name__ == "__main__":
    raise SystemExit(main())
