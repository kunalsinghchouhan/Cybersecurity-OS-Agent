"""Centralized paths and safe migration for local application data."""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import uuid


PROJECT_ROOT = Path(__file__).resolve().parent
SQLITE_TIMEOUT_SECONDS = 30
IMPORTANT_TABLES = {
    "security_agent.db": ("Alerts", "NetworkPackets"),
    "security_agent_users.db": ("Users", "AuthSessions"),
}


class AppDataError(RuntimeError):
    """Raised when local application data cannot be prepared safely."""


@dataclass(frozen=True)
class AppPaths:
    root: Path
    data: Path
    logs: Path
    config: Path
    runtime: Path
    backups: Path

    @property
    def monitoring_database(self) -> Path:
        return self.data / "security_agent.db"

    @property
    def auth_database(self) -> Path:
        return self.data / "security_agent_users.db"

    @property
    def security_log(self) -> Path:
        return self.logs / "security_events.log"

    @property
    def security_events(self) -> Path:
        return self.logs / "security_events.json"

    @property
    def agent_log(self) -> Path:
        return self.logs / "agent_runtime.log"

    @property
    def monitor_pid(self) -> Path:
        return self.runtime / "monitor_engine.pid"

    @property
    def agent_status(self) -> Path:
        return self.runtime / "agent_status.json"

    @property
    def internet_status(self) -> Path:
        return self.runtime / "internet_status.json"

    @property
    def agent_stop_request(self) -> Path:
        return self.runtime / "agent_stop.request"

    @property
    def application_stop_request(self) -> Path:
        return self.runtime / "application_stop.request"


@contextmanager
def runtime_lock(paths: AppPaths, filename: str):
    """Acquire a named cross-process lock stored in the runtime directory."""
    if Path(filename).name != filename or not filename.endswith(".sqlite"):
        raise ValueError("Runtime lock names must be simple .sqlite filenames")
    with _migration_lock(paths.runtime / filename):
        yield


def get_app_paths(root: Path | str | None = None) -> AppPaths:
    """Return and create the application directory tree.

    Windows uses ``%LOCALAPPDATA%``. Other platforms use XDG data storage,
    which keeps local development portable.
    """
    if root is None:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            root = Path(local_app_data) / "CybersecurityOSAgent"
        elif sys.platform == "win32":
            root = Path.home() / "AppData" / "Local" / "CybersecurityOSAgent"
        else:
            data_home = os.environ.get("XDG_DATA_HOME")
            root = (Path(data_home) if data_home else Path.home() / ".local" / "share") / "CybersecurityOSAgent"

    root = Path(root).expanduser().resolve()
    paths = AppPaths(
        root=root,
        data=root / "data",
        logs=root / "logs",
        config=root / "config",
        runtime=root / "runtime",
        backups=root / "backups",
    )
    try:
        for directory in (paths.data, paths.logs, paths.config, paths.runtime, paths.backups):
            directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise AppDataError(f"Cannot create application data folders under {root}: {error}") from error
    return paths


def get_project_database_path(filename: str) -> Path:
    """Return the legacy source path for a known application database."""
    if Path(filename).name != filename or filename not in IMPORTANT_TABLES:
        raise ValueError(f"Unsupported application database name: {filename!r}")
    return PROJECT_ROOT / filename


def _integrity_check(database_path: Path) -> None:
    try:
        with closing(sqlite3.connect(database_path, timeout=SQLITE_TIMEOUT_SECONDS)) as connection:
            connection.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
            results = [row[0] for row in connection.execute("PRAGMA integrity_check")]
    except sqlite3.Error as error:
        raise AppDataError(f"SQLite validation failed for {database_path}: {error}") from error
    if results != ["ok"]:
        raise AppDataError(f"SQLite integrity check failed for {database_path}: {'; '.join(results)}")


def _table_counts(database_path: Path) -> dict[str, int]:
    with closing(sqlite3.connect(database_path, timeout=SQLITE_TIMEOUT_SECONDS)) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        counts = {}
        for (table_name,) in tables:
            escaped_name = table_name.replace('"', '""')
            counts[table_name] = connection.execute(
                f'SELECT COUNT(*) FROM "{escaped_name}"'
            ).fetchone()[0]
        return counts


def _schema_manifest(database_path: Path) -> list[tuple]:
    with closing(sqlite3.connect(database_path, timeout=SQLITE_TIMEOUT_SECONDS)) as connection:
        return connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index', 'view', 'trigger') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()


def _verify_snapshot(source: Path, candidate: Path, important_tables: tuple[str, ...]) -> None:
    _integrity_check(source)
    _integrity_check(candidate)
    source_counts = _table_counts(source)
    candidate_counts = _table_counts(candidate)
    if source_counts != candidate_counts:
        raise AppDataError(
            f"Database migration row counts differ: source={source_counts}, "
            f"destination={candidate_counts}. The original data was retained."
        )
    for table in important_tables:
        if table in source_counts and source_counts[table] != candidate_counts.get(table):
            raise AppDataError(
                f"Database migration count check failed for {table}. "
                "The original data was retained."
            )
    if _schema_manifest(source) != _schema_manifest(candidate):
        raise AppDataError(
            "Database migration schema verification failed; tables or indexes "
            "do not match the source snapshot. The original data was retained."
        )


def _sqlite_backup(source: Path, destination: Path) -> None:
    source_connection = None
    destination_connection = None
    try:
        source_uri = source.resolve().as_uri() + "?mode=ro"
        source_connection = sqlite3.connect(
            source_uri, uri=True, timeout=SQLITE_TIMEOUT_SECONDS
        )
        source_connection.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
        destination_connection = sqlite3.connect(
            destination, timeout=SQLITE_TIMEOUT_SECONDS
        )
        source_connection.backup(destination_connection, pages=256, sleep=0.05)
        destination_connection.commit()
    except sqlite3.Error as error:
        raise AppDataError(f"Could not create a consistent SQLite snapshot of {source}: {error}") from error
    finally:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()


@contextmanager
def _migration_lock(lock_path: Path):
    """Serialize migrations across application processes using SQLite locking."""
    try:
        connection = sqlite3.connect(lock_path, timeout=SQLITE_TIMEOUT_SECONDS)
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS migration_lock_state "
            "(id INTEGER PRIMARY KEY CHECK(id = 1), marker INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO migration_lock_state (id, marker) VALUES (1, 0)"
        )
        connection.commit()
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute(
            "UPDATE migration_lock_state SET marker = marker WHERE id = 1"
        )
        yield
    except sqlite3.Error as error:
        raise AppDataError(
            f"Could not acquire the local database migration lock: {error}"
        ) from error
    finally:
        if "connection" in locals():
            try:
                connection.rollback()
            finally:
                connection.close()


def _publish_no_replace(temporary: Path, destination: Path) -> None:
    """Atomically publish a completed file without replacing an existing one."""
    if destination.exists():
        raise FileExistsError(destination)
    if os.name == "nt":
        # Windows rename fails if the destination exists and is atomic on the
        # same volume, which these sibling files share.
        os.rename(temporary, destination)
    else:
        # A hard link is an atomic create-if-absent operation on one filesystem.
        os.link(temporary, destination)
        temporary.unlink()


def _migration_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]


def _migrate_database(source: Path, destination: Path, backup_dir: Path, important_tables: tuple[str, ...]) -> None:
    stamp = _migration_stamp()
    backup_path = backup_dir / f"{source.name}.{stamp}.backup"
    snapshot_temp = backup_dir / f".{source.name}.{stamp}.snapshot.tmp"
    destination_temp = destination.with_name(f".{destination.name}.{stamp}.migration.tmp")

    try:
        _sqlite_backup(source, snapshot_temp)
        _verify_snapshot(snapshot_temp, snapshot_temp, important_tables)
        os.rename(snapshot_temp, backup_path)

        _sqlite_backup(backup_path, destination_temp)
        _verify_snapshot(backup_path, destination_temp, important_tables)
        _publish_no_replace(destination_temp, destination)
        # Verify the published database too, before allowing app initialization.
        _verify_snapshot(backup_path, destination, important_tables)
    except FileExistsError as error:
        # Another application instance may have completed migration first.
        if destination.exists():
            _verify_snapshot(backup_path, destination, important_tables)
            return
        raise AppDataError(
            f"Could not publish migrated database {destination}; "
            f"the original database remains at {source} and its backup is at {backup_path}."
        ) from error
    except Exception as error:
        if isinstance(error, AppDataError):
            detail = str(error)
        else:
            detail = str(error)
        raise AppDataError(
            f"Could not migrate {source} to {destination}: {detail}. "
            f"No project database was changed. Any completed backup is at {backup_path}. "
            "Initialization has stopped; fix the issue and retry."
        ) from error


def _copy_legacy_runtime_file(source: Path, destination: Path) -> None:
    """Preserve a legacy log/event file without replacing AppData data."""
    if not source.is_file() or destination.exists():
        return
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.migration.tmp"
    )
    try:
        with source.open("rb") as source_file, temporary.open("xb") as target_file:
            shutil.copyfileobj(source_file, target_file)
            target_file.flush()
            os.fsync(target_file.fileno())
        _publish_no_replace(temporary, destination)
    except FileExistsError:
        # A concurrent process has already published the AppData copy.
        return
    except OSError as error:
        raise AppDataError(
            f"Could not preserve existing runtime file {source} at {destination}: {error}"
        ) from error


def _copy_legacy_runtime_files(paths: AppPaths, project_dir: Path) -> None:
    for filename in ("security_events.log", "agent_runtime.log", "security_events.json"):
        _copy_legacy_runtime_file(project_dir / filename, paths.logs / filename)


def ensure_database_file(
    filename: str,
    *,
    paths: AppPaths | None = None,
    legacy_path: Path | None = None,
) -> Path:
    """Prepare the AppData database, migrating a project copy only if needed."""
    if Path(filename).name != filename or filename not in IMPORTANT_TABLES:
        raise ValueError(f"Unsupported application database name: {filename!r}")
    paths = paths or get_app_paths()
    destination = paths.data / filename
    source = Path(legacy_path) if legacy_path is not None else PROJECT_ROOT / filename

    try:
        with _migration_lock(paths.runtime / "migration.lock.sqlite"):
            _copy_legacy_runtime_files(paths, PROJECT_ROOT)

            if destination.exists():
                try:
                    _integrity_check(destination)
                except AppDataError as error:
                    raise AppDataError(
                        f"The existing AppData database {destination} is invalid. "
                        "It was not replaced, and the project-folder database will "
                        f"not be used as a fallback: {error}"
                    ) from error
                return destination
            if source.exists():
                _migrate_database(
                    source,
                    destination,
                    paths.backups,
                    IMPORTANT_TABLES[filename],
                )
            # No legacy DB means first-run initialization will create a fresh DB.
            return destination
    except AppDataError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise AppDataError(
            f"Could not prepare {filename} in the application data folder: {error}. "
            "Initialization has stopped; no fallback to the project folder was attempted."
        ) from error
