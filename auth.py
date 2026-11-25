"""
Authentication module for Cybersecurity OS Agent.

User accounts are stored separately from monitoring events.
Passwords are stored as PBKDF2-HMAC-SHA256 hashes, never as plain text.
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

import streamlit as st
from streamlit_cookies_controller import CookieController
from app_paths import ensure_database_file


AUTH_DB = ensure_database_file("security_agent_users.db")
HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16
MIN_PASSWORD_LENGTH = 10
SESSION_COOKIE_NAME = "cybersecurity_os_session"
SESSION_TTL_DAYS = 30


def _connect():
    connection = sqlite3.connect(AUTH_DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def init_auth_db():
    """Create the user table if it does not already exist."""
    with closing(_connect()) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'User'
                    CHECK(role IN ('Admin', 'User')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK(is_active IN (0, 1))
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS AuthSessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
            )
        """)
        connection.commit()


def _session_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_auth_session(user_id):
    """Create a random, revocable login token and return its raw value."""
    token = secrets.token_urlsafe(32)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)
    ).isoformat()
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO AuthSessions (token_hash, user_id, expires_at) "
            "VALUES (?, ?, ?)",
            (_session_token_hash(token), user_id, expires_at)
        )
        connection.commit()
    return token


def _get_user_for_session(token):
    if not isinstance(token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{40,50}", token
    ):
        return None

    now = datetime.now(timezone.utc).isoformat()
    with closing(_connect()) as connection:
        row = connection.execute(
            """
            SELECT Users.id, Users.username, Users.email, Users.role
            FROM AuthSessions
            JOIN Users ON Users.id = AuthSessions.user_id
            WHERE AuthSessions.token_hash = ?
              AND AuthSessions.expires_at > ?
              AND Users.is_active = 1
            """,
            (_session_token_hash(token), now)
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"]
    }


def revoke_auth_session(token):
    if not isinstance(token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{40,50}", token
    ):
        return
    with closing(_connect()) as connection:
        connection.execute(
            "DELETE FROM AuthSessions WHERE token_hash = ?",
            (_session_token_hash(token),)
        )
        connection.commit()


def _save_session_cookie(cookie_controller, user_id):
    token = create_auth_session(user_id)
    cookie_controller.set(
        SESSION_COOKIE_NAME,
        token,
        expires=datetime.now() + timedelta(days=SESSION_TTL_DAYS),
        max_age=SESSION_TTL_DAYS * 24 * 60 * 60,
        same_site="lax"
    )
    # Let the cookie component send the write to the browser before rerunning.
    time.sleep(1)


def _hash_password(password, salt=None):
    salt = salt or os.urandom(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return (
        f"pbkdf2_{HASH_NAME}${PBKDF2_ITERATIONS}$"
        f"{salt.hex()}${derived.hex()}"
    )


def _verify_password(password, stored_hash):
    try:
        algorithm, iterations_text, salt_hex, expected_hex = stored_hash.split("$")
        if algorithm != f"pbkdf2_{HASH_NAME}":
            return False

        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)

        actual = hashlib.pbkdf2_hmac(
            HASH_NAME,
            password.encode("utf-8"),
            salt,
            iterations
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def register_user(username, email, password):
    """
    Register a user. The first account is Admin; subsequent accounts are Users.
    Returns (success, message, user_dict_or_none).
    """
    username = (username or "").strip()
    email = (email or "").strip().lower()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
        return (
            False,
            "Username must be 3–30 characters and contain only letters, "
            "numbers, dots, underscores or hyphens.",
            None
        )

    if len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return False, "Enter a valid email address.", None

    if len(password or "") < MIN_PASSWORD_LENGTH:
        return (
            False,
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters.",
            None
        )

    if len(password) > 256:
        return False, "Password is too long.", None

    password_hash = _hash_password(password)

    try:
        connection = _connect()
        try:
            # Serialize registrations so two simultaneous first signups cannot
            # both receive the Admin role.
            connection.execute("BEGIN IMMEDIATE")
            existing_count = connection.execute(
                "SELECT COUNT(*) FROM Users"
            ).fetchone()[0]

            role = "Admin" if existing_count == 0 else "User"

            cursor = connection.execute(
                """
                INSERT INTO Users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, password_hash, role)
            )
            user_id = cursor.lastrowid
            connection.commit()

            user = {
                "id": user_id,
                "username": username,
                "email": email,
                "role": role
            }
            return True, f"Account created successfully. Assigned role: {role}.", user

        except sqlite3.IntegrityError:
            connection.rollback()
            return (
                False,
                "That username or email address is already registered.",
                None
            )
        finally:
            connection.close()

    except sqlite3.Error:
        return False, "The account could not be created due to a database error.", None


def authenticate_user(username_or_email, password):
    """Verify credentials and return an active user or None."""
    identity = (username_or_email or "").strip()
    if not identity or not password:
        return None

    try:
        with closing(_connect()) as connection:
            row = connection.execute(
                """
                SELECT id, username, email, password_hash, role, is_active
                FROM Users
                WHERE username = ? COLLATE NOCASE
                   OR email = ? COLLATE NOCASE
                LIMIT 1
                """,
                (identity, identity)
            ).fetchone()

        if row is None or row["is_active"] != 1:
            return None

        if not _verify_password(password, row["password_hash"]):
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"]
        }

    except sqlite3.Error:
        return None


def get_current_user(cookie_controller):
    """Restore the authenticated user from session state or browser cookie."""
    user = st.session_state.get("authenticated_user")
    if isinstance(user, dict):
        return user

    token = cookie_controller.get(SESSION_COOKIE_NAME)
    user = _get_user_for_session(token)
    if user is not None:
        st.session_state["authenticated_user"] = user
    return user


def logout_user(cookie_controller):
    """Clear authentication state for this browser session."""
    token = cookie_controller.get(SESSION_COOKIE_NAME)
    revoke_auth_session(token)
    cookie_controller.remove(SESSION_COOKIE_NAME)
    st.session_state.pop("authenticated_user", None)
    time.sleep(1)
    st.rerun()


def render_auth_page(cookie_controller):
    """Render the login and self-registration interface."""
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #17243b 0%, #0b1120 55%);
            color: #e2e8f0;
        }
        [data-testid="stHeader"] { background: transparent; }
        .auth-brand {
            text-align: center;
            padding: 28px 0 8px 0;
        }
        .auth-brand h1 {
            color: #f8fafc;
            font-size: 30px;
            margin-bottom: 4px;
        }
        .auth-brand p {
            color: #94a3b8;
            font-size: 13px;
            letter-spacing: 1.5px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    left, center, right = st.columns([1, 1.35, 1])
    with center:
        st.markdown(
            """
            <div class="auth-brand">
                <h1>🛡️ Cybersecurity OS Agent</h1>
                <p>SECURITY MONITORING PLATFORM</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        login_tab, signup_tab = st.tabs(["Login", "Create account"])

        with login_tab:
            with st.form("login_form", clear_on_submit=False):
                identity = st.text_input(
                    "Username or email",
                    placeholder="Enter your username or email"
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    placeholder="Enter your password"
                )
                submitted = st.form_submit_button(
                    "Login",
                    use_container_width=True
                )

            if submitted:
                user = authenticate_user(identity, password)
                if user:
                    _save_session_cookie(cookie_controller, user["id"])
                    st.session_state["authenticated_user"] = user
                    st.rerun()
                else:
                    st.error("Invalid credentials or inactive account.")

        with signup_tab:
            st.caption(
                "Create an account to access the monitoring dashboard. "
                "The first registered account receives the Admin role."
            )
            with st.form("signup_form", clear_on_submit=True):
                new_username = st.text_input(
                    "Username",
                    placeholder="3–30 characters"
                )
                new_email = st.text_input(
                    "Email address",
                    placeholder="name@example.com"
                )
                new_password = st.text_input(
                    "Password",
                    type="password",
                    help=f"Use at least {MIN_PASSWORD_LENGTH} characters."
                )
                confirm_password = st.text_input(
                    "Confirm password",
                    type="password"
                )
                signup_submitted = st.form_submit_button(
                    "Create account",
                    use_container_width=True
                )

            if signup_submitted:
                if new_password != confirm_password:
                    st.error("The passwords do not match.")
                else:
                    success, message, user = register_user(
                        new_username,
                        new_email,
                        new_password
                    )
                    if success:
                        _save_session_cookie(cookie_controller, user["id"])
                        st.session_state["authenticated_user"] = user
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)

        st.caption(
            "Passwords are stored as salted PBKDF2 hashes. "
            "Use a unique password for this application."
        )
