
"""
SQLite user authentication module.

Provides functions to initialize the users table, add users,
retrieve users, check whether users exist, and authenticate users.
"""

import sqlite3
import hashlib
import hmac
import os

from contextlib import closing
from typing import Optional, TypedDict


# Database configuration
DB_FILE: str = "users.db"

# Default administrator credentials
DEFAULT_ADMIN_USERNAME: str = "admin"
DEFAULT_ADMIN_PASSWORD: str = "password123"

# Password hashing configuration
HASH_ALGORITHM: str = "sha256"
HASH_ITERATIONS: int = 100_000
SALT_SIZE: int = 16


class UserRecord(TypedDict):
    """Structure returned when retrieving a user."""
    username: str
    password_hash: Optional[bytes]
    salt: Optional[bytes]


def _hash_password(password: str, salt: bytes) -> bytes:
    """
    Generate a secure password hash.

    Args:
        password: Plain-text password.
        salt: Random salt used during hashing.

    Returns:
        Password hash as bytes.
    """
    password_hash: bytes = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS
    )

    return password_hash


def initialize_users_table() -> None:
    """
    Create the users table if it does not exist.

    Also adds password columns if an older username-only
    users table already exists. Creates the default admin
    account if it does not already exist.
    """
    with closing(sqlite3.connect(DB_FILE)) as connection:
        with connection:
            cursor: sqlite3.Cursor = connection.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB,
                    salt BLOB
                )
            """)

            # Check the existing table structure.
            cursor.execute("PRAGMA table_info(users)")
            columns: list[tuple] = cursor.fetchall()

            column_names: list[str] = [
                column[1] for column in columns
            ]

            # Add password_hash to older tables if necessary.
            if "password_hash" not in column_names:
                cursor.execute(
                    "ALTER TABLE users ADD COLUMN password_hash BLOB"
                )

            # Add salt to older tables if necessary.
            if "salt" not in column_names:
                cursor.execute(
                    "ALTER TABLE users ADD COLUMN salt BLOB"
                )

            # Check whether the default administrator exists.
            cursor.execute(
                "SELECT username FROM users WHERE username = ?",
                (DEFAULT_ADMIN_USERNAME,)
            )

            admin: Optional[tuple] = cursor.fetchone()

            # Create the default administrator if missing.
            if admin is None:
                salt: bytes = os.urandom(SALT_SIZE)

                password_hash: bytes = _hash_password(
                    DEFAULT_ADMIN_PASSWORD,
                    salt
                )

                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, salt)
                    VALUES (?, ?, ?)
                    """,
                    (
                        DEFAULT_ADMIN_USERNAME,
                        password_hash,
                        salt
                    )
                )


def add_user(username: str, password: str) -> bool:
    """
    Add a new user to the database.

    Args:
        username: Username for the new account.
        password: Password for the new account.

    Returns:
        True if the user was added; otherwise False.
    """
    if not username or not password:
        return False

    salt: bytes = os.urandom(SALT_SIZE)
    password_hash: bytes = _hash_password(password, salt)

    try:
        with closing(sqlite3.connect(DB_FILE)) as connection:
            with connection:
                cursor: sqlite3.Cursor = connection.cursor()

                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, salt)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, salt)
                )

        return True

    except sqlite3.IntegrityError:
        # The username already exists.
        return False


def get_user(username: str) -> Optional[UserRecord]:
    """
    Retrieve a user from the database.

    Args:
        username: Username to retrieve.

    Returns:
        A UserRecord if found; otherwise None.
    """
    with closing(sqlite3.connect(DB_FILE)) as connection:
        cursor: sqlite3.Cursor = connection.cursor()

        cursor.execute(
            """
            SELECT username, password_hash, salt
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        row: Optional[tuple] = cursor.fetchone()

        if row is None:
            return None

        user: UserRecord = {
            "username": str(row[0]),
            "password_hash": row[1],
            "salt": row[2]
        }

        return user


def user_exists(username: str) -> bool:
    """
    Check whether a username exists in the database.

    Args:
        username: Username to check.

    Returns:
        True if the user exists; otherwise False.
    """
    with closing(sqlite3.connect(DB_FILE)) as connection:
        cursor: sqlite3.Cursor = connection.cursor()

        cursor.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,)
        )

        result: Optional[tuple] = cursor.fetchone()

        return result is not None


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user using their username and password.

    Args:
        username: Username supplied during login.
        password: Password supplied during login.

    Returns:
        True if the credentials are valid; otherwise False.
    """
    user: Optional[UserRecord] = get_user(username)

    if user is None:
        return False

    stored_hash: Optional[bytes] = user["password_hash"]
    salt: Optional[bytes] = user["salt"]

    # Older accounts may not have password information.
    if stored_hash is None or salt is None:
        return False

    entered_hash: bytes = _hash_password(password, salt)

    # Compare hashes securely.
    return hmac.compare_digest(stored_hash, entered_hash)


if __name__ == "__main__":
    initialize_users_table()
    print("Users table initialized.")
