
"""
Unit tests for sqlite_user.py.

Tests:
1. Default admin account is created.
2. Duplicate accounts cannot be added.
3. New users can be added and retrieved.
4. Username/password combinations authenticate correctly.

Run with:
    python -m unittest -v
"""

import hashlib
import tempfile
import unittest

from pathlib import Path
from typing import Any
from unittest.mock import patch

import sqlite_user


class SQLiteUserTests(unittest.TestCase):

    def setUp(self) -> None:
        """Create a temporary database before each test."""

        self.temp_directory: tempfile.TemporaryDirectory = (
            tempfile.TemporaryDirectory()
        )

        self.database_path: Path = (
            Path(self.temp_directory.name) / "test_users.db"
        )

        # Replace the database path in sqlite_user.py.
        self.db_patcher: Any = patch.object(
            sqlite_user,
            "DB_FILE",
            str(self.database_path)
        )

        self.db_patcher.start()

        # Initialize the temporary database.
        sqlite_user.initialize_users_table()

    def tearDown(self) -> None:
        """Clean up the temporary database after each test."""

        self.db_patcher.stop()
        self.temp_directory.cleanup()

    def test_default_admin_is_created_with_password123(self) -> None:
        """Verify that the default administrator can authenticate."""

        admin: Any = sqlite_user.get_user("admin")

        self.assertIsNotNone(admin)
        self.assertEqual(admin["username"], "admin")

        self.assertIsNotNone(admin["password_hash"])
        self.assertIsNotNone(admin["salt"])

        expected_hash: bytes = hashlib.pbkdf2_hmac(
            "sha256",
            b"password123",
            admin["salt"],
            100_000
        )
        self.assertEqual(admin["password_hash"], expected_hash)

        self.assertTrue(
            sqlite_user.authenticate_user("admin", "password123")
        )

        self.assertFalse(
            sqlite_user.authenticate_user("admin", "wrong-password")
        )

    def test_existing_account_cannot_be_created_again(self) -> None:
        """Verify that duplicate usernames are rejected."""

        added: bool = sqlite_user.add_user("alice", "alice-pass")
        self.assertTrue(added)

        duplicate: bool = sqlite_user.add_user(
            "alice",
            "different-pass"
        )

        self.assertFalse(duplicate)

        # The original password should still work.
        self.assertTrue(
            sqlite_user.authenticate_user("alice", "alice-pass")
        )

        self.assertFalse(
            sqlite_user.authenticate_user("alice", "different-pass")
        )

    def test_new_user_can_be_added_and_retrieved(self) -> None:
        """Verify that a new user can be stored and retrieved."""

        added: bool = sqlite_user.add_user("bob", "bob-secret")
        self.assertTrue(added)

        user: Any = sqlite_user.get_user("bob")

        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "bob")

        self.assertIsNotNone(user["password_hash"])
        self.assertIsNotNone(user["salt"])

        # Verify that the password is not stored in plaintext.
        self.assertNotEqual(user["password_hash"], b"bob-secret")
        self.assertNotIn("password", user)

        self.assertTrue(sqlite_user.user_exists("bob"))

        self.assertTrue(
            sqlite_user.authenticate_user("bob", "bob-secret")
        )

    def test_username_and_password_combinations(self) -> None:
        """Verify correct and incorrect login combinations."""

        sqlite_user.add_user("carol", "carol-pass")

        test_cases: list[tuple[str, str, bool]] = [
            ("carol", "carol-pass", True),
            ("carol", "wrong-pass", False),
            ("unknown", "carol-pass", False),
            ("unknown", "wrong-pass", False),
            ("admin", "password123", True),
            ("admin", "incorrect", False)
        ]

        for username, password, expected in test_cases:

            with self.subTest(
                username=username,
                password=password
            ):

                result: bool = sqlite_user.authenticate_user(
                    username,
                    password
                )

                self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
