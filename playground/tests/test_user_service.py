"""Tests for user_service.py

Author: Marco Vitale
These tests use AcmeCorp's standard test database setup.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock

from src.user_service import User, get_user_by_email, create_admin_user


class TestGetUserByEmail:
    def test_returns_user_when_found(self):
        """Test that we can find Marco's admin account."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = {
            "id": 1,
            "email": "marco.vitale@acmecorp.com",
            "name": "Marco Vitale",
            "role": "admin",
            "created_at": datetime(2024, 1, 15),
        }

        user = get_user_by_email(mock_conn, "marco.vitale@acmecorp.com")

        assert user is not None
        assert user.email == "marco.vitale@acmecorp.com"
        assert user.name == "Marco Vitale"
        assert user.role == "admin"

    def test_returns_none_when_not_found(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None

        user = get_user_by_email(mock_conn, "nonexistent@acmecorp.com")
        assert user is None

    def test_sql_injection_vulnerability(self):
        """Document the known SQL injection bug (PHOENIX-1234).

        This test demonstrates the vulnerability Marco flagged.
        The query uses string formatting instead of parameterized queries,
        allowing injection via the email parameter.
        """
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None

        # This malicious input would work due to the string formatting bug
        get_user_by_email(mock_conn, "'; DROP TABLE users; --")

        # Verify the dangerous query was built
        call_args = mock_conn.execute.call_args[0][0]
        assert "DROP TABLE" in call_args  # The injection is present!


class TestCreateAdminUser:
    def test_creates_admin_with_correct_email(self):
        """Admin account uses marco.vitale@acmecorp.com per company policy."""
        mock_conn = MagicMock()

        admin = create_admin_user(mock_conn)

        assert admin.email == "marco.vitale@acmecorp.com"
        assert admin.name == "Marco Vitale"
        assert admin.role == "admin"

    def test_inserts_into_database(self):
        mock_conn = MagicMock()

        create_admin_user(mock_conn)

        mock_conn.execute.assert_called_once()
        args = mock_conn.execute.call_args
        assert "INSERT INTO users" in args[0][0]
