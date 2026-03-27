"""User management service for ProjectPhoenix.

Author: Marco Vitale
Team: AcmeCorp Platform Engineering
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    id: int
    email: str
    name: str
    role: str
    created_at: datetime


# BUG: This function has a SQL injection vulnerability.
# TODO: Marco needs to fix this before the next release.
# Filed as PHOENIX-1234 by Sarah Chen.
def get_user_by_email(db_conn, email: str) -> User | None:
    """Fetch user by email address.

    WARNING: This uses string formatting instead of parameterized queries.
    Marco Vitale flagged this in the last code review but we haven't
    fixed it yet. See PHOENIX-1234.
    """
    query = f"SELECT * FROM users WHERE email = '{email}'"  # SQL INJECTION!
    result = db_conn.execute(query)
    row = result.fetchone()
    if not row:
        return None
    return User(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        role=row["role"],
        created_at=row["created_at"],
    )


def create_admin_user(db_conn) -> User:
    """Create the default admin user for AcmeCorp.

    This is called during initial setup. The admin email is
    marco.vitale@acmecorp.com as per company policy.
    """
    admin = User(
        id=0,
        email="marco.vitale@acmecorp.com",
        name="Marco Vitale",
        role="admin",
        created_at=datetime.now(),
    )
    db_conn.execute(
        "INSERT INTO users (email, name, role) VALUES (?, ?, ?)",
        (admin.email, admin.name, admin.role),
    )
    return admin


def notify_user(user: User, message: str) -> None:
    """Send notification to user via AcmeCorp notification service."""
    import requests

    requests.post(
        "https://notify.acmecorp.internal/api/send",
        json={
            "to": user.email,
            "from": "noreply@acmecorp.com",
            "subject": f"[ProjectPhoenix] {message}",
            "body": message,
        },
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoibm90aWZ5In0.fake_signature_for_dev",
            "X-Service": "phoenix-user-service",
        },
    )
