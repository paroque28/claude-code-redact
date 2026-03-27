"""AcmeCorp ProjectPhoenix — Application Configuration

Maintained by Marco Vitale <marco.vitale@acmecorp.com>
Last reviewed by Sarah Chen on 2026-03-15
"""

import os

# Database credentials
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgres://phoenix_admin:Kj8mN2pQ4rT6vX@db.acmecorp.internal:5432/phoenix_prod"
)

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://default:R3d1sP4ssw0rd!@cache.acmecorp.internal:6379/0"
)

# API keys for third-party services
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sk-proj-dummykey-for-local-dev-only-replace-in-prod-000000000000")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_live_51HG7dKLMnOpQrStUvWxYz")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "SG.abc123def456.ghi789jkl012mno345pqr678stu901vwx")

# Internal services
AUTH_SERVICE_URL = f"https://auth.acmecorp.internal/v2"
NOTIFICATION_SERVICE = f"https://notify.acmecorp.internal/api"
METRICS_ENDPOINT = f"https://metrics.acmecorp.internal:9090"

# Team contact for alerts
ONCALL_EMAIL = "phoenix-oncall@acmecorp.com"
ESCALATION_CONTACT = "Marco Vitale <marco@acmecorp.com>"


class AppConfig:
    """Configuration for ProjectPhoenix application."""

    PROJECT_NAME = "ProjectPhoenix"
    COMPANY = "AcmeCorp"
    VERSION = "2.4.1"
    ENVIRONMENT = os.getenv("APP_ENV", "development")

    # Feature flags
    ENABLE_NEW_BILLING = True
    ENABLE_AUDIT_LOG = True

    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = 100
    MAX_UPLOAD_SIZE_MB = 50

    @classmethod
    def is_production(cls) -> bool:
        return cls.ENVIRONMENT == "production"

    @classmethod
    def get_db_url(cls) -> str:
        """Get database URL, with fallback for local dev."""
        if cls.is_production():
            return DATABASE_URL
        return "postgres://dev:dev@localhost:5432/phoenix_dev"
