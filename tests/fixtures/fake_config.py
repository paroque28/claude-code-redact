# Application configuration
import os

# Database
DATABASE_URL = "postgres://admin:SuperSecret123!@db.acmecorp.internal:5432/production"
REDIS_URL = "redis://default:r3d1s_p4ss@cache.acmecorp.internal:6379"

# AWS
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API Keys
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-ABCDEFGHIJKLM"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
STRIPE_SECRET = "sk_live_51ABCDEFghijklmnopqrstuvwx"

# Internal
COMPANY_NAME = "AcmeCorp"
PROJECT_CODENAME = "ProjectPhoenix"
LEAD_DEVELOPER = "Pablo Rodriguez"
TEAM_EMAIL = "pablo.rodriguez@acmecorp.com"

# Slack
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPqrstuvwx"

# JWT (fake but valid structure)
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# SSH
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hqxnfZwGm0yMhR
FKXnPLLJQYlF7GS5f3EAwnFG+9g4mBzBUTJmKHTbOev1PnRCCMaBGsdN0kPSz3qq
-----END RSA PRIVATE KEY-----"""

def get_config():
    return {
        "db": DATABASE_URL,
        "api_key": os.getenv("API_KEY", "default_key_not_secret"),
    }
