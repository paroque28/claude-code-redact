# This file contains things that LOOK like secrets but aren't.
# A good redactor should NOT flag most of these.

# 1. Example/placeholder values in documentation
API_KEY_EXAMPLE = "sk-your-api-key-here"  # placeholder, not a real key
EXAMPLE_TOKEN = "ghp_REPLACE_WITH_YOUR_TOKEN"

# 2. Test constants with known fake values
TEST_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's official example key — actually IS a pattern match
FAKE_PASSWORD = "password123"  # too short/low entropy for entropy detection

# 3. Hash strings (look high-entropy but are checksums, not secrets)
SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MD5_HASH = "d41d8cd98f00b204e9800998ecf8427e"
GIT_COMMIT = "a1b2c3d4e5f6789012345678901234567890abcd"

# 4. Base64 encoded non-secret data
LOGO_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
CSS_FONT_BASE64 = "d09GRgABAAAAAAZAAAsAAAAABfQAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAABH"

# 5. UUIDs (formatted, low entropy despite looking random)
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"
SESSION_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

# 6. Version strings and build numbers
VERSION = "v3.14.159-beta.2+build.12345"
BUILD_HASH = "abc123def456"  # short, not a secret

# 7. Regular expressions (contain special chars, look weird)
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
URL_REGEX = r"https?://[^\s<>\"']+"

# 8. Color codes and CSS values
PRIMARY_COLOR = "#FF5733"
GRADIENT = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"

# 9. Mathematical constants
PI_DIGITS = "3.14159265358979323846264338327950288419716939937510"
E_DIGITS = "2.71828182845904523536028747135266249775724709369995"

# 10. IP addresses that are clearly internal/documentation
LOCALHOST = "127.0.0.1"
DOCKER_HOST = "172.17.0.1"
DOCUMENTATION_IP = "192.0.2.1"  # RFC 5737 documentation range
EXAMPLE_SERVER = "10.0.0.1"

# 11. Encryption-related but not actual secrets
AES_IV = "0" * 32  # all zeros, clearly not a real IV
SALT = "somesalt"  # developer placeholder

# 12. File paths that contain "secret" or "key" in the name
KEY_FILE_PATH = "/etc/ssl/private/server.key"
SECRET_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

# 13. Code that MENTIONS secrets without containing them
def validate_api_key(key: str) -> bool:
    """Check if api_key starts with 'sk-' prefix."""
    return key.startswith("sk-") and len(key) > 20

# 14. Config keys (the word "key" ≠ a secret)
CACHE_KEY_PREFIX = "myapp:cache:"
SORT_KEY = "created_at"
PRIMARY_KEY = "id"

# 15. Real-looking but explicitly fake connection strings for tests
TEST_DB = "postgres://test_user:test_pass@localhost:5432/test_db"
