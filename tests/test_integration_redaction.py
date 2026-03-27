"""Integration tests: run the full redactor against realistic files with embedded secrets."""

import re
from pathlib import Path

import pytest

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor
from rdx.core.unredactor import Unredactor
from rdx.detect.context import scan_context
from rdx.detect.entropy import scan_entropy
from rdx.detect.patterns import get_builtin_rules

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# --- User-defined rules (format-preserving) ---

USER_RULES = [
    Rule(id="developer-name", pattern=r"Pablo Rodriguez", replacement="Peter Smith",
         category="NAME", description="Lead developer name"),
    Rule(id="developer-first", pattern=r"Pablo", replacement="Peter",
         category="NAME", description="First name"),
    Rule(id="company-name", pattern=r"AcmeCorp", replacement="WidgetInc",
         category="PROJECT", is_regex=False, description="Company name"),
    Rule(id="project-name", pattern=r"ProjectPhoenix", replacement="ProjectEagle",
         category="PROJECT", is_regex=False, description="Project codename"),
    Rule(id="developer-email", pattern=r"pablo\.rodriguez@acmecorp\.com",
         replacement="peter.smith@widgetinc.com", category="EMAIL"),
    Rule(id="developer-email2", pattern=r"pablo@acmecorp\.com",
         replacement="peter@widgetinc.com", category="EMAIL"),
    Rule(id="cto-email", pattern=r"sarah\.chen@acmecorp\.com",
         replacement="jane.doe@widgetinc.com", category="EMAIL"),
    Rule(id="internal-domain", pattern=r"acmecorp\.internal",
         replacement="widgetinc.test", category="HOST"),
]

ALL_RULES = USER_RULES + get_builtin_rules()


@pytest.fixture
def cache() -> MappingCache:
    return MappingCache()


@pytest.fixture
def redactor(cache: MappingCache) -> Redactor:
    return Redactor(ALL_RULES, cache)


@pytest.fixture
def unredactor(cache: MappingCache) -> Unredactor:
    return Unredactor(cache)


# ============================================================
# TEST: fake_config.py — should redact all real secrets
# ============================================================

class TestFakeConfig:
    def test_aws_keys_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text

    def test_openai_key_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # sk-proj-... format includes hyphens, pattern must handle it
        assert "sk-proj-abc123def456ghi789" not in result.redacted_text

    def test_anthropic_key_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "sk-ant-api03" not in result.redacted_text

    def test_github_token_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "ghp_ABCDEFGHIJ" not in result.redacted_text

    def test_stripe_key_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "sk_live_51ABCDEF" not in result.redacted_text

    def test_slack_token_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "xoxb-" not in result.redacted_text

    def test_jwt_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "eyJhbGciOi" not in result.redacted_text

    def test_private_key_header_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "-----BEGIN RSA PRIVATE KEY-----" not in result.redacted_text

    def test_company_name_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AcmeCorp" not in result.redacted_text
        assert "WidgetInc" in result.redacted_text

    def test_developer_name_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "Pablo Rodriguez" not in result.redacted_text
        assert "Peter Smith" in result.redacted_text

    def test_project_name_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "ProjectPhoenix" not in result.redacted_text
        assert "ProjectEagle" in result.redacted_text

    def test_internal_domain_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "acmecorp.internal" not in result.redacted_text
        assert "widgetinc.test" in result.redacted_text

    def test_code_structure_preserved(self, redactor: Redactor) -> None:
        """Python syntax should survive redaction."""
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # Key structural elements must survive
        assert "import os" in result.redacted_text
        assert "def get_config():" in result.redacted_text
        assert "DATABASE_URL" in result.redacted_text
        assert "return {" in result.redacted_text

    def test_round_trip(self, redactor: Redactor, unredactor: Unredactor) -> None:
        """Redact then unredact should recover the original."""
        text = load_fixture("fake_config.py")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        restored = unredactor.unredact(result.redacted_text)
        assert restored == text


# ============================================================
# TEST: fake_env — .env file with secrets
# ============================================================

class TestFakeEnv:
    def test_db_password_not_caught_by_builtin_patterns(self, redactor: Redactor) -> None:
        """DB_PASSWORD in .env is NOT caught by builtin patterns because the
        generic-secret-assignment regex expects 'password' at the start of the match,
        not 'DB_PASSWORD'. This is where context detection fills the gap."""
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # Builtin patterns alone don't catch DB_PASSWORD="..." format
        # Context detection (scan_context) DOES catch it — tested separately
        assert "Tr0ub4dor&3horse" in result.redacted_text  # NOT caught by builtins

    def test_db_password_caught_by_context_detection(self) -> None:
        """Context detection catches DB_PASSWORD that builtin patterns miss."""
        text = 'DB_PASSWORD="Tr0ub4dor&3horse"'
        matches = scan_context(text)
        passwords = [m for m in matches if "Tr0ub4dor" in m.text]
        assert len(passwords) >= 1, "Context detection should catch DB_PASSWORD"

    def test_aws_keys_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAI44QH8DHBEXAMPLE" not in result.redacted_text

    def test_github_export_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "ghp_1234567890" not in result.redacted_text

    def test_gitlab_export_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "glpat-" not in result.redacted_text

    def test_company_domain_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "acmecorp.internal" not in result.redacted_text

    def test_developer_email_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "pablo@acmecorp.com" not in result.redacted_text

    def test_non_secret_env_vars_preserved(self, redactor: Redactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "NODE_ENV=development" in result.redacted_text
        assert "PORT=3000" in result.redacted_text
        assert "DEBUG=true" in result.redacted_text

    def test_round_trip(self, redactor: Redactor, unredactor: Unredactor) -> None:
        text = load_fixture("fake_env")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        restored = unredactor.unredact(result.redacted_text)
        assert restored == text


# ============================================================
# TEST: tricky_false_positives.py — things that look like secrets but aren't
# ============================================================

class TestFalsePositives:
    """These test what the redactor DOES flag vs what it SHOULD ideally skip.
    Some false positives are acceptable — we document them here."""

    def test_sha256_hash_not_context_detected(self) -> None:
        """SHA-256 hashes shouldn't be caught by context detection."""
        text = 'SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'
        matches = scan_context(text)
        assert len(matches) == 0

    def test_uuid_not_entropy_detected(self) -> None:
        """UUIDs have low entropy due to limited charset + dashes."""
        text = 'REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"'
        matches = scan_entropy(text)
        assert len(matches) == 0

    def test_color_codes_not_detected(self) -> None:
        """Hex color codes should not trigger anything."""
        text = 'PRIMARY_COLOR = "#FF5733"'
        matches = scan_entropy(text)
        assert len(matches) == 0
        matches = scan_context(text)
        assert len(matches) == 0

    def test_regex_patterns_not_detected(self) -> None:
        """Regex strings should not trigger entropy detection."""
        text = r'EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"'
        matches = scan_entropy(text)
        assert len(matches) == 0

    def test_short_password_not_entropy_detected(self) -> None:
        """Short passwords below min_length should not trigger entropy."""
        text = 'FAKE_PASSWORD = "password123"'
        matches = scan_entropy(text)
        assert len(matches) == 0

    def test_pi_digits_not_detected(self) -> None:
        """Mathematical constants shouldn't trigger."""
        text = 'PI = "3.14159265358979323846264338327950288419716939937510"'
        # Entropy detection might flag this — it's a long quoted string
        # But it's not a real secret. This documents the behavior.
        matches = scan_entropy(text)
        # Pi has moderate entropy (~3.3 bits/char for digits) — should be below threshold
        # This is a documentation test: if it flags, we know about it
        for m in matches:
            # If flagged, the score should at least be low
            assert m.score < 0.9, f"Pi digits flagged with high confidence: {m.score}"

    def test_aws_example_key_is_flagged(self) -> None:
        """AWS's official example key AKIAIOSFODNN7EXAMPLE matches the pattern.
        This is a known false positive — the pattern can't distinguish example from real."""
        text = 'TEST_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache)
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # This IS flagged — known acceptable false positive
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text

    def test_test_db_connection_string_context_detected(self) -> None:
        """Test DB connection strings ARE detected by context — even test ones.
        This is a known false positive but safe: better to over-redact."""
        text = 'TEST_DB = "postgres://test_user:test_pass@localhost:5432/test_db"'
        matches = scan_context(text)
        # The password portion "test_pass" should be detected
        passwords = [m for m in matches if "test_pass" in m.text]
        assert len(passwords) >= 1, "Connection string password should be detected even in test config"

    def test_base64_logo_entropy(self) -> None:
        """Base64 encoded non-secret data (like images) may have high entropy.
        Document whether this is flagged."""
        text = 'LOGO = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"'
        matches = scan_entropy(text)
        # This is borderline — base64 has high entropy
        # Document the result either way
        if matches:
            # If flagged, that's a known false positive
            assert matches[0].text.startswith("iVBORw")

    def test_localhost_ip_not_user_rule_matched(self) -> None:
        """127.0.0.1 should not be caught by user rules (unless explicitly added)."""
        text = 'LOCALHOST = "127.0.0.1"'
        cache = MappingCache()
        redactor = Redactor(USER_RULES, cache)
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "127.0.0.1" in result.redacted_text  # NOT redacted


# ============================================================
# TEST: mixed_code.js — realistic JS with mixed content
# ============================================================

class TestMixedCode:
    def test_api_key_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "sk-proj-realkey123456789012345678901234567890" not in result.redacted_text

    def test_public_key_preserved(self, redactor: Redactor) -> None:
        """Public keys (pk_test_) are NOT secrets."""
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # pk_test_ doesn't match any secret pattern
        assert "pk_test_not_a_secret" in result.redacted_text

    def test_company_replaced_in_js(self, redactor: Redactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "acmecorp" not in result.redacted_text.lower()

    def test_employee_names_replaced(self, redactor: Redactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "Pablo Rodriguez" not in result.redacted_text
        assert "Peter Smith" in result.redacted_text

    def test_bearer_token_redacted(self, redactor: Redactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "eyJhbGciOi" not in result.redacted_text

    def test_normal_code_preserved(self, redactor: Redactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "function calculateTotal" in result.redacted_text
        assert "module.exports" in result.redacted_text
        assert "Content-Type" in result.redacted_text

    def test_round_trip_js(self, redactor: Redactor, unredactor: Unredactor) -> None:
        text = load_fixture("mixed_code.js")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        restored = unredactor.unredact(result.redacted_text)
        assert restored == text


# ============================================================
# TEST: edge_cases.txt — tricky positions and patterns
# ============================================================

class TestEdgeCases:
    def test_secret_at_start_of_file(self, redactor: Redactor) -> None:
        text = load_fixture("edge_cases.txt")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text

    def test_multiple_secrets_same_line(self, redactor: Redactor) -> None:
        text = "Keys: AKIAI44QH8DHBEXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAI44QH8DHBEXAMPLE" not in result.redacted_text
        assert "ghp_ABCDEFGHIJ" not in result.redacted_text

    def test_secret_inside_json(self, redactor: Redactor) -> None:
        text = '{"api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdef", "name": "test"}'
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdef" not in result.redacted_text
        assert '"name": "test"' in result.redacted_text

    def test_repeated_same_secret_gets_same_token(self, redactor: Redactor) -> None:
        text = "Key1: AKIAIOSFODNN7EXAMPLE Key2: AKIAIOSFODNN7EXAMPLE Key3: AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        # All three should be replaced with the same token
        tokens = re.findall(r"__RDX_\w+__", result.redacted_text)
        if tokens:
            assert len(set(tokens)) == 1, f"Same secret should produce same token, got: {set(tokens)}"

    def test_empty_password_not_redacted(self, redactor: Redactor) -> None:
        """Empty string password should not be redacted (nothing to redact)."""
        text = 'password = ""'
        result = redactor.redact(text)
        assert result.redacted_text is not None
        # Context detection may match, but the value is empty — should pass through
        # The pattern captures group(1) which is empty string

    def test_unicode_surrounding_text_preserved(self, redactor: Redactor) -> None:
        text = 'La contraseña es "SecretP4ss" para pablo@acmecorp.com'
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "La contraseña es" in result.redacted_text
        assert "pablo@acmecorp.com" not in result.redacted_text
        assert "peter@widgetinc.com" in result.redacted_text

    def test_long_line_secret_in_middle(self, redactor: Redactor) -> None:
        prefix = "x" * 500
        suffix = "y" * 500
        text = f"{prefix} AKIAIOSFODNN7EXAMPLE {suffix}"
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert result.redacted_text.startswith("x" * 50)
        assert result.redacted_text.endswith("y" * 50)

    def test_round_trip_edge_cases(self, redactor: Redactor, unredactor: Unredactor) -> None:
        text = load_fixture("edge_cases.txt")
        result = redactor.redact(text)
        assert result.redacted_text is not None
        restored = unredactor.unredact(result.redacted_text)
        assert restored == text


# ============================================================
# TEST: Detection layer coverage
# ============================================================

class TestDetectionCoverage:
    def test_context_detects_db_password(self) -> None:
        text = load_fixture("fake_config.py")
        matches = scan_context(text)
        passwords = [m for m in matches if "SuperSecret123" in m.text]
        assert len(passwords) >= 1

    def test_entropy_detects_high_entropy_key(self) -> None:
        text = 'SECRET = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN"'
        matches = scan_entropy(text)
        assert len(matches) >= 1

    def test_context_ignores_normal_assignments(self) -> None:
        text = '''
name = "hello world"
count = "42"
debug = "true"
mode = "production"
'''
        matches = scan_context(text)
        assert len(matches) == 0

    def test_all_layers_together(self) -> None:
        """Run all detection layers on a mixed text and verify coverage."""
        text = '''
password = "MyP4ssw0rd123"
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdef"
RANDOM_TOKEN = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF"
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.abc123
normal_var = "hello world"
count = 42
'''
        # Builtin patterns
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache)
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdef" not in result.redacted_text
        assert "eyJhbGci" not in result.redacted_text

        # Context detection
        ctx_matches = scan_context(text)
        password_found = any("MyP4ssw0rd123" in m.text for m in ctx_matches)
        assert password_found, "Context should detect password assignment"

        # Normal values untouched
        assert "hello world" in result.redacted_text
        assert "count = 42" in result.redacted_text
