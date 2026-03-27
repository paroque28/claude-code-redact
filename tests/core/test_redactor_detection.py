"""Tests for detection layer integration in Redactor."""

from __future__ import annotations

import pytest

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name_rule() -> Rule:
    return Rule(
        id="name-pablo",
        pattern="pablo",
        is_regex=False,
        action="redact",
        replacement="peter",
        category="NAME",
        description="Redact name",
    )


def _password_rule() -> Rule:
    """A rule that matches password= assignments (overlaps with context detection)."""
    return Rule(
        id="password-pattern",
        pattern=r'password\s*=\s*"([^"]+)"',
        is_regex=True,
        action="redact",
        category="KEY",
        description="Password assignment pattern",
    )


# ---------------------------------------------------------------------------
# Context detection
# ---------------------------------------------------------------------------

class TestContextDetection:
    def test_catches_password_assignment(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact('password = "secret123"')
        assert result.redacted_text is not None
        assert "secret123" not in result.redacted_text

    def test_catches_token_assignment(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact('api_key = "myapikey1234"')
        assert result.redacted_text is not None
        assert "myapikey1234" not in result.redacted_text

    def test_catches_bearer_token(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact("Authorization: Bearer tok_abc123xyz789")
        assert result.redacted_text is not None
        assert "tok_abc123xyz789" not in result.redacted_text

    def test_catches_connection_string_password(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact("postgres://user:s3cretP4ss@localhost:5432/db")
        assert result.redacted_text is not None
        assert "s3cretP4ss" not in result.redacted_text

    def test_disabled_context_misses_password(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=False)
        result = redactor.redact('password = "secret123"')
        assert result.redacted_text is not None
        assert "secret123" in result.redacted_text


# ---------------------------------------------------------------------------
# Entropy detection
# ---------------------------------------------------------------------------

class TestEntropyDetection:
    def test_catches_high_entropy_string(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=True)
        # Long random-looking string with high entropy
        result = redactor.redact(
            'TOKEN = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN"'
        )
        assert result.redacted_text is not None
        assert "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN" not in result.redacted_text

    def test_does_not_catch_short_strings(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=True)
        result = redactor.redact('VAR = "hello"')
        assert result.redacted_text is not None
        assert "hello" in result.redacted_text

    def test_disabled_entropy_misses_high_entropy(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=False)
        result = redactor.redact(
            'TOKEN = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN"'
        )
        assert result.redacted_text is not None
        assert "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN" in result.redacted_text


# ---------------------------------------------------------------------------
# Both disabled — rules only
# ---------------------------------------------------------------------------

class TestRulesOnly:
    def test_only_rule_matches_when_detection_disabled(self) -> None:
        cache = MappingCache()
        redactor = Redactor(
            [_name_rule()], cache,
            use_context=False, use_entropy=False,
        )
        text = 'pablo set password = "secret123"'
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "pablo" not in result.redacted_text
        assert "peter" in result.redacted_text
        # password not caught since context detection is off and no pattern rule
        assert "secret123" in result.redacted_text


# ---------------------------------------------------------------------------
# Presidio detection
# ---------------------------------------------------------------------------

class TestPresidioDetection:
    def test_catches_person_name(self) -> None:
        pytest.importorskip("presidio_analyzer")
        cache = MappingCache()
        redactor = Redactor(
            [], cache,
            use_context=False, use_entropy=False, use_presidio=True,
        )
        result = redactor.redact("My colleague John Smith sent me a message.")
        assert result.redacted_text is not None
        assert "John Smith" not in result.redacted_text

    def test_disabled_presidio_does_not_catch_names(self) -> None:
        cache = MappingCache()
        redactor = Redactor(
            [], cache,
            use_context=False, use_entropy=False, use_presidio=False,
        )
        result = redactor.redact("My colleague John Smith sent me a message.")
        assert result.redacted_text is not None
        assert "John Smith" in result.redacted_text


# ---------------------------------------------------------------------------
# Token generation for detection matches
# ---------------------------------------------------------------------------

class TestDetectionTokens:
    def test_context_match_gets_rdx_token(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact('password = "mysecretvalue"')
        assert result.redacted_text is not None
        assert "__RDX_KEY_" in result.redacted_text

    def test_entropy_match_gets_rdx_token(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=True)
        result = redactor.redact(
            'KEY = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN"'
        )
        assert result.redacted_text is not None
        assert "__RDX_KEY_" in result.redacted_text

    def test_detection_token_in_mapping_cache(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        redactor.redact('token = "mytoken1234"')
        # The mapping cache should contain the redacted value
        redactions = cache.get_all_redactions()
        originals = [r.original for r in redactions]
        assert "mytoken1234" in originals

    def test_detection_token_is_unredactable(self) -> None:
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        result = redactor.redact('secret = "unredact_me_123"')
        assert result.redacted_text is not None
        # Find the token in the output
        import re
        tokens = re.findall(r"__RDX_\w+__", result.redacted_text)
        assert len(tokens) == 1
        # Unredact via cache
        original = cache.unredact(tokens[0])
        assert original == "unredact_me_123"


# ---------------------------------------------------------------------------
# Deduplication of overlapping detection + rule matches
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_overlapping_context_and_rule_match_deduped(self) -> None:
        """When a rule and context detection match the same span, only one
        redaction is applied (the longer match wins)."""
        cache = MappingCache()
        # Use a rule that matches "secret123" and context detection that also
        # catches it from password = "secret123"
        secret_rule = Rule(
            id="fixed-secret",
            pattern="secret123",
            is_regex=False,
            action="redact",
            category="KEY",
            description="Fixed secret pattern",
        )
        redactor = Redactor(
            [secret_rule], cache,
            use_context=True, use_entropy=False,
        )
        result = redactor.redact('password = "secret123"')
        assert result.redacted_text is not None
        assert "secret123" not in result.redacted_text
        # Should not have duplicate replacements for the same span
        import re
        tokens = re.findall(r"__RDX_\w+__", result.redacted_text)
        assert len(tokens) == 1

    def test_adjacent_non_overlapping_matches_both_applied(self) -> None:
        """Two detection matches that don't overlap should both be applied."""
        cache = MappingCache()
        redactor = Redactor(
            [_name_rule()], cache,
            use_context=True, use_entropy=False,
        )
        text = 'pablo set password = "longpassword1234"'
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "pablo" not in result.redacted_text
        assert "peter" in result.redacted_text
        assert "longpassword1234" not in result.redacted_text
