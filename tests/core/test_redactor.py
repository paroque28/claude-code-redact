"""Tests for rdx.core.redactor."""

from __future__ import annotations

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name_rule(replacement: str | None = None) -> Rule:
    return Rule(
        id="name-pablo",
        pattern="pablo",
        is_regex=False,
        action="redact",
        replacement=replacement,
        category="NAME",
        description="Redact name",
    )


def _block_rule() -> Rule:
    return Rule(
        id="block-secret",
        pattern=r"SECRET_\w+",
        is_regex=True,
        action="block",
        category="KEY",
        description="Block secrets",
    )


def _warn_rule() -> Rule:
    return Rule(
        id="warn-ip",
        pattern=r"\d{1,3}(?:\.\d{1,3}){3}",
        is_regex=True,
        action="warn",
        category="IP",
        description="Warn on IP address",
    )


def _email_rule(replacement: str | None = None) -> Rule:
    return Rule(
        id="email",
        pattern=r"[\w.+-]+@[\w-]+\.[\w.]+",
        is_regex=True,
        action="redact",
        replacement=replacement,
        category="EMAIL",
        description="Redact email",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRedactAction:
    def test_format_preserving_replacement(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule(replacement="peter")], cache)
        result = redactor.redact("hello pablo")
        assert result.redacted_text == "hello peter"
        assert len(result.matches) == 1

    def test_auto_token_replacement(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule()], cache)
        result = redactor.redact("hello pablo")
        assert result.redacted_text is not None
        assert "pablo" not in result.redacted_text
        assert result.redacted_text.startswith("hello __RDX_NAME_")
        assert result.redacted_text.endswith("__")

    def test_multiple_redactions_positions_correct(self) -> None:
        cache = MappingCache()
        rules = [_name_rule(replacement="peter"), _email_rule(replacement="hidden@example.com")]
        redactor = Redactor(rules, cache)
        text = "pablo wrote to foo@bar.com yesterday"
        result = redactor.redact(text)
        assert result.redacted_text is not None
        assert "pablo" not in result.redacted_text
        assert "foo@bar.com" not in result.redacted_text
        assert "peter" in result.redacted_text
        assert "hidden@example.com" in result.redacted_text

    def test_same_value_matched_twice_gets_same_token(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule()], cache)
        result = redactor.redact("pablo and pablo")
        assert result.redacted_text is not None
        parts = result.redacted_text.split(" and ")
        assert parts[0] == parts[1]  # same token for same original


class TestBlockAction:
    def test_block_returns_block_reasons_no_redacted_text(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_block_rule()], cache)
        result = redactor.redact("value is SECRET_FOO")
        assert result.block_reasons
        assert result.redacted_text is None
        assert len(result.matches) == 1

    def test_block_takes_priority_over_redact(self) -> None:
        """When both block and redact rules match, block wins."""
        cache = MappingCache()
        redactor = Redactor([_name_rule(replacement="peter"), _block_rule()], cache)
        result = redactor.redact("pablo has SECRET_KEY")
        assert result.block_reasons
        assert result.redacted_text is None  # no redacted text when blocked


class TestWarnAction:
    def test_warn_allows_through_with_reasons(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_warn_rule()], cache)
        result = redactor.redact("server at 192.168.1.1")
        assert result.warn_reasons
        assert result.redacted_text == "server at 192.168.1.1"  # not redacted
        assert len(result.matches) == 1

    def test_warn_combined_with_redact(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_warn_rule(), _name_rule(replacement="peter")], cache)
        result = redactor.redact("pablo at 10.0.0.1")
        assert result.warn_reasons
        assert result.redacted_text is not None
        assert "peter" in result.redacted_text
        assert "10.0.0.1" in result.redacted_text  # warn does not alter text


class TestEdgeCases:
    def test_empty_text_returns_empty(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule()], cache)
        result = redactor.redact("")
        assert result.redacted_text == ""
        assert result.matches == []

    def test_no_matches_returns_original(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule()], cache)
        result = redactor.redact("nothing to see here")
        assert result.redacted_text == "nothing to see here"

    def test_mapping_cache_populated_after_redact(self) -> None:
        cache = MappingCache()
        redactor = Redactor([_name_rule(replacement="peter")], cache)
        redactor.redact("hello pablo")
        assert cache.unredact("peter") == "pablo"
        reverse = cache.get_reverse_map()
        assert "peter" in reverse
        assert reverse["peter"] == "pablo"
