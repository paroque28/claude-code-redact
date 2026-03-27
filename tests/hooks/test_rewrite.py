"""Tests for Bash command rewriting."""

from rdx.core.mappings import MappingCache
from rdx.core.unredactor import Unredactor
from rdx.hooks.rewrite import rewrite_command


def _make_unredactor(cache: MappingCache | None = None) -> Unredactor:
    if cache is None:
        cache = MappingCache()
    return Unredactor(cache)


class TestRewriteCommand:
    def test_rewrites_plain_command(self) -> None:
        """A normal command gets prefixed with 'rdx'."""
        unredactor = _make_unredactor()
        result = rewrite_command("cat /etc/hosts", unredactor)
        assert result == "rdx cat /etc/hosts"

    def test_returns_none_for_already_wrapped(self) -> None:
        """Commands already starting with 'rdx ' are not double-wrapped."""
        unredactor = _make_unredactor()
        result = rewrite_command("rdx cat /etc/hosts", unredactor)
        assert result is None

    def test_returns_none_for_already_wrapped_with_whitespace(self) -> None:
        """Leading whitespace is stripped before checking for 'rdx ' prefix."""
        unredactor = _make_unredactor()
        result = rewrite_command("  rdx cat /etc/hosts", unredactor)
        assert result is None

    def test_unredacts_before_rewriting(self) -> None:
        """Redaction tokens in the command are un-redacted before wrapping."""
        cache = MappingCache()
        # Simulate a prior redaction: "pablo" was replaced with "peter"
        cache.get_or_create("name-rule", "pablo", "NAME", "peter")

        unredactor = Unredactor(cache)
        result = rewrite_command("echo peter", unredactor)
        assert result == "rdx echo pablo"

    def test_empty_command(self) -> None:
        """Empty command gets wrapped (caller should check for empty before calling)."""
        unredactor = _make_unredactor()
        result = rewrite_command("", unredactor)
        # Empty stripped string does not start with "rdx ", so it gets wrapped
        assert result == "rdx "
