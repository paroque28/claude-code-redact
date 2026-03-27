"""Tests for rdx.core.scanner."""

from __future__ import annotations

import hashlib

from rdx.core.models import Rule
from rdx.core.scanner import Scanner, hash_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aws_key_rule() -> Rule:
    return Rule(
        id="aws-key",
        pattern=r"AKIA[0-9A-Z]{16}",
        is_regex=True,
        category="KEY",
        description="AWS access key",
    )


def _fixed_string_rule() -> Rule:
    return Rule(
        id="name-pablo",
        pattern="pablo",
        is_regex=False,
        category="NAME",
        description="Fixed name match",
    )


def _hashed_rule(original: str) -> Rule:
    """Create a hashed rule whose pattern is the SHA-256 of *original*."""
    return Rule(
        id="hashed-secret",
        pattern=hashlib.sha256(original.encode()).hexdigest(),
        is_regex=True,  # ignored for hashed matching
        hashed=True,
        hash_extractor=r"\b\S+\b",
        category="KEY",
        description="Hashed secret",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRegexMatching:
    def test_aws_key_detected(self) -> None:
        scanner = Scanner([_aws_key_rule()])
        text = "my key is AKIAIOSFODNN7EXAMPLE ok?"
        matches = scanner.scan(text)
        assert len(matches) == 1
        assert matches[0].text == "AKIAIOSFODNN7EXAMPLE"
        assert matches[0].rule.id == "aws-key"
        assert matches[0].start == 10
        assert matches[0].end == 30

    def test_multiple_aws_keys(self) -> None:
        scanner = Scanner([_aws_key_rule()])
        text = "AKIAIOSFODNN7EXAMPLE and AKIA1234567890ABCDEF"
        matches = scanner.scan(text)
        assert len(matches) == 2
        assert matches[0].text == "AKIAIOSFODNN7EXAMPLE"
        assert matches[1].text == "AKIA1234567890ABCDEF"


class TestFixedStringMatching:
    def test_fixed_string_found(self) -> None:
        scanner = Scanner([_fixed_string_rule()])
        matches = scanner.scan("hello pablo, welcome")
        assert len(matches) == 1
        assert matches[0].text == "pablo"
        assert matches[0].start == 6
        assert matches[0].end == 11

    def test_fixed_string_special_chars(self) -> None:
        """re.escape must protect special regex characters."""
        rule = Rule(id="dot", pattern="a.b", is_regex=False, category="CUSTOM")
        scanner = Scanner([rule])
        # "a.b" should NOT match "axb" when is_regex=False
        assert scanner.scan("axb") == []
        assert len(scanner.scan("a.b")) == 1


class TestHashedMatching:
    def test_hashed_match_found(self) -> None:
        secret = "super-secret-token"
        scanner = Scanner([_hashed_rule(secret)])
        text = f"prefix {secret} suffix"
        matches = scanner.scan(text)
        assert len(matches) == 1
        assert matches[0].text == secret
        assert matches[0].segment_hash == hash_text(secret)

    def test_hashed_no_match(self) -> None:
        scanner = Scanner([_hashed_rule("real-secret")])
        matches = scanner.scan("nothing interesting here")
        assert matches == []

    def test_hashed_whole_text_without_extractor(self) -> None:
        secret = "entire-text-is-secret"
        rule = Rule(
            id="hashed-whole",
            pattern=hash_text(secret),
            hashed=True,
            hash_extractor=None,
            category="KEY",
        )
        scanner = Scanner([rule])
        matches = scanner.scan(secret)
        assert len(matches) == 1
        assert matches[0].start == 0
        assert matches[0].end == len(secret)


class TestTargetFiltering:
    def test_llm_rule_skipped_for_tool_target(self) -> None:
        rule = Rule(id="llm-only", pattern="secret", is_regex=False, target="llm", category="KEY")
        scanner = Scanner([rule])
        assert scanner.scan("secret", target="tool") == []

    def test_llm_rule_matches_for_llm_target(self) -> None:
        rule = Rule(id="llm-only", pattern="secret", is_regex=False, target="llm", category="KEY")
        scanner = Scanner([rule])
        assert len(scanner.scan("secret", target="llm")) == 1

    def test_both_target_always_matches(self) -> None:
        rule = Rule(id="any", pattern="secret", is_regex=False, target="both", category="KEY")
        scanner = Scanner([rule])
        assert len(scanner.scan("secret", target="llm")) == 1
        assert len(scanner.scan("secret", target="tool")) == 1


class TestToolFiltering:
    def test_tool_specific_rule_matches_correct_tool(self) -> None:
        rule = Rule(
            id="bash-only", pattern="pwd", is_regex=False, tool="Bash", category="CUSTOM"
        )
        scanner = Scanner([rule])
        assert len(scanner.scan("pwd", tool_name="Bash")) == 1

    def test_tool_specific_rule_skipped_for_wrong_tool(self) -> None:
        rule = Rule(
            id="bash-only", pattern="pwd", is_regex=False, tool="Bash", category="CUSTOM"
        )
        scanner = Scanner([rule])
        assert scanner.scan("pwd", tool_name="Read") == []

    def test_tool_none_rule_matches_any_tool(self) -> None:
        rule = Rule(id="any-tool", pattern="pwd", is_regex=False, tool=None, category="CUSTOM")
        scanner = Scanner([rule])
        assert len(scanner.scan("pwd", tool_name="Bash")) == 1
        assert len(scanner.scan("pwd", tool_name="Read")) == 1
        assert len(scanner.scan("pwd", tool_name=None)) == 1


class TestEdgeCases:
    def test_no_matches_returns_empty(self) -> None:
        scanner = Scanner([_aws_key_rule()])
        assert scanner.scan("nothing here") == []

    def test_rules_without_pattern_are_excluded(self) -> None:
        rule = Rule(id="no-pat", pattern=None, category="CUSTOM")
        scanner = Scanner([rule])
        assert scanner.rules == []

    def test_multiple_rules_produce_multiple_matches(self) -> None:
        rules = [_aws_key_rule(), _fixed_string_rule()]
        scanner = Scanner(rules)
        text = "pablo has key AKIAIOSFODNN7EXAMPLE"
        matches = scanner.scan(text)
        assert len(matches) == 2
        texts = {m.text for m in matches}
        assert texts == {"pablo", "AKIAIOSFODNN7EXAMPLE"}
