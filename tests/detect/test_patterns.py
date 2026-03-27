"""Tests for the built-in regex pattern library."""

import re

from rdx.detect.patterns import get_builtin_rules


class TestBuiltinRulesMetadata:
    """Every rule must carry the required metadata fields."""

    def test_all_rules_have_id(self) -> None:
        for rule in get_builtin_rules():
            assert rule.id, "Rule is missing an id"

    def test_all_rules_have_pattern(self) -> None:
        for rule in get_builtin_rules():
            assert rule.pattern is not None, f"Rule {rule.id!r} is missing a pattern"

    def test_all_rules_have_category(self) -> None:
        for rule in get_builtin_rules():
            assert rule.category, f"Rule {rule.id!r} is missing a category"

    def test_all_patterns_compile(self) -> None:
        for rule in get_builtin_rules():
            assert rule.pattern is not None
            re.compile(rule.pattern)  # must not raise

    def test_default_action_is_redact(self) -> None:
        for rule in get_builtin_rules():
            assert rule.action == "redact", f"Rule {rule.id!r} has action {rule.action!r}"

    def test_reasonable_rule_count(self) -> None:
        rules = get_builtin_rules()
        assert len(rules) >= 10, f"Expected at least 10 rules, got {len(rules)}"

    def test_unique_ids(self) -> None:
        ids = [r.id for r in get_builtin_rules()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


class TestPatternMatching:
    """Patterns match known secret formats."""

    def _match(self, rule_id: str, text: str) -> re.Match[str] | None:
        rules = {r.id: r for r in get_builtin_rules()}
        rule = rules[rule_id]
        assert rule.pattern is not None
        return re.search(rule.pattern, text)

    def test_aws_access_key(self) -> None:
        assert self._match("aws-access-key", "AKIAIOSFODNN7EXAMPLE")

    def test_aws_secret_key(self) -> None:
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert self._match("aws-secret-key", text)

    def test_github_token(self) -> None:
        token = "ghp_" + "a" * 36
        assert self._match("github-token", token)

    def test_github_fine_grained(self) -> None:
        token = "github_pat_" + "a" * 22
        assert self._match("github-fine-grained", token)

    def test_gitlab_token(self) -> None:
        token = "glpat-" + "a" * 20
        assert self._match("gitlab-token", token)

    def test_openai_key(self) -> None:
        key = "sk-" + "a" * 32
        assert self._match("openai-key", key)

    def test_anthropic_key(self) -> None:
        key = "sk-ant-" + "a" * 40
        assert self._match("anthropic-key", key)

    def test_slack_token(self) -> None:
        assert self._match("slack-token", "xoxb-123456-abcdef")

    def test_stripe_key(self) -> None:
        key = "sk_live_" + "a" * 24
        assert self._match("stripe-key", key)

    def test_private_key_rsa(self) -> None:
        assert self._match("private-key", "-----BEGIN RSA PRIVATE KEY-----")

    def test_private_key_generic(self) -> None:
        assert self._match("private-key", "-----BEGIN PRIVATE KEY-----")

    def test_private_key_ec(self) -> None:
        assert self._match("private-key", "-----BEGIN EC PRIVATE KEY-----")

    def test_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123_-xyz"
        assert self._match("jwt", jwt)

    def test_generic_secret_assignment(self) -> None:
        text = 'password = "my_super_secret_value"'
        assert self._match("generic-secret-assignment", text)

    def test_sendgrid_key(self) -> None:
        key = "SG." + "a" * 22 + "." + "b" * 22
        assert self._match("sendgrid-key", key)


class TestNoFalsePositives:
    """Patterns must not match normal, non-secret text."""

    def test_normal_text(self) -> None:
        text = "This is a normal sentence about programming in Python."
        for rule in get_builtin_rules():
            assert rule.pattern is not None
            assert not re.search(
                rule.pattern, text
            ), f"Rule {rule.id!r} matched normal text"

    def test_short_sk_prefix_no_openai(self) -> None:
        # "sk-" followed by too few characters should not match openai-key
        rules = {r.id: r for r in get_builtin_rules()}
        pattern = rules["openai-key"].pattern
        assert pattern is not None
        assert not re.search(pattern, "sk-short")

    def test_random_word_no_aws(self) -> None:
        rules = {r.id: r for r in get_builtin_rules()}
        pattern = rules["aws-access-key"].pattern
        assert pattern is not None
        assert not re.search(pattern, "AKIASHORT")
