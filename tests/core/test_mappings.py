"""Tests for in-memory mapping cache."""

from rdx.core.mappings import MappingCache


def test_token_generation_determinism() -> None:
    """Same input always produces the same token."""
    cache = MappingCache()
    token1 = cache._generate_token("secret-value", "KEY")
    token2 = cache._generate_token("secret-value", "KEY")
    assert token1 == token2
    assert token1.startswith("__RDX_KEY_")
    assert token1.endswith("__")


def test_token_generation_different_inputs() -> None:
    """Different inputs produce different tokens."""
    cache = MappingCache()
    token1 = cache._generate_token("secret-a", "KEY")
    token2 = cache._generate_token("secret-b", "KEY")
    assert token1 != token2


def test_token_generation_different_categories() -> None:
    """Same input with different categories produces different token prefixes."""
    cache = MappingCache()
    token_key = cache._generate_token("value", "KEY")
    token_name = cache._generate_token("value", "NAME")
    assert "__RDX_KEY_" in token_key
    assert "__RDX_NAME_" in token_name
    # Hash part is the same since input is the same
    # Token format: __RDX_{category}_{hash}__
    # split("_") gives: ['', '', 'RDX', '{category}', '{hash}', '', '']
    assert token_key.split("_")[4] == token_name.split("_")[4]


def test_format_preserving_replacement() -> None:
    """When replacement is provided, use it instead of generating a token."""
    cache = MappingCache()
    result = cache.get_or_create("name-rule", "pablo", "NAME", replacement="peter")
    assert result == "peter"


def test_auto_token_when_no_replacement() -> None:
    """When replacement is None, generate a deterministic token."""
    cache = MappingCache()
    result = cache.get_or_create("key-rule", "AKIAIOSFODNN7EXAMPLE", "KEY")
    assert result.startswith("__RDX_KEY_")
    assert result.endswith("__")


def test_reverse_lookup() -> None:
    """Can look up original value from replacement token."""
    cache = MappingCache()
    token = cache.get_or_create("rule1", "my-secret", "KEY")
    assert cache.unredact(token) == "my-secret"


def test_reverse_lookup_format_preserving() -> None:
    """Can look up original value from format-preserving replacement."""
    cache = MappingCache()
    cache.get_or_create("name-rule", "pablo", "NAME", replacement="peter")
    assert cache.unredact("peter") == "pablo"


def test_reverse_lookup_not_found() -> None:
    """Returns None for unknown tokens."""
    cache = MappingCache()
    assert cache.unredact("__RDX_KEY_nonexist__") is None


def test_cache_deduplication() -> None:
    """Same input returns same token without creating duplicates."""
    cache = MappingCache()
    token1 = cache.get_or_create("rule1", "secret", "KEY")
    token2 = cache.get_or_create("rule1", "secret", "KEY")
    assert token1 == token2
    assert cache.stats()["mappings"] == 1


def test_cache_deduplication_ignores_new_replacement() -> None:
    """Once a mapping exists, the cached value is returned even if a different replacement is passed."""
    cache = MappingCache()
    token1 = cache.get_or_create("rule1", "secret", "KEY", replacement="first")
    token2 = cache.get_or_create("rule1", "secret", "KEY", replacement="second")
    assert token1 == "first"
    assert token2 == "first"
    assert cache.stats()["mappings"] == 1


def test_different_rules_same_original() -> None:
    """Different rule ids with same original produce separate mappings."""
    cache = MappingCache()
    t1 = cache.get_or_create("rule-a", "secret", "KEY")
    t2 = cache.get_or_create("rule-b", "secret", "KEY")
    # Both auto-generated tokens are the same (deterministic from original + category),
    # but the second call creates a new forward entry keyed by (rule-b, secret).
    # However, the reverse map deduplicates by replacement string, so only 1 reverse entry.
    assert t1 == t2
    assert cache.stats()["mappings"] == 2
    # The reverse map has 1 entry because both map to the same token.
    # The second write overwrites the first in _reverse, so only rule-b is there.
    assert cache.stats()["rules"] == 1


def test_clear() -> None:
    """Clear removes all mappings."""
    cache = MappingCache()
    cache.get_or_create("rule1", "secret1", "KEY")
    cache.get_or_create("rule2", "secret2", "NAME", replacement="john")
    assert cache.stats()["mappings"] == 2

    cache.clear()
    assert cache.stats()["mappings"] == 0
    assert cache.stats()["rules"] == 0
    assert cache.unredact("john") is None


def test_stats() -> None:
    """Stats returns correct counts."""
    cache = MappingCache()
    assert cache.stats() == {"mappings": 0, "rules": 0}

    cache.get_or_create("rule1", "secret-a", "KEY")
    cache.get_or_create("rule1", "secret-b", "KEY")
    cache.get_or_create("rule2", "name", "NAME", replacement="peter")

    assert cache.stats() == {"mappings": 3, "rules": 2}


def test_get_reverse_map() -> None:
    """get_reverse_map returns {replacement: original} dict."""
    cache = MappingCache()
    token = cache.get_or_create("rule1", "my-key", "KEY")
    cache.get_or_create("rule2", "pablo", "NAME", replacement="peter")

    reverse = cache.get_reverse_map()
    assert reverse[token] == "my-key"
    assert reverse["peter"] == "pablo"
    assert len(reverse) == 2


def test_get_all_redactions() -> None:
    """get_all_redactions returns list of Redaction objects."""
    cache = MappingCache()
    cache.get_or_create("rule1", "secret", "KEY")
    cache.get_or_create("rule2", "pablo", "NAME", replacement="peter")

    redactions = cache.get_all_redactions()
    assert len(redactions) == 2

    by_rule = {r.rule_id: r for r in redactions}
    assert by_rule["rule1"].original == "secret"
    assert by_rule["rule1"].category == "KEY"
    assert by_rule["rule2"].original == "pablo"
    assert by_rule["rule2"].replacement == "peter"
    assert by_rule["rule2"].category == "NAME"
