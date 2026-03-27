"""Tests for Shannon entropy-based secret detection."""

import math
import string

from rdx.detect.entropy import ENTROPY_RULE, scan_entropy, shannon_entropy


class TestShannonEntropy:
    """Unit tests for the entropy calculation itself."""

    def test_empty_string_returns_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self) -> None:
        # "ab" repeated → exactly 1.0 bit/char
        assert math.isclose(shannon_entropy("ab"), 1.0)

    def test_four_distinct_chars(self) -> None:
        # "abcd" → 2.0 bits/char
        assert math.isclose(shannon_entropy("abcd"), 2.0)

    def test_high_entropy_random_string(self) -> None:
        # Use all hex digits equally: 16 distinct chars → 4.0 bits/char
        s = "0123456789abcdef"
        assert math.isclose(shannon_entropy(s), 4.0)

    def test_entropy_increases_with_diversity(self) -> None:
        low = shannon_entropy("aaaaabbbbb")
        high = shannon_entropy("abcdefghij")
        assert high > low


class TestScanEntropy:
    """Integration tests for the entropy scanner."""

    def test_high_entropy_base64_detected(self) -> None:
        # A realistic high-entropy base64 string (40 chars)
        secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
        text = f'config_key = "{secret}"'
        matches = scan_entropy(text)
        assert len(matches) >= 1
        assert matches[0].text == secret
        assert matches[0].score > 0.0
        assert matches[0].rule.id == "entropy-detected"

    def test_normal_english_not_detected(self) -> None:
        text = '"the quick brown fox jumps"'
        # English text has lower entropy even if quoted
        matches = scan_entropy(text)
        assert len(matches) == 0

    def test_short_strings_not_detected(self) -> None:
        # Below default min_length of 20
        text = '"abc123"'
        matches = scan_entropy(text)
        assert len(matches) == 0

    def test_custom_min_length(self) -> None:
        secret = "aB3dE5fG7hI9jK1lM"  # 17 chars, high diversity
        text = f'key = "{secret}"'
        # Default min_length=20 should miss it (string too short)
        assert len(scan_entropy(text, min_length=20)) == 0
        # Lowered min_length + lowered threshold should catch it
        assert len(scan_entropy(text, min_length=10, threshold=3.5)) >= 1

    def test_custom_threshold(self) -> None:
        # A string with moderate entropy
        s = "aaabbbcccdddeeefffggg"  # 21 chars, low entropy
        text = f'val = "{s}"'
        # Very low threshold should catch it
        low_matches = scan_entropy(text, threshold=1.0)
        # Very high threshold should miss it
        high_matches = scan_entropy(text, threshold=6.0)
        assert len(low_matches) >= len(high_matches)

    def test_quoted_string_extraction(self) -> None:
        secret = "xK9mW2pQ7rS3tU5vY8zA1bC4dE6fG7hI0jL"
        text = f"some_var = '{secret}'"
        matches = scan_entropy(text)
        assert len(matches) >= 1
        found_texts = [m.text for m in matches]
        assert secret in found_texts

    def test_unquoted_assignment_extraction(self) -> None:
        secret = "xK9mW2pQ7rS3tU5vY8zA1bC4dE6fG7hI0jL"
        text = f"SOME_VAR= {secret}\n"
        matches = scan_entropy(text)
        assert len(matches) >= 1
        found_texts = [m.text for m in matches]
        assert secret in found_texts

    def test_entropy_rule_is_shared(self) -> None:
        secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
        text = f'a = "{secret}"'
        matches = scan_entropy(text)
        assert len(matches) >= 1
        assert matches[0].rule is ENTROPY_RULE

    def test_score_normalised_below_one(self) -> None:
        secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
        text = f'x = "{secret}"'
        matches = scan_entropy(text)
        assert len(matches) >= 1
        assert 0.0 < matches[0].score <= 1.0

    def test_no_duplicate_spans(self) -> None:
        # A string that could match both quoted and assignment patterns
        secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
        text = f'x = "{secret}";'
        matches = scan_entropy(text)
        spans = [(m.start, m.end) for m in matches]
        assert len(spans) == len(set(spans))
