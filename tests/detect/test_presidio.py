"""Tests for the optional Presidio wrapper."""

import pytest

from rdx.detect.presidio import is_available, scan_presidio


class TestIsAvailable:
    def test_returns_bool(self) -> None:
        result = is_available()
        assert isinstance(result, bool)

    def test_does_not_raise(self) -> None:
        # Must never crash, even if Presidio is not installed
        is_available()


class TestScanPresidioUnavailable:
    """Tests that always pass, regardless of whether Presidio is installed."""

    def test_returns_list(self) -> None:
        result = scan_presidio("Hello world")
        assert isinstance(result, list)

    def test_no_crash_on_empty_text(self) -> None:
        result = scan_presidio("")
        assert isinstance(result, list)


class TestScanPresidioAvailable:
    """Tests that require Presidio to be installed."""

    @pytest.fixture(autouse=True)
    def _require_presidio(self) -> None:
        pytest.importorskip("presidio_analyzer")

    def test_detects_person_name(self) -> None:
        text = "My name is John Smith and I live in New York."
        matches = scan_presidio(text, score_threshold=0.3)
        entity_types = {m.entity_type for m in matches}
        assert "PERSON" in entity_types

    def test_detects_email(self) -> None:
        text = "Send an email to alice@example.com for details."
        matches = scan_presidio(text)
        entity_types = {m.entity_type for m in matches}
        assert "EMAIL_ADDRESS" in entity_types

    def test_detects_phone_number(self) -> None:
        text = "Call me at 212-555-1234 for more information."
        matches = scan_presidio(text, score_threshold=0.3)
        entity_types = {m.entity_type for m in matches}
        assert "PHONE_NUMBER" in entity_types

    def test_match_has_correct_text(self) -> None:
        text = "Contact alice@example.com please."
        matches = scan_presidio(text)
        email_matches = [m for m in matches if m.entity_type == "EMAIL_ADDRESS"]
        assert len(email_matches) >= 1
        assert email_matches[0].text == "alice@example.com"

    def test_match_positions(self) -> None:
        text = "Contact alice@example.com please."
        matches = scan_presidio(text)
        email_matches = [m for m in matches if m.entity_type == "EMAIL_ADDRESS"]
        assert len(email_matches) >= 1
        m = email_matches[0]
        assert text[m.start : m.end] == m.text

    def test_match_rule_metadata(self) -> None:
        text = "Email: alice@example.com"
        matches = scan_presidio(text)
        email_matches = [m for m in matches if m.entity_type == "EMAIL_ADDRESS"]
        assert len(email_matches) >= 1
        rule = email_matches[0].rule
        assert rule.id == "presidio-email_address"
        assert rule.category == "EMAIL"
        assert rule.action == "redact"

    def test_score_threshold_filters(self) -> None:
        text = "Contact alice@example.com."
        high = scan_presidio(text, score_threshold=0.99)
        low = scan_presidio(text, score_threshold=0.01)
        assert len(low) >= len(high)

    def test_normal_text_few_matches(self) -> None:
        text = "The weather is nice today."
        matches = scan_presidio(text, score_threshold=0.7)
        # Normal text should produce very few (if any) high-confidence matches
        assert len(matches) <= 2
