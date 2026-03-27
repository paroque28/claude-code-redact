"""Performance tests for redaction on large inputs."""

from __future__ import annotations

import logging
import time

import pytest

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor


def _make_redactor(rules: list[Rule] | None = None) -> Redactor:
    """Create a Redactor with optional rules, disabling slow detectors."""
    if rules is None:
        rules = [
            Rule(
                id="company",
                pattern="AcmeCorp",
                is_regex=False,
                replacement="WidgetInc",
                category="PROJECT",
            ),
            Rule(
                id="person",
                pattern=r"Marco Vitale",
                is_regex=False,
                replacement="Peter Smith",
                category="NAME",
            ),
            Rule(
                id="email",
                pattern=r"[a-zA-Z0-9_.]+@acmecorp\.com",
                replacement="user@widgetinc.com",
                category="EMAIL",
            ),
            Rule(
                id="token",
                pattern=r"acmetk-[a-zA-Z0-9]{20,40}",
                category="KEY",
            ),
        ]
    return Redactor(
        rules,
        MappingCache(),
        use_entropy=False,
        use_context=False,
        use_presidio=False,
    )


class TestLargeFilePerformance:
    """Test that redaction of large files completes without timeout."""

    def test_5mb_file_completes(self) -> None:
        """Redacting a 5MB file should complete in reasonable time."""
        # Use only simple fixed-string rules to avoid regex backtracking
        simple_rules = [
            Rule(
                id="company",
                pattern="AcmeCorp",
                is_regex=False,
                replacement="WidgetInc",
                category="PROJECT",
            ),
            Rule(
                id="person",
                pattern="Marco Vitale",
                is_regex=False,
                replacement="Peter Smith",
                category="NAME",
            ),
        ]
        redactor = Redactor(
            simple_rules,
            MappingCache(),
            use_entropy=False,
            use_context=False,
            use_presidio=False,
        )

        # Build a ~5MB text with scattered sensitive data
        block = (
            "This is a normal line of code with no sensitive data.\n"
            "def process_data(items):\n"
            "    for item in items:\n"
            "        result = transform(item)\n"
            "    return result\n"
        )
        # Each block is ~153 bytes; need ~35000 blocks for 5MB+
        chunks = []
        for i in range(35000):
            chunks.append(block)
            if i % 500 == 0:
                chunks.append(
                    "# Contact Marco Vitale for AcmeCorp details\n"
                )

        text = "".join(chunks)
        assert len(text) > 5_000_000, f"Text is {len(text)} bytes, expected > 5MB"

        start = time.monotonic()
        result = redactor.redact(text, target="both")
        elapsed = time.monotonic() - start

        assert result.redacted_text is not None
        assert "Marco Vitale" not in result.redacted_text
        assert "AcmeCorp" not in result.redacted_text
        # Should complete within 30 seconds (generous for CI)
        assert elapsed < 30, f"Redaction took {elapsed:.1f}s — too slow"

    def test_1mb_warning_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """Text > 1MB should trigger a warning log."""
        # Use only simple fixed-string rules to avoid regex backtracking
        simple_rules = [
            Rule(id="company", pattern="AcmeCorp", is_regex=False,
                 replacement="WidgetInc", category="PROJECT"),
        ]
        redactor = Redactor(
            simple_rules, MappingCache(),
            use_entropy=False, use_context=False, use_presidio=False,
        )
        text = "x" * 1_100_000  # 1.1 MB

        with caplog.at_level(logging.WARNING, logger="rdx.core.redactor"):
            redactor.redact(text, target="both")

        assert any("large text" in r.message.lower() for r in caplog.records)

    def test_small_text_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Text < 1MB should not trigger a warning."""
        redactor = _make_redactor()
        text = "Normal sized text with AcmeCorp mention"

        with caplog.at_level(logging.WARNING, logger="rdx.core.redactor"):
            redactor.redact(text, target="both")

        assert not any("large text" in r.message.lower() for r in caplog.records)

    def test_empty_text(self) -> None:
        """Empty text should return immediately."""
        redactor = _make_redactor()
        result = redactor.redact("", target="both")
        assert result.redacted_text == ""

    def test_1mb_no_matches(self) -> None:
        """1MB of text with no matches should be fast."""
        simple_rules = [
            Rule(id="company", pattern="AcmeCorp", is_regex=False,
                 replacement="WidgetInc", category="PROJECT"),
        ]
        redactor = Redactor(
            simple_rules, MappingCache(),
            use_entropy=False, use_context=False, use_presidio=False,
        )
        text = "clean data line\n" * 70000  # ~1.1MB

        start = time.monotonic()
        result = redactor.redact(text, target="both")
        elapsed = time.monotonic() - start

        assert result.redacted_text == text
        assert elapsed < 10, f"No-match scan took {elapsed:.1f}s"
