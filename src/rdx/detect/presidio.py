"""Optional Presidio wrapper for NLP-based PII detection.

Uses only ``AnalyzerEngine`` (detection), **not** ``AnonymizerEngine``.
Gracefully degrades to a no-op when Presidio is not installed.
"""

from __future__ import annotations

from rdx.core.models import Match, Rule

# Map Presidio entity types to rdx categories.
_ENTITY_TO_CATEGORY: dict[str, str] = {
    "PERSON": "NAME",
    "EMAIL_ADDRESS": "EMAIL",
    "IP_ADDRESS": "IP",
    "PHONE_NUMBER": "CUSTOM",
    "CREDIT_CARD": "KEY",
    "IBAN_CODE": "KEY",
    "US_SSN": "KEY",
    "LOCATION": "CUSTOM",
    "ORGANIZATION": "PROJECT",
    "URL": "HOST",
}

# Lazy-initialised singleton — creating an AnalyzerEngine is expensive because
# it loads the spaCy language model.
_analyzer: object | None = None  # typed as object to avoid import at module level


def _get_analyzer() -> object:
    """Return (and cache) a ``presidio_analyzer.AnalyzerEngine`` instance."""
    global _analyzer  # noqa: PLW0603
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine

        _analyzer = AnalyzerEngine()
    return _analyzer


def is_available() -> bool:
    """Return ``True`` if Presidio is installed and importable."""
    try:
        import presidio_analyzer  # noqa: F401

        return True
    except ImportError:
        return False


def scan_presidio(
    text: str,
    language: str = "en",
    score_threshold: float = 0.5,
) -> list[Match]:
    """Scan *text* using Presidio's ``AnalyzerEngine``.

    Returns an empty list when Presidio is not installed so callers never
    need to guard the import themselves.

    Parameters
    ----------
    text:
        The text to analyse.
    language:
        BCP-47 language code (default ``"en"``).
    score_threshold:
        Minimum Presidio confidence score to include a result.
    """
    if not is_available():
        return []

    from presidio_analyzer import AnalyzerEngine

    analyzer: AnalyzerEngine = _get_analyzer()  # type: ignore[assignment]
    results = analyzer.analyze(
        text=text,
        language=language,
        score_threshold=score_threshold,
    )

    matches: list[Match] = []
    for result in results:
        category = _ENTITY_TO_CATEGORY.get(result.entity_type, "CUSTOM")
        original_text = text[result.start : result.end]
        matches.append(
            Match(
                rule=Rule(
                    id=f"presidio-{result.entity_type.lower()}",
                    pattern=None,
                    action="redact",
                    category=category,
                    description=f"Presidio: {result.entity_type}",
                ),
                start=result.start,
                end=result.end,
                text=original_text,
                entity_type=result.entity_type,
                score=result.score,
            )
        )
    return matches
