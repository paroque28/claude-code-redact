"""Reverses redactions using the in-memory mapping cache."""

from __future__ import annotations

from .mappings import MappingCache


class Unredactor:
    """Reverses redactions using the in-memory mapping cache."""

    def __init__(self, cache: MappingCache) -> None:
        self.cache = cache

    def unredact(self, text: str) -> str:
        """Replace all redaction tokens / replacements with original values."""
        reverse_map = self.cache.get_reverse_map()
        if not reverse_map:
            return text

        # Sort by replacement length (longest first) to avoid partial-match
        # corruption — e.g. replacing "__RDX_NAME_" before "__RDX_NAME_a1b2__".
        result = text
        for replacement, original in sorted(
            reverse_map.items(), key=lambda x: -len(x[0])
        ):
            result = result.replace(replacement, original)

        return result

    def unredact_value(self, token: str) -> str:
        """Un-redact a single token. Returns *token* unchanged if not found."""
        original = self.cache.unredact(token)
        return original if original is not None else token
