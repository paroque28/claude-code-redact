"""In-memory bidirectional mapping cache for redaction tokens."""

import hashlib

from .models import Category, Redaction


class MappingCache:
    """In-memory bidirectional mapping cache for redaction tokens.

    No file persistence -- everything lives in process memory.
    Forward map: (rule_id, original) -> replacement
    Reverse map: replacement -> Redaction
    """

    def __init__(self) -> None:
        # Forward: (rule_id, original) -> replacement
        self._forward: dict[tuple[str, str], str] = {}
        # Reverse: replacement -> Redaction
        self._reverse: dict[str, Redaction] = {}

    def get_or_create(
        self,
        rule_id: str,
        original: str,
        category: Category,
        replacement: str | None = None,
    ) -> str:
        """Get existing mapping or create new one.

        If replacement is provided (format-preserving), use it.
        If None, generate deterministic __RDX_ token.
        """
        key = (rule_id, original)
        if key in self._forward:
            return self._forward[key]

        if replacement is None:
            replacement = self._generate_token(original, category)

        self._forward[key] = replacement
        self._reverse[replacement] = Redaction(
            original=original,
            replacement=replacement,
            rule_id=rule_id,
            category=category,
        )
        return replacement

    @staticmethod
    def _generate_token(original: str, category: Category) -> str:
        """Generate a deterministic redaction token from original text and category."""
        h = hashlib.sha256(original.encode()).hexdigest()[:8]
        return f"__RDX_{category}_{h}__"

    def unredact(self, token: str) -> str | None:
        """Look up original value for a token. Returns None if not found."""
        entry = self._reverse.get(token)
        return entry.original if entry else None

    def get_reverse_map(self) -> dict[str, str]:
        """Get full reverse map {replacement: original} for bulk un-redaction."""
        return {k: v.original for k, v in self._reverse.items()}

    def get_all_redactions(self) -> list[Redaction]:
        """Get all redaction entries for audit/display."""
        return list(self._reverse.values())

    def clear(self) -> None:
        """Clear all mappings."""
        self._forward.clear()
        self._reverse.clear()

    def stats(self) -> dict[str, int]:
        """Return mapping statistics."""
        return {
            "mappings": len(self._forward),
            "rules": len({r.rule_id for r in self._reverse.values()}),
        }
