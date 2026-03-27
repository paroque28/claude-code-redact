"""Applies redactions to text using the scanner and mapping cache."""

from __future__ import annotations

from .mappings import MappingCache
from .models import Match, ScanResult
from .scanner import Scanner
from .models import Rule


class Redactor:
    """Applies redactions to text, building the mapping cache."""

    def __init__(self, rules: list[Rule], cache: MappingCache) -> None:
        self.scanner = Scanner(rules)
        self.cache = cache
        self.rules = rules

    def redact(
        self,
        text: str,
        target: str = "both",
        tool_name: str | None = None,
    ) -> ScanResult:
        """Scan *text* and apply redactions / blocks / warns."""
        matches = self.scanner.scan(text, target, tool_name)

        if not matches:
            return ScanResult(matches=[], redacted_text=text)

        block_reasons: list[str] = []
        warn_reasons: list[str] = []
        redact_matches: list[Match] = []

        for match in matches:
            reason = f"[{match.rule.id}] {match.rule.description or 'Pattern matched'}"
            if match.rule.action == "block":
                block_reasons.append(reason)
            elif match.rule.action == "warn":
                warn_reasons.append(reason)
            else:
                redact_matches.append(match)

        # If any rule blocks, return immediately without redacted text.
        if block_reasons:
            return ScanResult(
                matches=matches,
                block_reasons=block_reasons,
                warn_reasons=warn_reasons,
            )

        # Apply redactions in reverse position order to preserve offsets.
        result = text
        for match in sorted(redact_matches, key=lambda m: m.start, reverse=True):
            replacement = self.cache.get_or_create(
                match.rule.id,
                match.text,
                match.rule.category,
                match.rule.replacement,
            )
            result = result[:match.start] + replacement + result[match.end:]

        return ScanResult(
            matches=matches,
            warn_reasons=warn_reasons,
            redacted_text=result,
        )
