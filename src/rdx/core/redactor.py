"""Applies redactions to text using the scanner and mapping cache."""

from __future__ import annotations

from .mappings import MappingCache
from .models import Match, ScanResult
from .scanner import Scanner
from .models import Rule

from rdx.detect.context import scan_context
from rdx.detect.entropy import scan_entropy
from rdx.detect.presidio import scan_presidio


class Redactor:
    """Applies redactions to text, building the mapping cache."""

    def __init__(
        self,
        rules: list[Rule],
        cache: MappingCache,
        *,
        use_entropy: bool = True,
        use_context: bool = True,
        use_presidio: bool = False,
    ) -> None:
        self.scanner = Scanner(rules)
        self.cache = cache
        self.rules = rules
        self.use_entropy = use_entropy
        self.use_context = use_context
        self.use_presidio = use_presidio

    def redact(
        self,
        text: str,
        target: str = "both",
        tool_name: str | None = None,
    ) -> ScanResult:
        """Scan *text* and apply redactions / blocks / warns."""
        matches = self.scanner.scan(text, target, tool_name)

        if self.use_context:
            matches.extend(scan_context(text))
        if self.use_entropy:
            matches.extend(scan_entropy(text))
        if self.use_presidio:
            matches.extend(scan_presidio(text))

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

        # Deduplicate overlapping matches: keep the longest span when two
        # matches overlap.  Sort by (start, -length) so the longest match
        # at each position comes first, then sweep left-to-right and skip
        # any match whose span is fully contained in an already-accepted one.
        redact_matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        deduped: list[Match] = []
        last_end = -1
        for match in redact_matches:
            if match.start >= last_end:
                deduped.append(match)
                last_end = match.end
            # else: this match overlaps with a longer one — skip it

        # Apply redactions in reverse position order to preserve offsets.
        result = text
        for match in reversed(deduped):
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
