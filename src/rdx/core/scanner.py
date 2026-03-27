"""Pattern matching engine — scans text against rules and returns matches."""

from __future__ import annotations

import hashlib
import re

from .models import Match, Rule


def hash_text(text: str) -> str:
    """Return the SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode()).hexdigest()


class Scanner:
    """Scans text against redaction rules."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = [r for r in rules if r.pattern]
        self._compiled: dict[str, re.Pattern[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        text: str,
        target: str = "both",
        tool_name: str | None = None,
    ) -> list[Match]:
        """Scan *text* and return all matches for applicable rules."""
        matches: list[Match] = []
        for rule in self.rules:
            # Target filtering: a rule with target "both" always applies;
            # otherwise it must match the requested target.
            if rule.target != "both" and rule.target != target:
                continue
            # Tool filtering: if the rule is scoped to a specific tool,
            # skip it unless the caller is that tool.
            if rule.tool is not None and rule.tool != tool_name:
                continue

            if rule.hashed:
                matches.extend(self._match_hashed(rule, text))
            else:
                matches.extend(self._match_plain(rule, text))
        return matches

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_pattern(self, rule: Rule) -> re.Pattern[str]:
        """Return a compiled regex for *rule*, caching the result."""
        if rule.id not in self._compiled:
            assert rule.pattern is not None
            raw = rule.pattern if rule.is_regex else re.escape(rule.pattern)
            self._compiled[rule.id] = re.compile(raw)
        return self._compiled[rule.id]

    def _match_plain(self, rule: Rule, text: str) -> list[Match]:
        """Find all non-hashed matches of *rule* in *text*."""
        pattern = self._get_pattern(rule)
        results: list[Match] = []
        for m in pattern.finditer(text):
            results.append(
                Match(
                    rule=rule,
                    start=m.start(),
                    end=m.end(),
                    text=m.group(),
                    entity_type=rule.category,
                )
            )
        return results

    def _match_hashed(self, rule: Rule, text: str) -> list[Match]:
        """Match when the rule's pattern is compared against hashed segments.

        If *hash_extractor* is set it is used as a regex to pull candidate
        segments out of *text*; the SHA-256 of each candidate is then compared
        to *rule.pattern*.  Without a hash_extractor the entire text is hashed
        and compared.
        """
        assert rule.pattern is not None
        expected_hash = rule.pattern
        results: list[Match] = []

        if rule.hash_extractor:
            extractor = re.compile(rule.hash_extractor)
            for m in extractor.finditer(text):
                candidate = m.group()
                if hash_text(candidate) == expected_hash:
                    results.append(
                        Match(
                            rule=rule,
                            start=m.start(),
                            end=m.end(),
                            text=candidate,
                            entity_type=rule.category,
                            segment_hash=expected_hash,
                        )
                    )
        else:
            if hash_text(text) == expected_hash:
                results.append(
                    Match(
                        rule=rule,
                        start=0,
                        end=len(text),
                        text=text,
                        entity_type=rule.category,
                        segment_hash=expected_hash,
                    )
                )

        return results
