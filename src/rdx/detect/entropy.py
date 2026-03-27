"""Shannon entropy-based detection for high-entropy strings likely to be secrets."""

import math
import re
from collections import Counter

from rdx.core.models import Match, Rule

# Synthetic rule for entropy-detected secrets (not pattern-based).
ENTROPY_RULE = Rule(
    id="entropy-detected",
    pattern=None,
    action="redact",
    category="KEY",
    description="High-entropy string (likely secret)",
)


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    Returns 0.0 for empty strings.  Maximum value depends on character-set
    diversity (e.g. ~6.57 for uniformly random base-64).
    """
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def scan_entropy(
    text: str,
    threshold: float = 4.5,
    min_length: int = 20,
) -> list[Match]:
    """Find high-entropy strings in *text* that are likely secrets.

    The scanner extracts candidate strings from two contexts:

    * Quoted strings — ``"…"`` or ``'…'``
    * Assignment values — ``= <value>`` followed by whitespace, ``;``, or EOL

    Only alphanumeric-plus-base64 characters are considered so that natural
    language prose does not trigger false positives.

    Parameters
    ----------
    text:
        The source text to scan.
    threshold:
        Minimum Shannon entropy (bits/char) to flag a candidate.
    min_length:
        Minimum character length for a candidate string.

    Returns
    -------
    list[Match]
        Matches whose entropy meets the threshold.
    """
    matches: list[Match] = []
    seen_spans: set[tuple[int, int]] = set()

    patterns = [
        # Quoted strings (single or double)
        r'["\']([A-Za-z0-9+/=_\-]{%d,})["\']' % min_length,
        # Assignment values (unquoted)
        r"=\s*([A-Za-z0-9+/=_\-]{%d,})(?:\s|$|;)" % min_length,
    ]

    for pattern in patterns:
        for m in re.finditer(pattern, text):
            span = (m.start(1), m.end(1))
            if span in seen_spans:
                continue
            seen_spans.add(span)

            candidate = m.group(1)
            entropy = shannon_entropy(candidate)
            if entropy >= threshold:
                matches.append(
                    Match(
                        rule=ENTROPY_RULE,
                        start=m.start(1),
                        end=m.end(1),
                        text=candidate,
                        score=min(entropy / 6.0, 1.0),
                    )
                )

    return matches
