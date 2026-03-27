"""Context-based secret detection.

Identifies secrets by their surrounding context (variable names, HTTP headers,
connection strings) rather than by the shape of the secret value itself.
"""

import re

from rdx.core.models import Match, Rule

CONTEXT_RULE = Rule(
    id="context-detected",
    pattern=None,
    action="redact",
    category="KEY",
    description="Secret detected by surrounding context",
)

# Each tuple is (regex, description).
# ``group(1)`` in every regex MUST capture the secret value.
CONTEXT_PATTERNS: list[tuple[str, str]] = [
    # Key-value assignments (quoted)
    (
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
        "password assignment",
    ),
    (
        r'(?:secret|token|api_key|apikey|auth_token)\s*[:=]\s*["\']([^"\']+)["\']',
        "secret assignment",
    ),
    (
        r'(?:access_key|secret_key|private_key)\s*[:=]\s*["\']([^"\']+)["\']',
        "key assignment",
    ),
    # Environment variable exports
    (
        r'export\s+\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\s*=\s*["\']?(\S+)',
        "env export",
    ),
    # Connection strings — capture the password portion
    (
        r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://\w+:([^@]+)@",
        "connection string password",
    ),
    # HTTP headers
    (r"Authorization:\s*Bearer\s+(\S+)", "bearer token"),
    (r"X-API-Key:\s*(\S+)", "API key header"),
]

# Minimum length for a captured value to be flagged.
_MIN_VALUE_LENGTH = 4


def scan_context(text: str) -> list[Match]:
    """Find secrets identified by their surrounding context.

    Returns a :class:`Match` for every captured value whose length is at least
    ``_MIN_VALUE_LENGTH`` characters.  Each match carries a dedicated
    :class:`Rule` whose ``id`` encodes the detection context (e.g.
    ``"context-password-assignment"``).
    """
    matches: list[Match] = []

    for pattern, description in CONTEXT_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            value = m.group(1)
            if len(value) < _MIN_VALUE_LENGTH:
                continue
            matches.append(
                Match(
                    rule=Rule(
                        id=f"context-{description.replace(' ', '-')}",
                        pattern=pattern,
                        action="redact",
                        category="KEY",
                        description=f"Secret in {description}",
                    ),
                    start=m.start(1),
                    end=m.end(1),
                    text=value,
                    score=0.8,
                )
            )

    return matches
