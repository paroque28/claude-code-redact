"""Command rewriting for Bash tool — un-redacts and wraps with rdx proxy."""

from __future__ import annotations

from rdx.core.unredactor import Unredactor


def rewrite_command(command: str, unredactor: Unredactor) -> str | None:
    """Rewrite a shell command for rdx proxy execution.

    Returns the rewritten command string, or ``None`` if no rewrite is needed
    (e.g. the command is already wrapped with ``rdx``).
    """
    stripped = command.strip()

    # Already wrapped — don't double-wrap
    if stripped.startswith("rdx "):
        return None

    # Un-redact any redaction tokens in the command
    unredacted = unredactor.unredact(stripped)

    # Prepend rdx proxy
    return f"rdx {unredacted}"
