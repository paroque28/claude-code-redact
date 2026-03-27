"""Main hook entry point for Claude Code hooks integration.

Reads JSON from stdin, dispatches to per-tool / per-event handlers,
and writes a JSON response to stdout.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from rdx.core.mappings import MappingCache
from rdx.core.redactor import Redactor
from rdx.core.rules import load_rules
from rdx.core.unredactor import Unredactor
from rdx.detect.patterns import get_builtin_rules

from .rewrite import rewrite_command
from .shadow import create_shadow

# Module-level cache shared across invocations within the same process.
_cache = MappingCache()


def _build_rules(project_dir: Path | None) -> list:
    """Load project + builtin rules."""
    rules = load_rules(project_dir)
    rules.extend(get_builtin_rules())
    return rules


def _make_redactor(project_dir: Path | None) -> Redactor:
    return Redactor(_build_rules(project_dir), _cache)


def _make_unredactor() -> Unredactor:
    return Unredactor(_cache)


# ── Response builders ──────────────────────────────────────────────


def _allow() -> dict[str, Any]:
    return {"continue": True}


def _allow_updated(event: str, reason: str, updated_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
            "updatedInput": updated_input,
        },
    }


def _deny(event: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _block_prompt(reason: str) -> dict[str, Any]:
    return {
        "decision": "block",
        "reason": reason,
    }


# ── PreToolUse handlers ───────────────────────────────────────────


def _handle_read(tool_input: dict[str, Any], project_dir: Path | None) -> dict[str, Any]:
    """Read tool: redirect to a redacted shadow file if secrets are found."""
    file_path = tool_input.get("file_path", "")
    if not file_path:
        return _allow()

    redactor = _make_redactor(project_dir)
    p_dir = project_dir or Path.cwd()
    shadow = create_shadow(file_path, p_dir, redactor)
    if shadow is None:
        return _allow()

    updated = dict(tool_input)
    updated["file_path"] = str(shadow)
    return _allow_updated("PreToolUse", "Redirected to redacted shadow file", updated)


def _handle_write(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Write tool: un-redact content before writing to disk."""
    unredactor = _make_unredactor()
    content = tool_input.get("content", "")
    unredacted = unredactor.unredact(content)
    if unredacted == content:
        return _allow()

    updated = dict(tool_input)
    updated["content"] = unredacted
    return _allow_updated("PreToolUse", "Content un-redacted before write", updated)


def _handle_edit(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Edit tool: un-redact old_string and new_string."""
    unredactor = _make_unredactor()
    old_string = tool_input.get("old_string", "")
    new_string = tool_input.get("new_string", "")

    old_unredacted = unredactor.unredact(old_string)
    new_unredacted = unredactor.unredact(new_string)

    if old_unredacted == old_string and new_unredacted == new_string:
        return _allow()

    updated = dict(tool_input)
    updated["old_string"] = old_unredacted
    updated["new_string"] = new_unredacted
    return _allow_updated("PreToolUse", "Edit strings un-redacted", updated)


def _handle_bash(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Bash tool: un-redact command and prepend rdx proxy."""
    command = tool_input.get("command", "")
    if not command:
        return _allow()

    unredactor = _make_unredactor()
    rewritten = rewrite_command(command, unredactor)
    if rewritten is None:
        return _allow()

    updated = dict(tool_input)
    updated["command"] = rewritten
    return _allow_updated("PreToolUse", "rdx command rewrite", updated)


def _handle_grep(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Grep tool: block and redirect to rdx rg for redacted search."""
    pattern = tool_input.get("pattern", "<pattern>")
    path = tool_input.get("path", ".")

    # Un-redact the pattern so the user can see what to search for
    unredactor = _make_unredactor()
    real_pattern = unredactor.unredact(pattern)

    reason = f"Use Bash: rdx rg {real_pattern} {path} for redacted search results"
    return _deny("PreToolUse", reason)


# ── Event handlers ─────────────────────────────────────────────────


def handle_pre_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Dispatch PreToolUse to the appropriate per-tool handler."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    handlers: dict[str, Any] = {
        "Read": lambda: _handle_read(tool_input, project_dir),
        "Write": lambda: _handle_write(tool_input),
        "Edit": lambda: _handle_edit(tool_input),
        "Bash": lambda: _handle_bash(tool_input),
        "Grep": lambda: _handle_grep(tool_input),
    }

    handler = handlers.get(tool_name)
    if handler is None:
        json.dump(_allow(), sys.stdout)
        return 0

    response = handler()
    json.dump(response, sys.stdout)

    # Return 2 for deny (blocked), 0 otherwise
    decision = response.get("hookSpecificOutput", {}).get("permissionDecision")
    return 2 if decision == "deny" else 0


def handle_post_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Scan tool output for secrets. Warn-only (PostToolUse cannot modify output)."""
    tool_response = data.get("tool_response")
    if not tool_response:
        json.dump(_allow(), sys.stdout)
        return 0

    # Extract content from tool response
    content: str | None = None
    if isinstance(tool_response, dict):
        for field in ("content", "output", "stdout", "result", "text"):
            if field in tool_response:
                content = str(tool_response[field])
                break
    elif tool_response:
        content = str(tool_response)

    if not content:
        json.dump(_allow(), sys.stdout)
        return 0

    redactor = _make_redactor(project_dir)
    result = redactor.redact(content, target="tool")

    if result.matches:
        rule_ids = ", ".join(m.rule.id for m in result.matches)
        sys.stderr.write(f"rdx: secrets detected in tool output [{rule_ids}]\n")

    json.dump(_allow(), sys.stdout)
    return 0


def handle_user_prompt_submit(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Scan user prompt for un-redacted original values from the reverse map."""
    prompt = data.get("prompt", "")
    if not prompt:
        json.dump(_allow(), sys.stdout)
        return 0

    # Check if the prompt contains any original (un-redacted) values
    reverse_map = _cache.get_reverse_map()
    if reverse_map:
        originals = set(reverse_map.values())
        for original in originals:
            if original in prompt:
                json.dump(
                    _block_prompt(
                        "Prompt contains sensitive value. Use the redacted alias instead."
                    ),
                    sys.stdout,
                )
                return 2

    # Also scan with the redactor for new secrets
    redactor = _make_redactor(project_dir)
    result = redactor.redact(prompt, target="llm")
    if result.block_reasons:
        json.dump(
            _block_prompt(f"Prompt blocked: {'; '.join(result.block_reasons)}"),
            sys.stdout,
        )
        return 2

    json.dump(_allow(), sys.stdout)
    return 0


# ── Main entry ─────────────────────────────────────────────────────


def run_hook(project_dir: Path | None = None) -> int:
    """Main entry point. Read JSON from stdin, dispatch by event."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"rdx: invalid JSON input: {e}\n")
        return 1

    event = data.get("hook_event_name", "")

    if event == "PreToolUse":
        return handle_pre_tool_use(data, project_dir)
    if event == "PostToolUse":
        return handle_post_tool_use(data, project_dir)
    if event == "UserPromptSubmit":
        return handle_user_prompt_submit(data, project_dir)

    # Unknown event — allow through
    json.dump(_allow(), sys.stdout)
    return 0
