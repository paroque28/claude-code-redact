"""Tests for the main hook dispatcher and per-tool handlers."""

import io
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rdx.core.mappings import MappingCache
from rdx.hooks import hook as hook_module
from rdx.hooks.hook import (
    handle_post_tool_use,
    handle_pre_tool_use,
    handle_user_prompt_submit,
    run_hook,
)


def capture_output(func: Any, *args: Any, **kwargs: Any) -> tuple[int, dict[str, Any]]:
    """Call *func*, capture stdout, and parse the JSON response."""
    stdout = io.StringIO()
    with patch.object(sys, "stdout", stdout):
        code = func(*args, **kwargs)
    stdout.seek(0)
    output = json.load(stdout)
    return code, output


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    """Reset the module-level mapping cache between tests."""
    hook_module._cache = MappingCache()
    yield
    hook_module._cache = MappingCache()


# ── PreToolUse: Read ──────────────────────────────────────────────


class TestPreToolUseRead:
    def test_redirects_to_shadow_when_secret_found(self, tmp_path: Path) -> None:
        """Read of a file with a secret returns updatedInput with shadow path."""
        secret_file = tmp_path / "config.txt"
        secret_file.write_text("api_key = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(secret_file)},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)

        assert code == 0
        updated = output["hookSpecificOutput"]["updatedInput"]
        shadow_path = updated["file_path"]
        assert shadow_path != str(secret_file)
        assert ".claude/rdx_shadow" in shadow_path
        # Shadow file content should not contain the original secret
        assert "ghp_ABCDEFGHIJ" not in Path(shadow_path).read_text()

    def test_allows_clean_file(self, tmp_path: Path) -> None:
        """Read of a clean file passes through unchanged."""
        clean_file = tmp_path / "readme.txt"
        clean_file.write_text("Just a normal readme.")

        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(clean_file)},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── PreToolUse: Write ─────────────────────────────────────────────


class TestPreToolUseWrite:
    def test_unredacts_content(self, tmp_path: Path) -> None:
        """Write content with redaction tokens gets un-redacted."""
        # Seed the cache with a mapping
        hook_module._cache.get_or_create("name-rule", "real-secret", "NAME", "fake-alias")

        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"content": "value = fake-alias", "file_path": "out.txt"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert updated["content"] == "value = real-secret"

    def test_allows_clean_content(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"content": "nothing redacted", "file_path": "out.txt"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── PreToolUse: Edit ──────────────────────────────────────────────


class TestPreToolUseEdit:
    def test_unredacts_old_and_new_strings(self, tmp_path: Path) -> None:
        hook_module._cache.get_or_create("key-rule", "SECRET123", "KEY", "REDACTED")

        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "config.py",
                "old_string": "key = REDACTED",
                "new_string": "key = REDACTED",
            },
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert updated["old_string"] == "key = SECRET123"
        assert updated["new_string"] == "key = SECRET123"


# ── PreToolUse: Bash ──────────────────────────────────────────────


class TestPreToolUseBash:
    def test_rewrites_command_with_rdx_prefix(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat /etc/hosts"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert updated["command"] == "rdx cat /etc/hosts"

    def test_already_wrapped_passes_through(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rdx cat /etc/hosts"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── PreToolUse: Grep ──────────────────────────────────────────────


class TestPreToolUseGrep:
    def test_blocks_with_redirect_message(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_input": {"pattern": "password", "path": "/src"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 2
        hook_out = output["hookSpecificOutput"]
        assert hook_out["permissionDecision"] == "deny"
        assert "rdx rg" in hook_out["permissionDecisionReason"]
        assert "password" in hook_out["permissionDecisionReason"]


# ── PreToolUse: Unknown tool ──────────────────────────────────────


class TestPreToolUseUnknown:
    def test_allows_unknown_tool(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeFutureTool",
            "tool_input": {"foo": "bar"},
        }
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── PostToolUse ───────────────────────────────────────────────────


class TestPostToolUse:
    def test_warns_about_secrets_in_output(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {"stdout": "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
        }
        stderr = io.StringIO()
        with patch.object(sys, "stderr", stderr):
            code, output = capture_output(handle_post_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True
        assert "secrets detected" in stderr.getvalue()

    def test_allows_clean_output(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {"content": "just normal text"},
        }
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True

    def test_allows_empty_response(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": None,
        }
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── UserPromptSubmit ──────────────────────────────────────────────


class TestUserPromptSubmit:
    def test_blocks_prompt_containing_unredacted_value(self, tmp_path: Path) -> None:
        """If the mapping cache knows 'real-secret', block prompts that contain it."""
        hook_module._cache.get_or_create("key-rule", "real-secret", "KEY", "fake-token")

        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Please use real-secret in the config",
        }
        code, output = capture_output(handle_user_prompt_submit, data, tmp_path)
        assert code == 2
        assert output["decision"] == "block"
        assert "sensitive value" in output["reason"].lower()

    def test_allows_clean_prompt(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Help me refactor the database module",
        }
        code, output = capture_output(handle_user_prompt_submit, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True

    def test_allows_empty_prompt(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "",
        }
        code, output = capture_output(handle_user_prompt_submit, data, tmp_path)
        assert code == 0
        assert output.get("continue") is True


# ── run_hook dispatcher ───────────────────────────────────────────


class TestRunHook:
    def test_dispatches_pre_tool_use(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
        stdin = io.StringIO(json.dumps(data))
        stdout = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            code = run_hook(tmp_path)
        assert code == 0

    def test_dispatches_post_tool_use(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": {"content": "clean"},
        }
        stdin = io.StringIO(json.dumps(data))
        stdout = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            code = run_hook(tmp_path)
        assert code == 0

    def test_dispatches_user_prompt_submit(self, tmp_path: Path) -> None:
        data = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello",
        }
        stdin = io.StringIO(json.dumps(data))
        stdout = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            code = run_hook(tmp_path)
        assert code == 0

    def test_unknown_event_allows_through(self, tmp_path: Path) -> None:
        data = {"hook_event_name": "FutureEvent"}
        stdin = io.StringIO(json.dumps(data))
        stdout = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            code = run_hook(tmp_path)
        assert code == 0
        stdout.seek(0)
        output = json.load(stdout)
        assert output["continue"] is True

    def test_invalid_json_returns_error(self, tmp_path: Path) -> None:
        stdin = io.StringIO("not valid json{{{")
        stderr = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stderr", stderr):
            code = run_hook(tmp_path)
        assert code == 1
        assert "invalid JSON" in stderr.getvalue()
