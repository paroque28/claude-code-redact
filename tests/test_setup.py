"""Tests for rdx setup commands."""

import json
from pathlib import Path

import yaml

from rdx.setup.setup import (
    CLAUDE_MD_FILE,
    RDX_MD_FILE,
    _CLAUDE_MD_MARKER,
    _build_hooks_settings,
    _ensure_claude_md_includes_rdx,
    setup_hooks,
    setup_proxy,
    show_config,
)


def _write_rules(project_dir: Path, rules: list[dict]) -> None:
    path = project_dir / ".redaction_rules"
    yaml_data = {"rules": rules}
    path.write_text(yaml.dump(yaml_data, default_flow_style=False))


class TestEnsureClaudeMdIncludesRdx:
    def test_creates_claude_md_if_missing(self, tmp_path):
        modified = _ensure_claude_md_includes_rdx(tmp_path)
        assert modified is True
        content = (tmp_path / CLAUDE_MD_FILE).read_text()
        assert _CLAUDE_MD_MARKER in content
        assert "RDX.md" in content

    def test_appends_to_existing_claude_md(self, tmp_path):
        (tmp_path / CLAUDE_MD_FILE).write_text("# My Project\n\nExisting content.\n")
        modified = _ensure_claude_md_includes_rdx(tmp_path)
        assert modified is True
        content = (tmp_path / CLAUDE_MD_FILE).read_text()
        assert "Existing content." in content
        assert _CLAUDE_MD_MARKER in content

    def test_idempotent_no_duplicate(self, tmp_path):
        _ensure_claude_md_includes_rdx(tmp_path)
        modified = _ensure_claude_md_includes_rdx(tmp_path)
        assert modified is False
        content = (tmp_path / CLAUDE_MD_FILE).read_text()
        assert content.count(_CLAUDE_MD_MARKER) == 1

    def test_handles_file_without_trailing_newline(self, tmp_path):
        (tmp_path / CLAUDE_MD_FILE).write_text("No trailing newline")
        _ensure_claude_md_includes_rdx(tmp_path)
        content = (tmp_path / CLAUDE_MD_FILE).read_text()
        assert "No trailing newline\n" in content
        assert _CLAUDE_MD_MARKER in content


class TestBuildHooksSettings:
    def test_has_hooks_key(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        assert "hooks" in settings

    def test_has_pre_tool_use(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        assert "PreToolUse" in settings["hooks"]

    def test_has_post_tool_use(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        assert "PostToolUse" in settings["hooks"]

    def test_has_user_prompt_submit(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        assert "UserPromptSubmit" in settings["hooks"]

    def test_hook_command_is_rdx(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        pre = settings["hooks"]["PreToolUse"][0]["hooks"][0]
        assert pre["command"] == "rdx hook"
        assert pre["type"] == "command"

    def test_pre_tool_use_matcher(self, tmp_path):
        settings = _build_hooks_settings(tmp_path)
        matcher = settings["hooks"]["PreToolUse"][0]["matcher"]
        for tool in ("Read", "Write", "Edit", "Bash", "Grep"):
            assert tool in matcher


class TestSetupProxy:
    def test_creates_rdx_md(self, tmp_path):
        result = setup_proxy(tmp_path)
        assert (tmp_path / RDX_MD_FILE).exists()
        assert result["mode"] == "proxy"
        assert result["port"] == 8642

    def test_modifies_claude_md(self, tmp_path):
        result = setup_proxy(tmp_path)
        assert result["claude_md_modified"] is True
        assert (tmp_path / CLAUDE_MD_FILE).exists()
        assert _CLAUDE_MD_MARKER in (tmp_path / CLAUDE_MD_FILE).read_text()

    def test_rdx_md_contains_proxy_info(self, tmp_path):
        setup_proxy(tmp_path)
        content = (tmp_path / RDX_MD_FILE).read_text()
        assert "proxy" in content.lower()

    def test_custom_port(self, tmp_path):
        result = setup_proxy(tmp_path, port=9000)
        assert result["port"] == 9000

    def test_idempotent_claude_md(self, tmp_path):
        setup_proxy(tmp_path)
        result = setup_proxy(tmp_path)
        assert result["claude_md_modified"] is False


class TestSetupHooks:
    def test_creates_settings_file(self, tmp_path):
        result = setup_hooks(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        assert result["mode"] == "hooks"
        assert result["settings_path"] == str(settings_path)

    def test_creates_rdx_md(self, tmp_path):
        setup_hooks(tmp_path)
        assert (tmp_path / RDX_MD_FILE).exists()
        content = (tmp_path / RDX_MD_FILE).read_text()
        assert "hooks" in content.lower()

    def test_modifies_claude_md(self, tmp_path):
        result = setup_hooks(tmp_path)
        assert result["claude_md_modified"] is True
        assert _CLAUDE_MD_MARKER in (tmp_path / CLAUDE_MD_FILE).read_text()

    def test_settings_contains_hooks(self, tmp_path):
        setup_hooks(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]

    def test_merges_with_existing_settings(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps({"existing_key": "value"}) + "\n")

        setup_hooks(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert settings["existing_key"] == "value"
        assert "hooks" in settings

    def test_global_scope_writes_to_home(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))

        project = tmp_path / "project"
        project.mkdir()
        result = setup_hooks(project, global_scope=True)

        global_settings = fake_home / ".claude" / "settings.json"
        assert global_settings.exists()
        assert result["global_scope"] is True
        assert str(global_settings) == result["settings_path"]


class TestShowConfig:
    def test_basic_config_no_setup(self, tmp_path):
        config = show_config(tmp_path)
        assert config["project_dir"] == str(tmp_path)
        assert config["rules_file_exists"] is False
        assert config["rdx_md_exists"] is False
        assert config["claude_md_exists"] is False
        assert config["claude_md_has_rdx_import"] is False
        assert config["hooks_configured"] is False

    def test_after_proxy_setup(self, tmp_path):
        setup_proxy(tmp_path)
        config = show_config(tmp_path)
        assert config["rdx_md_exists"] is True
        assert config["claude_md_exists"] is True
        assert config["claude_md_has_rdx_import"] is True

    def test_after_hooks_setup(self, tmp_path):
        setup_hooks(tmp_path)
        config = show_config(tmp_path)
        assert config["hooks_configured"] is True
        assert config["rdx_md_exists"] is True
        assert config["claude_md_has_rdx_import"] is True

    def test_with_user_rules(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "r1", "pattern": "a", "category": "NAME"},
            {"id": "r2", "pattern": "b", "category": "EMAIL"},
        ])
        config = show_config(tmp_path)
        assert config["rules_file_exists"] is True
        assert config["user_rule_count"] == 2
        assert "NAME" in config["active_categories"]
        assert "EMAIL" in config["active_categories"]

    def test_builtin_rule_count(self, tmp_path):
        config = show_config(tmp_path)
        assert config["builtin_rule_count"] > 0

    def test_categories_include_builtins(self, tmp_path):
        config = show_config(tmp_path)
        assert "KEY" in config["active_categories"]

    def test_handles_corrupt_settings(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text("not valid json {{{")
        config = show_config(tmp_path)
        assert config["hooks_configured"] is False
