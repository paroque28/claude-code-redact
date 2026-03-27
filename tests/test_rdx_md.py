"""Tests for RDX.md generation."""

from pathlib import Path

import yaml

from rdx.core.models import Rule
from rdx.setup.rdx_md import (
    _collect_categories,
    _format_preserving_section,
    _format_rules_table,
    generate_rdx_md,
    write_rdx_md,
)


def _write_rules(project_dir: Path, rules: list[dict]) -> None:
    """Write rules to .redaction_rules in the given directory."""
    path = project_dir / ".redaction_rules"
    yaml_data = {"rules": rules}
    path.write_text(yaml.dump(yaml_data, default_flow_style=False))


class TestCollectCategories:
    def test_groups_by_category(self):
        rules = [
            Rule(id="r1", pattern="a", category="KEY"),
            Rule(id="r2", pattern="b", category="NAME"),
            Rule(id="r3", pattern="c", category="KEY"),
        ]
        result = _collect_categories(rules)
        assert set(result.keys()) == {"KEY", "NAME"}
        assert len(result["KEY"]) == 2
        assert len(result["NAME"]) == 1

    def test_empty_rules(self):
        assert _collect_categories([]) == {}


class TestFormatRulesTable:
    def test_basic_table(self):
        rules = [
            Rule(id="test-key", pattern="sk-.*", category="KEY", description="Test API key"),
        ]
        table = _format_rules_table(rules)
        assert "| Rule ID |" in table
        assert "`test-key`" in table
        assert "KEY" in table
        assert "Test API key" in table

    def test_format_preserving_shows_replacement(self):
        rules = [
            Rule(
                id="name-rule",
                pattern="John",
                category="NAME",
                description="Real name",
                replacement="peter",
            ),
        ]
        table = _format_rules_table(rules)
        assert "`peter`" in table

    def test_auto_token_shows_example(self):
        rules = [
            Rule(id="key-rule", pattern="sk-.*", category="KEY", description="API key"),
        ]
        table = _format_rules_table(rules)
        assert "__RDX_KEY_" in table

    def test_deduplicates_by_id(self):
        rules = [
            Rule(id="same-id", pattern="a", category="KEY", description="First"),
            Rule(id="same-id", pattern="b", category="KEY", description="Second"),
        ]
        table = _format_rules_table(rules)
        assert table.count("`same-id`") == 1


class TestFormatPreservingSection:
    def test_returns_empty_for_no_fp_rules(self):
        rules = [Rule(id="r1", pattern="a", category="KEY")]
        assert _format_preserving_section(rules) == ""

    def test_lists_fp_rules(self):
        rules = [
            Rule(id="r1", pattern="John", category="NAME", replacement="peter", description="Name"),
        ]
        section = _format_preserving_section(rules)
        assert "Format-preserving" in section
        assert "`peter`" in section
        assert "Name" in section


class TestGenerateRdxMd:
    def test_proxy_mode_header(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "# RDX Redaction Active" in md
        assert "proxy" in md.lower()

    def test_hooks_mode_header(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="hooks")
        assert "# RDX Redaction Active" in md
        assert "hooks" in md.lower()

    def test_includes_builtin_rules(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=True, mode="proxy")
        assert "aws-access-key" in md
        assert "github-token" in md

    def test_excludes_builtins_when_disabled(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "aws-access-key" not in md

    def test_includes_user_rules(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "my-rule", "pattern": "secret123", "category": "KEY", "description": "My secret"},
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "`my-rule`" in md
        assert "My secret" in md

    def test_user_rules_override_builtins(self, tmp_path):
        _write_rules(tmp_path, [
            {
                "id": "aws-access-key",
                "pattern": "CUSTOM_PATTERN",
                "category": "KEY",
                "description": "Custom AWS rule",
            },
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=True, mode="proxy")
        # Should only appear once (user rule overrides builtin)
        assert md.count("`aws-access-key`") == 1
        assert "Custom AWS rule" in md

    def test_shows_active_categories(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "r1", "pattern": "a", "category": "NAME"},
            {"id": "r2", "pattern": "b", "category": "EMAIL"},
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "EMAIL" in md
        assert "NAME" in md

    def test_shows_token_format(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=True, mode="proxy")
        assert "__RDX_" in md

    def test_blocked_rules_section(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "block-this", "pattern": "DANGER", "action": "block", "description": "Dangerous"},
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "Blocked patterns" in md
        assert "Dangerous" in md

    def test_no_blocked_section_when_none(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "r1", "pattern": "a", "category": "KEY"},
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "Blocked patterns" not in md

    def test_format_preserving_in_output(self, tmp_path):
        _write_rules(tmp_path, [
            {"id": "name", "pattern": "Alice", "category": "NAME", "replacement": "bob"},
        ])
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "Format-preserving" in md
        assert "`bob`" in md

    def test_instructions_for_claude(self, tmp_path):
        md = generate_rdx_md(project_dir=tmp_path, include_builtins=False, mode="proxy")
        assert "Do not" in md
        assert "opaque" in md.lower() or "token" in md.lower()


class TestWriteRdxMd:
    def test_writes_file(self, tmp_path):
        path = write_rdx_md(tmp_path, mode="proxy", include_builtins=False)
        assert path == tmp_path / "RDX.md"
        assert path.exists()
        content = path.read_text()
        assert "# RDX Redaction Active" in content

    def test_custom_content(self, tmp_path):
        path = write_rdx_md(tmp_path, content="Custom content")
        assert path.read_text() == "Custom content"

    def test_overwrites_existing(self, tmp_path):
        (tmp_path / "RDX.md").write_text("old content")
        write_rdx_md(tmp_path, content="new content")
        assert (tmp_path / "RDX.md").read_text() == "new content"
