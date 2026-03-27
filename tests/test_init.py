"""Tests for the rdx init wizard."""

from __future__ import annotations

import io
import json
from pathlib import Path

import yaml
import pytest

from rdx.core.rules import PROJECT_RULES_FILE, load_rules_file, validate_rules_file
from rdx.init import run_init


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """Return a clean temporary project directory."""
    return tmp_path


class TestNonInteractive:
    """Tests for non-interactive mode with JSON input."""

    def test_basic_company(self, project_dir: Path) -> None:
        """Non-interactive mode with just a company name produces valid rules."""
        config = {
            "company": "AcmeCorp",
            "replacement_company": "WidgetInc",
            "mode": "hooks",
        }
        stdin = io.StringIO(json.dumps(config))
        import sys
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin

        assert code == 0
        rules_path = project_dir / PROJECT_RULES_FILE
        assert rules_path.exists()

        rules = load_rules_file(rules_path)
        # company + company-lower
        company_rules = [r for r in rules if r.id.startswith("company")]
        assert len(company_rules) == 2
        assert company_rules[0].pattern == "AcmeCorp"
        assert company_rules[0].replacement == "WidgetInc"
        assert company_rules[1].pattern == "acmecorp"
        assert company_rules[1].replacement == "widgetinc"

    def test_full_config(self, project_dir: Path) -> None:
        """Non-interactive mode with all options produces valid YAML."""
        config = {
            "company": "AcmeCorp",
            "replacement_company": "WidgetInc",
            "company_variants": ["ACME_CORP"],
            "replacement_variants": ["WIDGET_INC"],
            "project": "ProjectPhoenix",
            "replacement_project": "ProjectEagle",
            "people": [
                {"name": "Marco Vitale", "replacement": "Peter Smith"},
                {"name": "Sarah Chen", "replacement": "Jane Doe"},
            ],
            "email_domain": "acmecorp.com",
            "replacement_email_domain": "widgetinc.com",
            "host_domain": "acmecorp.internal",
            "replacement_host_domain": "widgetinc.test",
            "token_prefixes": ["acmetk-", "acme-deploy-"],
            "ticket_prefixes": ["ACME-", "PHOENIX-"],
            "mode": "proxy",
        }
        stdin = io.StringIO(json.dumps(config))
        import sys
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin

        assert code == 0
        rules_path = project_dir / PROJECT_RULES_FILE
        assert rules_path.exists()

        # Validate YAML is well-formed
        errors = validate_rules_file(rules_path)
        assert errors == [], f"Validation errors: {errors}"

        rules = load_rules_file(rules_path)
        categories = {r.category for r in rules}
        assert "PROJECT" in categories
        assert "NAME" in categories
        assert "EMAIL" in categories
        assert "HOST" in categories
        assert "KEY" in categories

    def test_generated_yaml_is_valid(self, project_dir: Path) -> None:
        """The generated .redaction_rules file is valid YAML."""
        config = {
            "company": "TestCo",
            "replacement_company": "MockCo",
            "mode": "hooks",
        }
        stdin = io.StringIO(json.dumps(config))
        import sys
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin

        rules_path = project_dir / PROJECT_RULES_FILE
        with rules_path.open() as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert "rules" in data
        assert isinstance(data["rules"], list)

    def test_invalid_json_returns_error(self, project_dir: Path) -> None:
        """Non-interactive mode with invalid JSON returns error."""
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("not json{{{")
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin
        assert code == 1

    def test_empty_config(self, project_dir: Path) -> None:
        """Non-interactive mode with empty config produces no rules file."""
        config = {"mode": "hooks"}
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(config))
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin
        assert code == 0
        # No rules were generated, so the file should not exist
        rules_path = project_dir / PROJECT_RULES_FILE
        assert not rules_path.exists()

    def test_people_as_strings(self, project_dir: Path) -> None:
        """People can be specified as plain strings (auto-generates replacement)."""
        config = {
            "people": ["Alice Wonder", "Bob Builder"],
            "mode": "hooks",
        }
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(config))
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin
        assert code == 0
        rules = load_rules_file(project_dir / PROJECT_RULES_FILE)
        name_rules = [r for r in rules if r.category == "NAME"]
        # 2 full names + 2 first names = 4
        assert len(name_rules) == 4

    def test_company_variants_padding(self, project_dir: Path) -> None:
        """Replacement variants are padded if fewer than variants."""
        config = {
            "company": "AcmeCorp",
            "replacement_company": "WidgetInc",
            "company_variants": ["acme", "ACME"],
            "replacement_variants": ["widget"],
            "mode": "hooks",
        }
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(config))
        try:
            code = run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin
        assert code == 0
        rules = load_rules_file(project_dir / PROJECT_RULES_FILE)
        variant_rules = [r for r in rules if r.id.startswith("company-variant")]
        assert len(variant_rules) == 2
        assert variant_rules[0].replacement == "widget"
        # Second variant should use lowered replacement_company as default
        assert variant_rules[1].replacement == "widgetinc"


class TestModeSelection:
    """Tests that mode selection triggers the right setup."""

    def test_hooks_mode_creates_settings(self, project_dir: Path) -> None:
        """Hooks mode creates .claude/settings.json."""
        config = {"company": "Test", "replacement_company": "Mock", "mode": "hooks"}
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(config))
        try:
            run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin

        settings_path = project_dir / ".claude" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings

    def test_proxy_mode_creates_rdx_md(self, project_dir: Path) -> None:
        """Proxy mode creates RDX.md."""
        config = {"company": "Test", "replacement_company": "Mock", "mode": "proxy"}
        import sys
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(config))
        try:
            run_init(project_dir=project_dir, non_interactive=True)
        finally:
            sys.stdin = old_stdin

        rdx_md = project_dir / "RDX.md"
        assert rdx_md.exists()


class TestInteractive:
    """Tests for interactive mode using monkeypatched input()."""

    def test_skip_all_questions(self, project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pressing Enter for every question skips everything gracefully."""
        inputs = iter([""] * 20)  # Enough empty inputs to skip everything
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
        code = run_init(project_dir=project_dir)
        assert code == 0

    def test_company_only(self, project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Interactive mode with just company name."""
        responses = [
            "AcmeCorp",      # company name
            "WidgetInc",     # replacement
            "",              # variants
            "",              # project
            "",              # people
            "",              # email domain
            "",              # host domain
            "",              # token prefixes
            "",              # ticket prefixes
            "hooks",         # mode
        ]
        inputs = iter(responses)
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
        code = run_init(project_dir=project_dir)
        assert code == 0

        rules = load_rules_file(project_dir / PROJECT_RULES_FILE)
        assert len(rules) >= 2  # company + company-lower
        assert rules[0].pattern == "AcmeCorp"

    def test_with_people(self, project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Interactive mode with people generates NAME rules."""
        responses = [
            "",                          # company (skip)
            "",                          # project (skip)
            "Marco Vitale, Sarah Chen",  # people
            "Peter Smith",               # replacement for Marco
            "Jane Doe",                  # replacement for Sarah
            "",                          # email domain
            "",                          # host domain
            "",                          # token prefixes
            "",                          # ticket prefixes
            "hooks",                     # mode
        ]
        inputs = iter(responses)
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
        code = run_init(project_dir=project_dir)
        assert code == 0

        rules = load_rules_file(project_dir / PROJECT_RULES_FILE)
        name_rules = [r for r in rules if r.category == "NAME"]
        # 2 full names + 2 first names = 4
        assert len(name_rules) == 4

    def test_existing_rules_overwrite_decline(
        self, project_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Declining overwrite of existing rules aborts."""
        rules_path = project_dir / PROJECT_RULES_FILE
        rules_path.write_text("rules: []\n")

        responses = ["n"]  # decline overwrite
        inputs = iter(responses)
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
        code = run_init(project_dir=project_dir)
        assert code == 0
        # Original file should be unchanged
        assert rules_path.read_text() == "rules: []\n"

    def test_existing_rules_overwrite_accept(
        self, project_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Accepting overwrite of existing rules proceeds."""
        rules_path = project_dir / PROJECT_RULES_FILE
        rules_path.write_text("rules: []\n")

        responses = [
            "y",            # accept overwrite
            "NewCorp",      # company
            "FakeCorp",     # replacement
            "",             # variants
            "",             # project
            "",             # people
            "",             # email domain
            "",             # host domain
            "",             # token prefixes
            "",             # ticket prefixes
            "hooks",        # mode
        ]
        inputs = iter(responses)
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
        code = run_init(project_dir=project_dir)
        assert code == 0
        rules = load_rules_file(rules_path)
        assert len(rules) >= 1
        assert rules[0].pattern == "NewCorp"


class TestRuleGeneration:
    """Tests for individual rule-building functions."""

    def test_token_rule_regex(self, project_dir: Path) -> None:
        """Token rules produce valid regex patterns."""
        import re
        from rdx.init import _build_token_rules
        rules = _build_token_rules(["acmetk-"])
        assert len(rules) == 1
        pattern = rules[0].pattern
        assert pattern is not None
        # Should compile without error
        compiled = re.compile(pattern)
        assert compiled.match("acmetk-abc123def456ghi789jkl012")

    def test_ticket_rule_regex(self, project_dir: Path) -> None:
        """Ticket rules produce valid regex patterns."""
        import re
        from rdx.init import _build_ticket_rules
        rules = _build_ticket_rules(["PHOENIX-"])
        assert len(rules) == 1
        pattern = rules[0].pattern
        assert pattern is not None
        compiled = re.compile(pattern)
        assert compiled.match("PHOENIX-1234")

    def test_ticket_rule_no_replacement(self, project_dir: Path) -> None:
        """Ticket rules have no format-preserving replacement (auto-token)."""
        from rdx.init import _build_ticket_rules
        rules = _build_ticket_rules(["JIRA-"])
        assert rules[0].replacement is None

    def test_email_domain_escaping(self, project_dir: Path) -> None:
        """Email domain dots are escaped in regex."""
        from rdx.init import _build_email_domain_rules
        rules = _build_email_domain_rules("acmecorp.com", "widgetinc.com")
        assert rules[0].pattern == r"acmecorp\.com"

    def test_host_domain_escaping(self, project_dir: Path) -> None:
        """Host domain dots are escaped in regex."""
        from rdx.init import _build_host_domain_rules
        rules = _build_host_domain_rules("acme.internal", "widget.test")
        assert rules[0].pattern == r"acme\.internal"

    def test_people_rule_first_name(self, project_dir: Path) -> None:
        """People rules include first-name-only rules."""
        from rdx.init import _build_people_rules
        rules = _build_people_rules(["Marco Vitale"], ["Peter Smith"])
        ids = [r.id for r in rules]
        assert "person-marco-vitale" in ids
        assert "person-marco-vitale-first" in ids
        first_rule = [r for r in rules if r.id == "person-marco-vitale-first"][0]
        assert first_rule.replacement == "Peter"

    def test_company_no_lowercase_duplicate(self, project_dir: Path) -> None:
        """If company is already lowercase, don't add a duplicate lowercase rule."""
        from rdx.init import _build_company_rules
        rules = _build_company_rules("acmecorp", "widgetinc", [], [])
        ids = [r.id for r in rules]
        assert "company-lower" not in ids


class TestCLIIntegration:
    """Test the CLI init subcommand wiring."""

    def test_init_subcommand_exists(self) -> None:
        """The init subcommand is registered in the parser."""
        from rdx.cli import build_parser
        parser = build_parser()
        # Should parse without error
        args = parser.parse_args(["init", "--non-interactive"])
        assert args.non_interactive is True
        assert hasattr(args, "func")
