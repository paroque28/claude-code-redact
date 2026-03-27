"""Tests for the CLI entry point."""

import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from rdx.cli import build_parser, cmd_catchall, main


@pytest.fixture()
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Use tmp_path as the working directory for CLI tests."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# ── Parser structure ──────────────────────────────────────────────


class TestParser:
    def test_parser_builds_without_error(self) -> None:
        parser = build_parser()
        assert parser is not None

    def test_no_args_shows_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        ret = main([])
        assert ret == 0
        out = capsys.readouterr().out
        assert "rdx" in out.lower() or "usage" in out.lower()


# ── hook ──────────────────────────────────────────────────────────


class TestHookCommand:
    def test_hook_dispatches_unknown_event(self, project_dir: Path) -> None:
        data = {"hook_event_name": "UnknownEvent"}
        stdin = io.StringIO(json.dumps(data))
        stdout = io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            ret = main(["hook"])
        assert ret == 0
        stdout.seek(0)
        output = json.load(stdout)
        assert output["continue"] is True


# ── rules ─────────────────────────────────────────────────────────


class TestRulesCommands:
    def test_rules_validate_no_file(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["rules", "validate"])
        assert ret == 0
        assert "no rules file" in capsys.readouterr().out.lower()

    def test_rules_validate_valid(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / ".redaction_rules").write_text(
            "rules:\n  - id: test\n    pattern: 'foo'\n"
        )
        ret = main(["rules", "validate"])
        assert ret == 0
        assert "valid" in capsys.readouterr().out.lower()

    def test_rules_validate_invalid(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / ".redaction_rules").write_text(
            "rules:\n  - id: test\n"
        )
        ret = main(["rules", "validate"])
        assert ret == 1

    def test_rules_list_empty(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["rules", "list"])
        assert ret == 0
        assert "no rules" in capsys.readouterr().out.lower()

    def test_rules_list_shows_rules(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / ".redaction_rules").write_text(
            "rules:\n  - id: my-rule\n    pattern: 'secret'\n    description: test rule\n"
        )
        ret = main(["rules", "list"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "my-rule" in out


# ── check ─────────────────────────────────────────────────────────


class TestCheckCommand:
    def test_check_clean_file(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / "clean.txt").write_text("nothing here")
        ret = main(["check", str(project_dir / "clean.txt")])
        assert ret == 0
        assert "no issues" in capsys.readouterr().out.lower()

    def test_check_file_with_secret(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / "secret.txt").write_text(
            "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        )
        ret = main(["check", str(project_dir / "secret.txt")])
        assert ret == 1
        assert "issue" in capsys.readouterr().out.lower()

    def test_check_nonexistent_file(self, project_dir: Path) -> None:
        ret = main(["check", "/nonexistent/file.txt"])
        # Should not crash, just report not found
        assert ret == 0

    def test_check_stdin(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stdin = io.StringIO("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        with patch.object(sys, "stdin", stdin):
            ret = main(["check", "--stdin"])
        assert ret == 1

    def test_check_quiet_no_output_when_clean(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (project_dir / "clean.txt").write_text("nothing here")
        ret = main(["check", "-q", str(project_dir / "clean.txt")])
        assert ret == 0
        assert capsys.readouterr().out == ""


# ── audit ─────────────────────────────────────────────────────────


class TestAuditCommand:
    def test_audit_empty(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["audit"])
        assert ret == 0
        assert "no audit" in capsys.readouterr().out.lower()

    def test_audit_shows_entries(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rdx.audit.logger import AuditLogger
        logger = AuditLogger(project_dir)
        logger.log("redact", "outgoing", count=3)
        ret = main(["audit"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "redact" in out

    def test_audit_stats(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rdx.audit.logger import AuditLogger
        logger = AuditLogger(project_dir)
        logger.log("redact", "outgoing", count=5)
        logger.log("block", "incoming", count=1)
        ret = main(["audit", "--stats"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "total" in out

    def test_audit_clear(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rdx.audit.logger import AuditLogger
        logger = AuditLogger(project_dir)
        logger.log("redact", "outgoing")
        ret = main(["audit", "--clear"])
        assert ret == 0
        assert "cleared" in capsys.readouterr().out.lower()

    def test_audit_tail(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rdx.audit.logger import AuditLogger
        logger = AuditLogger(project_dir)
        for i in range(10):
            logger.log("redact", "outgoing", count=i)
        ret = main(["audit", "--tail", "3"])
        assert ret == 0
        out = capsys.readouterr().out
        lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(lines) == 3


# ── shadow ────────────────────────────────────────────────────────


class TestShadowCommand:
    def test_shadow_clean_empty(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["shadow", "clean"])
        assert ret == 0
        assert "0" in capsys.readouterr().out

    def test_shadow_clean_removes_files(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        shadow_dir = project_dir / ".claude" / "rdx_shadow"
        shadow_dir.mkdir(parents=True)
        (shadow_dir / "abc.txt").write_text("shadow content")
        ret = main(["shadow", "clean"])
        assert ret == 0
        assert "1" in capsys.readouterr().out


# ── setup ─────────────────────────────────────────────────────────


class TestSetupCommand:
    def test_setup_show(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["setup", "--show"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "rules" in out.lower()

    def test_setup_proxy(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["setup", "--proxy"])
        assert ret == 0
        assert "ANTHROPIC_BASE_URL" in capsys.readouterr().out

    def test_setup_hooks(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["setup", "--hooks"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "PreToolUse" in out

    def test_setup_no_flag(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["setup"])
        assert ret == 1


# ── proxy status ──────────────────────────────────────────────────


class TestProxyStatus:
    def test_not_running(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["proxy", "status"])
        assert ret == 0
        assert "not running" in capsys.readouterr().out.lower()


# ── catch-all ─────────────────────────────────────────────────────


class TestCatchAll:
    def test_runs_command_and_redacts_output(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["echo", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"])
        assert ret == 0
        out = capsys.readouterr().out
        # The GitHub token should be redacted
        assert "ghp_ABCDEFGHIJ" not in out
        assert "__RDX_" in out

    def test_nonexistent_command(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["__nonexistent_command_xyz__"])
        assert ret == 127

    def test_clean_output_passes_through(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["echo", "hello world"])
        assert ret == 0
        assert "hello world" in capsys.readouterr().out


# ── secret ────────────────────────────────────────────────────────


class TestSecretCommands:
    def test_secret_list_empty(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["secret", "list"])
        assert ret == 0
        assert "no hashed" in capsys.readouterr().out.lower()

    def test_secret_add_from_env(
        self,
        project_dir: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("REDACT_SECRET", "my-super-secret-value")
        ret = main(["secret", "add", "--id", "test-secret"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "test-secret" in out

        # Verify the rule was added
        ret = main(["secret", "list"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "test-secret" in out


# ── rewrite ───────────────────────────────────────────────────────


class TestRewriteCommand:
    def test_rewrite_outputs_command(
        self, project_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ret = main(["rewrite", "cat", "/etc/hosts"])
        assert ret == 0
        out = capsys.readouterr().out.strip()
        # Should just print the command since no mappings exist
        assert "cat /etc/hosts" in out
