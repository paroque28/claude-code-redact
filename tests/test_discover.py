"""Tests for rdx discover — project scanning and rule suggestion."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rdx.discover import (
    DiscoverReport,
    Finding,
    discover,
    print_report,
    scan_file,
    walk_project_files,
    _truncate,
    _method_from_rule_id,
    _suggest_rule_id,
    interactive_add,
)
from rdx.core.mappings import MappingCache
from rdx.core.redactor import Redactor
from rdx.detect.patterns import get_builtin_rules

PLAYGROUND = Path(__file__).resolve().parent.parent / "playground"


# ---------------------------------------------------------------------------
# walk_project_files
# ---------------------------------------------------------------------------

class TestWalkProjectFiles:
    def test_finds_python_files_in_playground(self) -> None:
        files, skipped = walk_project_files(PLAYGROUND)
        names = {f.name for f in files}
        assert "config.py" in names
        assert "billing.py" in names
        assert "user_service.py" in names

    def test_skips_pycache(self, tmp_path: Path) -> None:
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "mod.cpython-312.pyc").write_text("compiled")
        (tmp_path / "main.py").write_text("print('hello')")
        files, skipped = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "main.py" in names
        assert "mod.cpython-312.pyc" not in names

    def test_skips_binary_extensions(self, tmp_path: Path) -> None:
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        (tmp_path / "readme.md").write_text("hello")
        files, _ = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "readme.md" in names
        assert "image.png" not in names

    def test_skips_large_files(self, tmp_path: Path) -> None:
        (tmp_path / "huge.txt").write_text("x" * 2_000_000)
        (tmp_path / "small.txt").write_text("ok")
        files, skipped = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "small.txt" in names
        assert "huge.txt" not in names
        assert skipped >= 1

    def test_respects_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\nsecrets/\n")
        (tmp_path / "app.py").write_text("code")
        (tmp_path / "debug.log").write_text("log data")
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "key.txt").write_text("secret")
        files, _ = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "app.py" in names
        assert "debug.log" not in names

    def test_skips_dot_git(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("[core]")
        (tmp_path / "main.py").write_text("code")
        files, _ = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "main.py" in names
        assert "config" not in names

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text("module")
        (tmp_path / "app.js").write_text("app")
        files, _ = walk_project_files(tmp_path)
        names = {f.name for f in files}
        assert "app.js" in names
        assert "pkg.js" not in names

    def test_empty_directory(self, tmp_path: Path) -> None:
        files, skipped = walk_project_files(tmp_path)
        assert files == []
        assert skipped == 0


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------

class TestScanFile:
    def test_detects_aws_key(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache, use_context=True, use_entropy=False)
        findings = scan_file(f, tmp_path, redactor)
        assert len(findings) >= 1
        aws_findings = [fd for fd in findings if "AKIA" in fd.value]
        assert len(aws_findings) == 1
        assert aws_findings[0].method == "builtin"

    def test_detects_password_via_context(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret99"')
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        findings = scan_file(f, tmp_path, redactor)
        pw = [fd for fd in findings if "SuperSecret99" in fd.value]
        assert len(pw) >= 1
        assert pw[0].method == "context"

    def test_detects_high_entropy_via_entropy(self, tmp_path: Path) -> None:
        f = tmp_path / "secrets.py"
        f.write_text('TOKEN = "kJ8mN2pQ4rT6vX8zA1cE3gI5kM7oQ9sU1wY3aB5dF7hJ9lN"')
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=False, use_entropy=True)
        findings = scan_file(f, tmp_path, redactor)
        assert len(findings) >= 1
        assert findings[0].method == "entropy"

    def test_empty_file_returns_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.py"
        f.write_text("")
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache)
        findings = scan_file(f, tmp_path, redactor)
        assert findings == []

    def test_clean_file_returns_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text('name = "hello"\ncount = 42\n')
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache, use_context=True, use_entropy=True)
        findings = scan_file(f, tmp_path, redactor)
        assert findings == []

    def test_deduplicates_same_match_on_same_line(self, tmp_path: Path) -> None:
        f = tmp_path / "dup.py"
        # The builtin generic-secret-assignment and context may both match the same value
        f.write_text('password = "SuperSecret99"')
        cache = MappingCache()
        redactor = Redactor(get_builtin_rules(), cache, use_context=True, use_entropy=False)
        findings = scan_file(f, tmp_path, redactor)
        # Each unique (file, line, value) should appear only once
        keys = [(fd.file, fd.line, fd.value) for fd in findings]
        assert len(keys) == len(set(keys))

    def test_reports_correct_line_numbers(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.py"
        f.write_text('line1 = "ok"\nline2 = "ok"\npassword = "Secret12345"\nline4 = "ok"\n')
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        findings = scan_file(f, tmp_path, redactor)
        pw = [fd for fd in findings if "Secret12345" in fd.value]
        assert len(pw) >= 1
        assert pw[0].line == 3

    def test_relative_file_path(self, tmp_path: Path) -> None:
        sub = tmp_path / "src"
        sub.mkdir()
        f = sub / "app.py"
        f.write_text('token = "mytokenvalue1234"')
        cache = MappingCache()
        redactor = Redactor([], cache, use_context=True, use_entropy=False)
        findings = scan_file(f, tmp_path, redactor)
        assert len(findings) >= 1
        assert findings[0].file == "src/app.py"


# ---------------------------------------------------------------------------
# discover (full pipeline)
# ---------------------------------------------------------------------------

class TestDiscover:
    def test_discover_playground(self) -> None:
        report = discover(PLAYGROUND)
        assert report.files_scanned > 0
        assert len(report.findings) > 0

    def test_playground_finds_stripe_key(self) -> None:
        report = discover(PLAYGROUND)
        stripe = [f for f in report.findings if "stripe" in f.rule_id.lower() or "sk_live" in f.value]
        assert len(stripe) >= 1

    def test_playground_finds_jwt(self) -> None:
        report = discover(PLAYGROUND)
        jwt_findings = [f for f in report.findings if "jwt" in f.rule_id.lower() or "eyJ" in f.value]
        assert len(jwt_findings) >= 1

    def test_playground_finds_connection_string_password(self) -> None:
        report = discover(PLAYGROUND)
        conn_pw = [f for f in report.findings if "connection" in f.description.lower() or "context" in f.method]
        assert len(conn_pw) >= 1

    def test_playground_finds_openai_key(self) -> None:
        report = discover(PLAYGROUND)
        openai = [f for f in report.findings if "openai" in f.rule_id.lower() or "sk-proj-" in f.value]
        assert len(openai) >= 1

    def test_empty_directory(self, tmp_path: Path) -> None:
        report = discover(tmp_path)
        assert report.files_scanned == 0
        assert report.findings == []

    def test_clean_directory(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text('print("hello world")\n')
        report = discover(tmp_path)
        assert report.files_scanned == 1
        assert report.findings == []

    def test_directory_with_secret(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        report = discover(tmp_path)
        assert report.files_scanned == 1
        assert len(report.findings) >= 1
        assert any("AKIA" in f.value for f in report.findings)

    def test_skips_venv(self, tmp_path: Path) -> None:
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "lib.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        (tmp_path / "app.py").write_text("print(1)")
        report = discover(tmp_path)
        assert report.files_scanned == 1  # only app.py
        assert all(".venv" not in f.file for f in report.findings)


# ---------------------------------------------------------------------------
# print_report
# ---------------------------------------------------------------------------

class TestPrintReport:
    def test_empty_report(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = DiscoverReport(files_scanned=5, files_skipped=2)
        print_report(report)
        out = capsys.readouterr().out
        assert "5 file(s)" in out
        assert "No secrets" in out

    def test_report_with_findings(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = DiscoverReport(
            files_scanned=3,
            findings=[
                Finding(
                    file="config.py",
                    line=5,
                    value="AKIAIOSFODNN7EXAMPLE",
                    category="KEY",
                    method="builtin",
                    rule_id="aws-access-key",
                    description="AWS Access Key ID",
                ),
            ],
        )
        print_report(report)
        out = capsys.readouterr().out
        assert "config.py:5" in out
        assert "AKIAIOSFODNN7" in out
        assert "builtin" in out

    def test_quiet_mode_minimal(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = DiscoverReport(
            files_scanned=1,
            findings=[
                Finding(
                    file="a.py", line=1, value="AKIAIOSFODNN7EXAMPLE",
                    category="KEY", method="builtin",
                    rule_id="aws-access-key", description="AWS Access Key",
                ),
            ],
        )
        print_report(report, quiet=True)
        out = capsys.readouterr().out
        # Quiet mode should still show findings but not the summary header
        assert "a.py:1" in out
        assert "Scanned" not in out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_truncate_short_string(self) -> None:
        assert _truncate("hello", 40) == "hello"

    def test_truncate_long_string(self) -> None:
        result = _truncate("a" * 50, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_method_from_rule_id(self) -> None:
        assert _method_from_rule_id("context-password-assignment") == "context"
        assert _method_from_rule_id("entropy-detected") == "entropy"
        assert _method_from_rule_id("presidio-person") == "presidio"
        assert _method_from_rule_id("aws-access-key") == "builtin"

    def test_suggest_rule_id(self) -> None:
        finding = Finding(
            file="config.py", line=1, value="AKIAIOSFODNN7EXAMPLE",
            category="KEY", method="builtin",
            rule_id="aws-access-key", description="AWS Access Key",
        )
        rule_id = _suggest_rule_id(finding)
        assert rule_id.startswith("discover-key-")
        assert "akiaiosfodnn7example" in rule_id


# ---------------------------------------------------------------------------
# interactive_add
# ---------------------------------------------------------------------------

class TestInteractiveAdd:
    def test_no_findings_prints_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = DiscoverReport()
        result = interactive_add(report, Path("."))
        assert result == 0
        out = capsys.readouterr().out
        assert "No findings" in out

    def test_add_rule_via_interactive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = DiscoverReport(
            findings=[
                Finding(
                    file="config.py", line=5, value="my-secret-key-value",
                    category="KEY", method="context",
                    rule_id="context-secret-assignment", description="Secret in secret assignment",
                ),
            ],
        )
        # Simulate user input: y, accept default rule id, no replacement, then done
        inputs = iter(["y", "", ""])
        monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

        result = interactive_add(report, tmp_path)
        assert result == 0

        # Verify rule was written
        from rdx.core.rules import load_rules_file, get_rules_path
        rules = load_rules_file(get_rules_path(project_dir=tmp_path))
        assert len(rules) == 1
        assert "my\\-secret\\-key\\-value" in (rules[0].pattern or "")

    def test_skip_finding(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = DiscoverReport(
            findings=[
                Finding(
                    file="config.py", line=5, value="skip-this-value",
                    category="KEY", method="context",
                    rule_id="context-secret", description="Secret",
                ),
            ],
        )
        inputs = iter(["n"])
        monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

        result = interactive_add(report, tmp_path)
        assert result == 0

        from rdx.core.rules import load_rules_file, get_rules_path
        rules = load_rules_file(get_rules_path(project_dir=tmp_path))
        assert len(rules) == 0

    def test_quit_interactive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = DiscoverReport(
            findings=[
                Finding(
                    file="a.py", line=1, value="val1",
                    category="KEY", method="context", rule_id="r1", description="d1",
                ),
                Finding(
                    file="b.py", line=2, value="val2",
                    category="KEY", method="context", rule_id="r2", description="d2",
                ),
            ],
        )
        inputs = iter(["q"])
        monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

        result = interactive_add(report, tmp_path)
        assert result == 0

        from rdx.core.rules import load_rules_file, get_rules_path
        rules = load_rules_file(get_rules_path(project_dir=tmp_path))
        assert len(rules) == 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestCLI:
    def test_discover_subcommand_registered(self) -> None:
        from rdx.cli import build_parser
        parser = build_parser()
        # Should not raise when parsing discover
        args = parser.parse_args(["discover", str(PLAYGROUND)])
        assert args.command == "discover"
        assert args.directory == str(PLAYGROUND)
        assert not args.add
        assert not args.presidio
        assert not args.quiet

    def test_discover_with_flags(self) -> None:
        from rdx.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["discover", "/tmp", "--add", "--presidio", "-q"])
        assert args.add is True
        assert args.presidio is True
        assert args.quiet is True

    def test_discover_default_directory(self) -> None:
        from rdx.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["discover"])
        assert args.directory == "."

    def test_discover_in_known_commands(self) -> None:
        """Ensure discover is in the known set so it's not treated as catch-all."""
        from rdx.cli import main
        # Parsing "discover --help" should not hit the catch-all
        with pytest.raises(SystemExit) as exc_info:
            main(["discover", "--help"])
        assert exc_info.value.code == 0
