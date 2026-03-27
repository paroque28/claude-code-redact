"""Tests for rule loading, saving, validation, and merging."""

from pathlib import Path

import pytest

from rdx.core.rules import (
    load_rules,
    load_rules_file,
    save_rules_file,
    validate_rules_file,
)
from rdx.core.models import Rule


@pytest.fixture
def tmp_rules_file(tmp_path: Path) -> Path:
    """Create a temporary rules file path."""
    return tmp_path / ".redaction_rules"


# --- Loading ---


def test_load_empty_file(tmp_rules_file: Path) -> None:
    """Loading from non-existent file returns empty list."""
    rules = load_rules_file(tmp_rules_file)
    assert rules == []


def test_load_empty_yaml(tmp_rules_file: Path) -> None:
    """Loading from file with no rules key returns empty list."""
    tmp_rules_file.write_text("# empty config\n")
    rules = load_rules_file(tmp_rules_file)
    assert rules == []


def test_load_rules_file(tmp_rules_file: Path) -> None:
    """Load rules from a well-formed YAML file."""
    tmp_rules_file.write_text("""
rules:
  - id: my-name
    pattern: 'pablo'
    replacement: 'peter'
    category: NAME
    description: Redact developer name
""")
    rules = load_rules_file(tmp_rules_file)
    assert len(rules) == 1
    assert rules[0].id == "my-name"
    assert rules[0].pattern == "pablo"
    assert rules[0].replacement == "peter"
    assert rules[0].category == "NAME"
    assert rules[0].action == "redact"  # default
    assert rules[0].target == "both"  # default
    assert rules[0].is_regex is True  # default


def test_load_rules_all_fields(tmp_rules_file: Path) -> None:
    """Load a rule with every field populated."""
    tmp_rules_file.write_text("""
rules:
  - id: full-rule
    pattern: 'secret.*'
    path_pattern: '*.env'
    is_regex: false
    hashed: true
    hash_extractor: '\\b\\w+\\b'
    action: block
    replacement: '***'
    category: KEY
    target: tool
    tool: Bash
    description: Full rule
""")
    rules = load_rules_file(tmp_rules_file)
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "full-rule"
    assert r.is_regex is False
    assert r.hashed is True
    assert r.hash_extractor == r"\b\w+\b"
    assert r.action == "block"
    assert r.category == "KEY"
    assert r.target == "tool"
    assert r.tool == "Bash"


# --- Saving ---


def test_save_rules_file(tmp_rules_file: Path) -> None:
    """Save rules to YAML and reload them."""
    rules = [
        Rule(id="rule1", pattern="abc", description="First rule", category="NAME"),
        Rule(id="rule2", pattern="def", action="redact", replacement="***"),
    ]
    save_rules_file(tmp_rules_file, rules)

    loaded = load_rules_file(tmp_rules_file)
    assert len(loaded) == 2
    assert loaded[0].id == "rule1"
    assert loaded[0].category == "NAME"
    assert loaded[1].id == "rule2"
    assert loaded[1].replacement == "***"


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    """save_rules_file creates parent directories as needed."""
    deep_path = tmp_path / "a" / "b" / ".redaction_rules"
    save_rules_file(deep_path, [Rule(id="r1", pattern="x")])
    loaded = load_rules_file(deep_path)
    assert len(loaded) == 1


def test_save_omits_defaults(tmp_rules_file: Path) -> None:
    """Default values are omitted from saved YAML for cleanliness."""
    rules = [Rule(id="minimal", pattern="test")]
    save_rules_file(tmp_rules_file, rules)

    content = tmp_rules_file.read_text()
    # action=redact is the default and should be omitted
    assert "action" not in content
    # category=CUSTOM is the default and should be omitted
    assert "category" not in content
    # target=both is the default and should be omitted
    assert "target" not in content


# --- Merging ---


def test_load_rules_merges_global_and_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Project rules override global rules with the same id."""
    global_dir = tmp_path / "global"
    global_dir.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Patch GLOBAL_RULES_FILE
    monkeypatch.setattr(
        "rdx.core.rules.GLOBAL_RULES_FILE", global_dir / ".redaction_rules"
    )

    # Create global rules
    (global_dir / ".redaction_rules").write_text("""
rules:
  - id: shared-rule
    pattern: global-pattern
  - id: global-only
    pattern: global-only-pattern
""")

    # Create project rules
    (project_dir / ".redaction_rules").write_text("""
rules:
  - id: shared-rule
    pattern: project-pattern
  - id: project-only
    pattern: project-only-pattern
""")

    rules = load_rules(project_dir)
    rules_by_id = {r.id: r for r in rules}

    assert len(rules) == 3
    assert rules_by_id["shared-rule"].pattern == "project-pattern"  # Project wins
    assert rules_by_id["global-only"].pattern == "global-only-pattern"
    assert rules_by_id["project-only"].pattern == "project-only-pattern"


def test_load_rules_global_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When no project rules exist, only global rules are returned."""
    global_dir = tmp_path / "global"
    global_dir.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    monkeypatch.setattr(
        "rdx.core.rules.GLOBAL_RULES_FILE", global_dir / ".redaction_rules"
    )

    (global_dir / ".redaction_rules").write_text("""
rules:
  - id: global-rule
    pattern: global-pattern
""")

    rules = load_rules(project_dir)
    assert len(rules) == 1
    assert rules[0].id == "global-rule"


# --- Validation ---


def test_validate_valid_rules(tmp_rules_file: Path) -> None:
    """Validation passes for valid rules."""
    tmp_rules_file.write_text("""
rules:
  - id: test-rule
    pattern: "secret.*"
    action: block
""")
    errors = validate_rules_file(tmp_rules_file)
    assert errors == []


def test_validate_missing_file(tmp_path: Path) -> None:
    """Validation returns empty for non-existent file."""
    errors = validate_rules_file(tmp_path / "nonexistent")
    assert errors == []


def test_validate_invalid_yaml(tmp_rules_file: Path) -> None:
    """Validation catches YAML syntax errors."""
    tmp_rules_file.write_text("rules: [invalid yaml")
    errors = validate_rules_file(tmp_rules_file)
    assert len(errors) == 1
    assert "YAML syntax error" in errors[0]


def test_validate_missing_id(tmp_rules_file: Path) -> None:
    """Validation catches missing id field."""
    tmp_rules_file.write_text("""
rules:
  - pattern: "test"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("missing required field 'id'" in e for e in errors)


def test_validate_missing_pattern(tmp_rules_file: Path) -> None:
    """Validation catches missing pattern and path_pattern fields."""
    tmp_rules_file.write_text("""
rules:
  - id: test
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("must have 'pattern' or 'path_pattern'" in e for e in errors)


def test_validate_invalid_regex(tmp_rules_file: Path) -> None:
    """Validation catches invalid regex patterns."""
    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "[invalid"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid regex pattern" in e for e in errors)


def test_validate_invalid_action(tmp_rules_file: Path) -> None:
    """Validation catches invalid action values."""
    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "test"
    action: invalid
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid action" in e for e in errors)


def test_validate_invalid_category(tmp_rules_file: Path) -> None:
    """Validation catches invalid category values."""
    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "test"
    category: INVALID
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid category" in e for e in errors)


def test_validate_invalid_target(tmp_rules_file: Path) -> None:
    """Validation catches invalid target values."""
    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "test"
    target: invalid
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid target" in e for e in errors)


def test_validate_duplicate_ids(tmp_rules_file: Path) -> None:
    """Validation catches duplicate rule ids."""
    tmp_rules_file.write_text("""
rules:
  - id: dupe
    pattern: "test1"
  - id: dupe
    pattern: "test2"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("duplicate id" in e for e in errors)


def test_validate_path_pattern_only(tmp_rules_file: Path) -> None:
    """A rule with only path_pattern (no pattern) is valid."""
    tmp_rules_file.write_text("""
rules:
  - id: path-rule
    path_pattern: "*.env"
    action: block
""")
    errors = validate_rules_file(tmp_rules_file)
    assert errors == []
