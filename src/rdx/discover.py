"""Scan a project directory and suggest redaction rules based on detection layers.

Usage (via CLI):
    rdx discover [DIR] [--add] [--presidio] [-q]
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from rdx.core.mappings import MappingCache
from rdx.core.models import Match, Rule
from rdx.core.redactor import Redactor
from rdx.core.rules import (
    add_rule,
    get_rules_path,
    load_rules_file,
    save_rules_file,
)
from rdx.detect.patterns import get_builtin_rules


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single secret/PII finding in a file."""

    file: str
    line: int
    value: str
    category: str
    method: str  # "builtin", "context", "entropy", "presidio"
    rule_id: str
    description: str
    score: float = 1.0


@dataclass
class DiscoverReport:
    """Aggregated discovery results."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


# ---------------------------------------------------------------------------
# File walking
# ---------------------------------------------------------------------------

_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".sqlite", ".db",
    ".lock",
})

_ALWAYS_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "node_modules", ".venv", "venv", ".env",
    ".tox", ".nox", ".eggs",
    "dist", "build", ".egg-info",
    ".claude",
})

_MAX_FILE_SIZE = 1_000_000  # 1 MB


def _load_gitignore_patterns(directory: Path) -> list[str]:
    """Load .gitignore patterns from a directory."""
    gitignore = directory / ".gitignore"
    if not gitignore.exists():
        return []
    patterns: list[str] = []
    for line in gitignore.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _is_gitignored(path: Path, root: Path, patterns: list[str]) -> bool:
    """Check if a path matches any gitignore pattern."""
    rel = str(path.relative_to(root))
    name = path.name
    for pat in patterns:
        # Directory-only patterns (trailing /)
        clean = pat.rstrip("/")
        if fnmatch.fnmatch(name, clean) or fnmatch.fnmatch(rel, clean):
            return True
        if "/" not in clean and fnmatch.fnmatch(name, clean):
            return True
    return False


def walk_project_files(directory: Path) -> tuple[list[Path], int]:
    """Walk project files, skipping binary/large/ignored files.

    Returns (files, skipped_count).
    """
    gitignore_patterns = _load_gitignore_patterns(directory)
    files: list[Path] = []
    skipped = 0

    for item in sorted(directory.rglob("*")):
        if not item.is_file():
            continue

        # Skip files in always-skipped directories
        parts = item.relative_to(directory).parts
        if any(p in _ALWAYS_SKIP_DIRS for p in parts):
            skipped += 1
            continue

        # Skip gitignored files
        if _is_gitignored(item, directory, gitignore_patterns):
            skipped += 1
            continue

        # Skip binary extensions
        if item.suffix.lower() in _BINARY_EXTENSIONS:
            skipped += 1
            continue

        # Skip large files
        try:
            if item.stat().st_size > _MAX_FILE_SIZE:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue

        files.append(item)

    return files, skipped


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _method_from_rule_id(rule_id: str) -> str:
    """Determine the detection method from a rule id."""
    if rule_id.startswith("context-"):
        return "context"
    if rule_id == "entropy-detected":
        return "entropy"
    if rule_id.startswith("presidio-"):
        return "presidio"
    return "builtin"


def _line_number(text: str, offset: int) -> int:
    """Convert character offset to 1-based line number."""
    return text.count("\n", 0, offset) + 1


def scan_file(
    file_path: Path,
    root: Path,
    redactor: Redactor,
) -> list[Finding]:
    """Scan a single file and return findings."""
    try:
        text = file_path.read_text(errors="replace")
    except OSError:
        return []

    if not text.strip():
        return []

    result = redactor.redact(text)
    if not result.matches:
        return []

    rel_path = str(file_path.relative_to(root))
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    for match in result.matches:
        line = _line_number(text, match.start)
        key = (rel_path, line, match.text)
        if key in seen:
            continue
        seen.add(key)

        findings.append(Finding(
            file=rel_path,
            line=line,
            value=match.text,
            category=match.rule.category,
            method=_method_from_rule_id(match.rule.id),
            rule_id=match.rule.id,
            description=match.rule.description,
            score=match.score,
        ))

    return findings


def discover(
    directory: Path,
    *,
    use_presidio: bool = False,
    quiet: bool = False,
) -> DiscoverReport:
    """Scan a project directory and return a discovery report."""
    directory = directory.resolve()
    files, skipped = walk_project_files(directory)

    cache = MappingCache()
    redactor = Redactor(
        get_builtin_rules(),
        cache,
        use_entropy=True,
        use_context=True,
        use_presidio=use_presidio,
    )

    report = DiscoverReport(files_scanned=len(files), files_skipped=skipped)

    for file_path in files:
        findings = scan_file(file_path, directory, redactor)
        report.findings.extend(findings)

    # Deduplicate findings with same value and category across files
    # (keep all — different files are relevant)

    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _truncate(s: str, max_len: int = 40) -> str:
    """Truncate a string for display."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def print_report(report: DiscoverReport, quiet: bool = False) -> None:
    """Print a human-readable report of findings."""
    if not quiet:
        print(f"\nScanned {report.files_scanned} file(s), skipped {report.files_skipped}.")

    if not report.findings:
        if not quiet:
            print("No secrets or PII found.")
        return

    # Group by category
    by_category: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_category.setdefault(f.category, []).append(f)

    if not quiet:
        print(f"Found {len(report.findings)} finding(s):\n")

    for category in sorted(by_category):
        if not quiet:
            print(f"  [{category}]")
        for f in by_category[category]:
            value_display = _truncate(f.value)
            print(f"    {f.file}:{f.line}  {value_display:42s}  ({f.method}: {f.description})")
        if not quiet:
            print()


# ---------------------------------------------------------------------------
# Interactive add
# ---------------------------------------------------------------------------

def _suggest_rule_id(finding: Finding) -> str:
    """Generate a suggested rule id from a finding."""
    # Use the first meaningful part of the value
    safe = re.sub(r"[^a-zA-Z0-9]", "-", finding.value[:20]).strip("-").lower()
    return f"discover-{finding.category.lower()}-{safe}" if safe else f"discover-{finding.category.lower()}"


def interactive_add(
    report: DiscoverReport,
    project_dir: Path,
) -> int:
    """Interactively ask the user which findings to add as rules."""
    if not report.findings:
        print("No findings to add.")
        return 0

    # Deduplicate by (value, category) — same secret in multiple files needs one rule
    unique: dict[tuple[str, str], Finding] = {}
    for f in report.findings:
        key = (f.value, f.category)
        if key not in unique:
            unique[key] = f

    added = 0
    for finding in unique.values():
        value_display = _truncate(finding.value, 50)
        print(f"\n  [{finding.category}] {value_display}")
        print(f"    Found in: {finding.file}:{finding.line}")
        print(f"    Method: {finding.method} — {finding.description}")

        response = input("    Add rule? [y/N/q] ").strip().lower()
        if response == "q":
            break
        if response != "y":
            continue

        rule_id = _suggest_rule_id(finding)
        suggested_id = input(f"    Rule ID [{rule_id}]: ").strip() or rule_id
        replacement = input("    Replacement (blank for auto-token): ").strip() or None

        # Escape the value for use as a regex pattern
        pattern = re.escape(finding.value)

        add_rule(
            suggested_id,
            pattern,
            replacement=replacement,
            action="redact",
            category=finding.category,
            description=f"Discovered: {finding.description}",
            project_dir=project_dir,
        )
        added += 1
        print(f"    Added rule '{suggested_id}'")

    print(f"\n{added} rule(s) added to {get_rules_path(project_dir=project_dir)}")
    return 0
