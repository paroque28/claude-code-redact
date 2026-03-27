#!/usr/bin/env python3
"""Demo: run the rdx redactor against playground fixtures and show results.

Usage:
    cd /home/pablorod/code/redact/claude-code-redact
    uv run python scripts/test_redaction_demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rdx.core.mappings import MappingCache
from rdx.core.redactor import Redactor
from rdx.core.rules import load_rules_file
from rdx.core.unredactor import Unredactor
from rdx.detect.patterns import get_builtin_rules

PLAYGROUND = Path(__file__).parent.parent / "playground"
FIXTURES = PLAYGROUND / "fixtures"


def load_rules():
    user_rules = load_rules_file(PLAYGROUND / ".redaction_rules")
    return user_rules + get_builtin_rules()


def print_header(title: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def print_diff(label: str, original: str, redacted: str) -> None:
    """Show what changed between original and redacted."""
    orig_lines = original.splitlines()
    red_lines = redacted.splitlines()

    changes = []
    for i, (o, r) in enumerate(zip(orig_lines, red_lines)):
        if o != r:
            changes.append((i + 1, o, r))

    if not changes:
        print(f"\n  [{label}] No changes (clean)")
        return

    print(f"\n  [{label}] {len(changes)} lines redacted:")
    for line_num, orig, redacted_line in changes[:15]:  # Show first 15
        print(f"    L{line_num}:")
        print(f"      - {orig[:100]}")
        print(f"      + {redacted_line[:100]}")
    if len(changes) > 15:
        print(f"    ... and {len(changes) - 15} more")


def test_source_files() -> None:
    """Redact the playground source files."""
    print_header("SOURCE FILE REDACTION")

    cache = MappingCache()
    rules = load_rules()
    redactor = Redactor(rules, cache)
    unredactor = Unredactor(cache)

    for src_file in sorted((PLAYGROUND / "src").glob("*.py")):
        original = src_file.read_text()
        result = redactor.redact(original)
        if result.redacted_text and result.redacted_text != original:
            print_diff(src_file.name, original, result.redacted_text)

            # Verify round-trip
            restored = unredactor.unredact(result.redacted_text)
            if restored == original:
                print(f"    ✓ Round-trip OK")
            else:
                print(f"    ✗ Round-trip FAILED")
        else:
            print(f"\n  [{src_file.name}] No redactions needed")

    # Also test TASKS.md
    tasks_file = PLAYGROUND / "TASKS.md"
    if tasks_file.exists():
        original = tasks_file.read_text()
        result = redactor.redact(original)
        if result.redacted_text and result.redacted_text != original:
            print_diff("TASKS.md", original, result.redacted_text)
            restored = unredactor.unredact(result.redacted_text)
            if restored == original:
                print(f"    ✓ Round-trip OK")
            else:
                print(f"    ✗ Round-trip FAILED")

    print(f"\n  Mapping cache: {cache.stats()}")


def test_api_fixtures() -> None:
    """Redact the API request/response fixtures."""
    print_header("API REQUEST/RESPONSE REDACTION")

    cache = MappingCache()
    rules = load_rules()
    redactor = Redactor(rules, cache)
    unredactor = Unredactor(cache)

    for fixture_file in sorted(FIXTURES.glob("*.json")):
        original_text = fixture_file.read_text()
        original = json.loads(original_text)

        # Recursively redact all string values
        def redact_recursive(obj):
            if isinstance(obj, str):
                r = redactor.redact(obj)
                return r.redacted_text if r.redacted_text else obj
            if isinstance(obj, list):
                return [redact_recursive(item) for item in obj]
            if isinstance(obj, dict):
                return {k: redact_recursive(v) for k, v in obj.items()}
            return obj

        redacted = redact_recursive(original)
        redacted_text = json.dumps(redacted, indent=2)

        if redacted_text != json.dumps(original, indent=2):
            # Show key differences
            print(f"\n  [{fixture_file.name}]")

            # Find specific secrets that were redacted
            orig_str = json.dumps(original)
            red_str = json.dumps(redacted)

            secrets_found = []
            for redaction in cache.get_all_redactions():
                if redaction.original in orig_str and redaction.original not in red_str:
                    secrets_found.append(
                        f"    {redaction.original[:50]:50s} → {redaction.replacement[:30]}"
                    )

            if secrets_found:
                print(f"    Redacted values:")
                for s in secrets_found[:20]:
                    print(s)

            # Verify round-trip
            def unredact_recursive(obj):
                if isinstance(obj, str):
                    return unredactor.unredact(obj)
                if isinstance(obj, list):
                    return [unredact_recursive(item) for item in obj]
                if isinstance(obj, dict):
                    return {k: unredact_recursive(v) for k, v in obj.items()}
                return obj

            restored = unredact_recursive(redacted)
            if json.dumps(restored) == json.dumps(original):
                print(f"    ✓ Round-trip OK")
            else:
                print(f"    ✗ Round-trip FAILED")
        else:
            print(f"\n  [{fixture_file.name}] No redactions needed")

    print(f"\n  Mapping cache: {cache.stats()}")


def test_sensitive_values_gone() -> None:
    """Final check: verify no sensitive values survive in redacted output."""
    print_header("LEAK CHECK — sensitive values that should NOT appear in redacted output")

    cache = MappingCache()
    rules = load_rules()
    redactor = Redactor(rules, cache)

    sensitive_values = [
        "Marco Vitale",
        "Sarah Chen",
        "AcmeCorp",
        "ProjectPhoenix",
        "acmecorp.internal",
        "marco.vitale@acmecorp.com",
        "marco@acmecorp.com",
        "sarah.chen@acmecorp.com",
        "PHOENIX-1234",
        "PHOENIX-5678",
        "sk_live_51HG7dKLMnOpQrStUvWxYz",
        "acmetk-prod-x7k9m2nQ4rT6vX8zA1cE3gI5kM7oQ9s",
        "acme-deploy-f8h2j4l6n0p2r4t6v8x0z2b4d6f8h0j",
        "glpat-xxxx-yyyy-zzzz-aaaa-bbbb",
    ]

    # Collect all text from all files
    all_files = list((PLAYGROUND / "src").glob("*.py")) + [PLAYGROUND / "TASKS.md"]
    all_files += list(FIXTURES.glob("*.json"))

    leaks_found = 0
    for filepath in all_files:
        if not filepath.exists():
            continue
        original = filepath.read_text()
        result = redactor.redact(original)
        redacted = result.redacted_text or original

        for value in sensitive_values:
            if value in original and value in redacted:
                print(f"  ✗ LEAK: '{value}' still in {filepath.name}")
                leaks_found += 1

    if leaks_found == 0:
        print(f"  ✓ All {len(sensitive_values)} sensitive values redacted across {len(all_files)} files")
    else:
        print(f"\n  {leaks_found} leaks found!")


if __name__ == "__main__":
    test_source_files()
    test_api_fixtures()
    test_sensitive_values_gone()
    print(f"\n{'='*70}")
    print(f"  Done.")
    print(f"{'='*70}")
