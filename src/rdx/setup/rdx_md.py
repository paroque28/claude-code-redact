"""Generate RDX.md — instructions for Claude about active redaction."""

from __future__ import annotations

from pathlib import Path

from rdx.core.models import Rule
from rdx.core.rules import load_rules
from rdx.detect.patterns import get_builtin_rules

# Example tokens for each category, used in the markdown documentation.
_CATEGORY_EXAMPLES: dict[str, str] = {
    "NAME": "__RDX_NAME_a1b2c3d4__",
    "EMAIL": "__RDX_EMAIL_e5f6a7b8__",
    "KEY": "__RDX_KEY_c9d0e1f2__",
    "IP": "__RDX_IP_1a2b3c4d__",
    "HOST": "__RDX_HOST_5e6f7a8b__",
    "PROJECT": "__RDX_PROJECT_9c0d1e2f__",
    "PATH": "__RDX_PATH_3a4b5c6d__",
    "CUSTOM": "__RDX_CUSTOM_7e8f9a0b__",
}


def _collect_categories(rules: list[Rule]) -> dict[str, list[Rule]]:
    """Group rules by category."""
    by_category: dict[str, list[Rule]] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)
    return by_category


def _format_rules_table(rules: list[Rule]) -> str:
    """Format rules as a markdown table."""
    lines = ["| Rule ID | Category | Description | Token Example |", "| --- | --- | --- | --- |"]
    seen_ids: set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            continue
        seen_ids.add(rule.id)
        desc = rule.description or rule.id
        if rule.replacement:
            example = f"`{rule.replacement}`"
        else:
            example = f"`{_CATEGORY_EXAMPLES.get(rule.category, '__RDX_CUSTOM_xxxxxxxx__')}`"
        lines.append(f"| `{rule.id}` | {rule.category} | {desc} | {example} |")
    return "\n".join(lines)


def _format_preserving_section(rules: list[Rule]) -> str:
    """Generate a section about format-preserving replacements, if any exist."""
    fp_rules = [r for r in rules if r.replacement is not None]
    if not fp_rules:
        return ""

    lines = [
        "",
        "## Format-preserving replacements",
        "",
        "Some values are replaced with realistic-looking stand-ins rather than tokens:",
        "",
    ]
    for rule in fp_rules:
        desc = rule.description or rule.id
        lines.append(f"- **{desc}** (`{rule.id}`): replaced with `{rule.replacement}`")
    lines.append("")
    return "\n".join(lines)


def generate_rdx_md(
    project_dir: Path | None = None,
    include_builtins: bool = True,
    mode: str = "proxy",
) -> str:
    """Generate the contents of RDX.md.

    Parameters
    ----------
    project_dir:
        Project root. Used to load `.redaction_rules`.
    include_builtins:
        Whether to include built-in pattern rules in the documentation.
    mode:
        Either "proxy" or "hooks" — affects the explanation of how redaction works.
    """
    user_rules = load_rules(project_dir)
    all_rules = list(user_rules)
    if include_builtins:
        seen_ids = {r.id for r in user_rules}
        for r in get_builtin_rules():
            if r.id not in seen_ids:
                all_rules.append(r)

    categories = _collect_categories(all_rules)

    # Build category list
    active_categories = sorted(categories.keys())
    category_tokens = ", ".join(
        f"`{_CATEGORY_EXAMPLES.get(cat, '__RDX_' + cat + '_xxxxxxxx__')}`"
        for cat in active_categories
    )

    if mode == "proxy":
        how_it_works = (
            "All messages between you and the API pass through the rdx redaction proxy. "
            "Sensitive values in outgoing messages are replaced with redaction tokens before "
            "they reach the API. When responses come back, tokens are mapped back to original "
            "values automatically."
        )
    else:
        how_it_works = (
            "Claude Code hooks intercept tool calls and redact sensitive values before they "
            "are sent to the LLM. When you write files or run commands, tokens are un-redacted "
            "back to their original values automatically."
        )

    sections = [
        "# RDX Redaction Active",
        "",
        f"{how_it_works}",
        "",
        "## What you need to know",
        "",
        "- You will see redaction tokens in place of sensitive values",
        f"- Tokens look like: {category_tokens}",
        "- Each token is a deterministic placeholder — the same original value always maps "
        "to the same token",
        "- **Do not** try to guess or reconstruct the original values",
        "- **Do not** ask the user to share the original values",
        "- Treat tokens as opaque identifiers — use them as-is in your responses",
        "- When writing code or commands, use the tokens; they will be un-redacted automatically",
        "",
        "## Active categories",
        "",
        f"Redaction is active for: {', '.join(active_categories)}",
        "",
    ]

    # Rules table
    if all_rules:
        sections.extend([
            "## Rules",
            "",
            _format_rules_table(all_rules),
            "",
        ])

    # Format-preserving section
    fp_section = _format_preserving_section(all_rules)
    if fp_section:
        sections.append(fp_section)

    # Blocked rules
    blocked = [r for r in all_rules if r.action == "block"]
    if blocked:
        sections.extend([
            "## Blocked patterns",
            "",
            "The following patterns will cause the request to be blocked entirely:",
            "",
        ])
        for rule in blocked:
            desc = rule.description or rule.id
            sections.append(f"- **{desc}** (`{rule.id}`)")
        sections.append("")

    return "\n".join(sections)


def write_rdx_md(project_dir: Path, content: str | None = None, **kwargs: object) -> Path:
    """Write RDX.md to the project directory. Returns the path written."""
    if content is None:
        content = generate_rdx_md(project_dir=project_dir, **kwargs)  # type: ignore[arg-type]
    path = project_dir / "RDX.md"
    path.write_text(content)
    return path
