"""Interactive init wizard for rdx.

Guides users through creating their .redaction_rules file and setting up rdx.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from rdx.core.models import Rule
from rdx.core.rules import PROJECT_RULES_FILE, save_rules_file
from rdx.setup.setup import setup_hooks, setup_proxy


def _ask(prompt: str, default: str = "") -> str:
    """Ask a question, return answer or default."""
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return answer if answer else default


def _ask_yn(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question."""
    hint = "Y/n" if default else "y/N"
    answer = _ask(f"{prompt} ({hint})", "")
    if not answer:
        return default
    return answer.lower().startswith("y")


def _slug(text: str) -> str:
    """Make a URL/ID-safe slug from text."""
    return re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()


def _escape_regex(text: str) -> str:
    """Escape special regex characters in text."""
    return re.escape(text)


def _build_company_rules(
    company: str,
    replacement_company: str,
    variants: list[str],
    replacement_variants: list[str],
) -> list[Rule]:
    """Build rules for company name and variants."""
    rules: list[Rule] = []

    rules.append(Rule(
        id="company",
        pattern=company,
        is_regex=False,
        replacement=replacement_company,
        category="PROJECT",
        description="Company name",
    ))

    # Lowercase variant automatically
    if company.lower() != company:
        rules.append(Rule(
            id="company-lower",
            pattern=company.lower(),
            is_regex=False,
            replacement=replacement_company.lower(),
            category="PROJECT",
            description="Company name (lowercase)",
        ))

    for i, (var, rep) in enumerate(zip(variants, replacement_variants)):
        rules.append(Rule(
            id=f"company-variant-{i}",
            pattern=var,
            is_regex=False,
            replacement=rep,
            category="PROJECT",
            description=f"Company variant: {var}",
        ))

    return rules


def _build_project_rules(project: str, replacement_project: str) -> list[Rule]:
    """Build rules for project codename."""
    return [Rule(
        id="project-name",
        pattern=project,
        is_regex=False,
        replacement=replacement_project,
        category="PROJECT",
        description="Project codename",
    )]


def _build_people_rules(
    names: list[str], replacements: list[str]
) -> list[Rule]:
    """Build rules for people's names."""
    rules: list[Rule] = []
    for name, repl in zip(names, replacements):
        slug = _slug(name)
        rules.append(Rule(
            id=f"person-{slug}",
            pattern=_escape_regex(name),
            replacement=repl,
            category="NAME",
            description=f"Person: {name}",
        ))
        # Add first-name rule
        first = name.split()[0]
        repl_first = repl.split()[0]
        if first != name:
            rules.append(Rule(
                id=f"person-{slug}-first",
                pattern=_escape_regex(first),
                replacement=repl_first,
                category="NAME",
                description=f"First name: {first}",
            ))
    return rules


def _build_email_domain_rules(
    domain: str, replacement_domain: str
) -> list[Rule]:
    """Build rules for email domain."""
    return [Rule(
        id="email-domain",
        pattern=_escape_regex(domain),
        replacement=replacement_domain,
        category="EMAIL",
        description=f"Email domain: {domain}",
    )]


def _build_host_domain_rules(
    domain: str, replacement_domain: str
) -> list[Rule]:
    """Build rules for internal hostname domain."""
    return [Rule(
        id="internal-domain",
        pattern=_escape_regex(domain),
        replacement=replacement_domain,
        category="HOST",
        description=f"Internal domain: {domain}",
    )]


def _build_token_rules(prefixes: list[str]) -> list[Rule]:
    """Build regex rules for custom API token prefixes."""
    rules: list[Rule] = []
    for prefix in prefixes:
        slug = _slug(prefix)
        escaped = _escape_regex(prefix)
        rules.append(Rule(
            id=f"token-{slug}",
            pattern=f"{escaped}[a-zA-Z0-9\\-]{{20,}}",
            is_regex=True,
            category="KEY",
            description=f"API token with prefix: {prefix}",
        ))
    return rules


def _build_ticket_rules(prefixes: list[str]) -> list[Rule]:
    """Build rules for ticket/issue prefixes (auto-token, no format-preserving)."""
    rules: list[Rule] = []
    for prefix in prefixes:
        slug = _slug(prefix)
        escaped = _escape_regex(prefix)
        rules.append(Rule(
            id=f"ticket-{slug}",
            pattern=f"{escaped}\\d{{3,}}",
            is_regex=True,
            category="PROJECT",
            description=f"Ticket IDs with prefix: {prefix}",
        ))
    return rules


def _run_interactive(project_dir: Path) -> int:
    """Run the interactive wizard flow."""
    rules: list[Rule] = []

    # 1. Welcome
    print()
    print("Welcome to rdx!")
    print("This wizard will help you create a .redaction_rules file")
    print("to protect sensitive information when using AI coding tools.")
    print()
    print("Press Enter to skip any question.")
    print()

    # 2. Company name
    company = _ask("What's your company name? (e.g., AcmeCorp)")
    if company:
        default_repl = "WidgetInc"
        replacement_company = _ask(
            f"Replacement company name?", default_repl
        )

        # 3. Company variants
        variants_str = _ask(
            "Any other forms? (comma-separated, e.g., acmecorp, ACME_CORP)"
        )
        variants: list[str] = []
        replacement_variants: list[str] = []
        if variants_str:
            variants = [v.strip() for v in variants_str.split(",") if v.strip()]
            for var in variants:
                repl = _ask(f"Replacement for '{var}'?", replacement_company.lower())
                replacement_variants.append(repl)

        rules.extend(
            _build_company_rules(company, replacement_company, variants, replacement_variants)
        )

    # 4. Project name
    project = _ask("What's your project codename? (optional, e.g., ProjectPhoenix)")
    if project:
        replacement_project = _ask(f"Replacement project name?", "ProjectEagle")
        rules.extend(_build_project_rules(project, replacement_project))

    # 5. People
    people_str = _ask(
        "Names to redact? (comma-separated, e.g., Marco Vitale, Sarah Chen)"
    )
    if people_str:
        names = [n.strip() for n in people_str.split(",") if n.strip()]
        replacements: list[str] = []
        for name in names:
            repl = _ask(f"Replacement for '{name}'?", "")
            if not repl:
                # Generate a simple replacement
                repl = f"Person{len(replacements) + 1}"
            replacements.append(repl)
        rules.extend(_build_people_rules(names, replacements))

    # 6. Email domain
    email_domain = _ask("Internal email domain? (e.g., acmecorp.com)")
    if email_domain:
        repl_email = _ask(f"Replacement email domain?", "example.com")
        rules.extend(_build_email_domain_rules(email_domain, repl_email))

    # 7. Internal domain
    host_domain = _ask("Internal hostname domain? (e.g., acmecorp.internal)")
    if host_domain:
        repl_host = _ask(f"Replacement hostname domain?", "example.test")
        rules.extend(_build_host_domain_rules(host_domain, repl_host))

    # 8. Custom token prefixes
    token_str = _ask(
        "Custom API token prefix? (comma-separated, e.g., acmetk-, acme-deploy-)"
    )
    if token_str:
        prefixes = [p.strip() for p in token_str.split(",") if p.strip()]
        rules.extend(_build_token_rules(prefixes))

    # 9. Ticket prefix
    ticket_str = _ask("Issue/ticket prefix? (comma-separated, e.g., JIRA-, PHOENIX-)")
    if ticket_str:
        prefixes = [p.strip() for p in ticket_str.split(",") if p.strip()]
        rules.extend(_build_ticket_rules(prefixes))

    if not rules:
        print()
        print("No rules configured. You can always run 'rdx init' again or")
        print("edit .redaction_rules manually.")
        return 0

    # 10. Mode selection
    print()
    mode = _ask("Use proxy mode or hooks mode? [proxy/hooks]", "hooks")
    mode = mode.lower().strip()
    if mode not in ("proxy", "hooks"):
        mode = "hooks"

    # 11. Write rules and run setup
    rules_path = project_dir / PROJECT_RULES_FILE
    save_rules_file(rules_path, rules)
    print(f"\nWrote {len(rules)} rule(s) to {rules_path}")

    if mode == "proxy":
        result = setup_proxy(project_dir)
    else:
        result = setup_hooks(project_dir)

    print(f"\nSetup complete ({mode} mode)!")
    print(f"  Rules file: {rules_path}")
    if "rdx_md" in result:
        print(f"  RDX.md:     {result['rdx_md']}")
    if result.get("claude_md_modified"):
        print("  CLAUDE.md:  updated with RDX.md import")
    if mode == "hooks" and "settings_path" in result:
        print(f"  Settings:   {result['settings_path']}")
    print()
    print("You can edit rules anytime with: rdx rules edit")
    print("Validate your rules with:        rdx rules validate")

    return 0


def _run_non_interactive(project_dir: Path) -> int:
    """Run in non-interactive mode, reading JSON config from stdin."""
    try:
        config = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON on stdin: {e}", file=sys.stderr)
        return 1

    rules: list[Rule] = []

    # Company
    company = config.get("company", "")
    replacement_company = config.get("replacement_company", "WidgetInc")
    if company:
        variants = config.get("company_variants", [])
        replacement_variants = config.get("replacement_variants", [])
        # Pad replacement_variants if shorter
        while len(replacement_variants) < len(variants):
            replacement_variants.append(replacement_company.lower())
        rules.extend(
            _build_company_rules(company, replacement_company, variants, replacement_variants)
        )

    # Project
    project = config.get("project", "")
    replacement_project = config.get("replacement_project", "ProjectEagle")
    if project:
        rules.extend(_build_project_rules(project, replacement_project))

    # People
    people = config.get("people", [])
    if people:
        names = []
        replacements = []
        for entry in people:
            if isinstance(entry, dict):
                names.append(entry["name"])
                replacements.append(entry.get("replacement", f"Person{len(names)}"))
            else:
                names.append(entry)
                replacements.append(f"Person{len(names)}")
        rules.extend(_build_people_rules(names, replacements))

    # Email domain
    email_domain = config.get("email_domain", "")
    replacement_email = config.get("replacement_email_domain", "example.com")
    if email_domain:
        rules.extend(_build_email_domain_rules(email_domain, replacement_email))

    # Host domain
    host_domain = config.get("host_domain", "")
    replacement_host = config.get("replacement_host_domain", "example.test")
    if host_domain:
        rules.extend(_build_host_domain_rules(host_domain, replacement_host))

    # Token prefixes
    token_prefixes = config.get("token_prefixes", [])
    if token_prefixes:
        rules.extend(_build_token_rules(token_prefixes))

    # Ticket prefixes
    ticket_prefixes = config.get("ticket_prefixes", [])
    if ticket_prefixes:
        rules.extend(_build_ticket_rules(ticket_prefixes))

    # Write rules
    rules_path = project_dir / PROJECT_RULES_FILE
    if rules:
        save_rules_file(rules_path, rules)
        print(f"Wrote {len(rules)} rule(s) to {rules_path}")

    # Setup mode
    mode = config.get("mode", "hooks")
    if mode == "proxy":
        setup_proxy(project_dir)
    else:
        setup_hooks(project_dir)

    print(f"Setup complete ({mode} mode).")
    return 0


def run_init(project_dir: Path | None = None, non_interactive: bool = False) -> int:
    """Run the interactive init wizard. Returns exit code."""
    if project_dir is None:
        project_dir = Path.cwd()

    # Check if rules already exist
    rules_path = project_dir / PROJECT_RULES_FILE
    if rules_path.exists() and not non_interactive:
        overwrite = _ask_yn(
            f"{rules_path} already exists. Overwrite?", default=False
        )
        if not overwrite:
            print("Aborted.")
            return 0

    if non_interactive:
        return _run_non_interactive(project_dir)
    return _run_interactive(project_dir)
