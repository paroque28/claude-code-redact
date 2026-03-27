"""Full CLI entry point for rdx.

Usage:
    rdx proxy start [--port PORT]
    rdx proxy stop
    rdx proxy status
    rdx setup --proxy | --hooks | --show
    rdx hook                        (reads JSON from stdin)
    rdx rewrite COMMAND             (un-redact + rewrite for rdx proxy)
    rdx rules edit [--global]
    rdx rules validate [--global]
    rdx rules list [--global]
    rdx secret add --id ID [--global]
    rdx secret list [--global]
    rdx check FILE... | --stdin
    rdx audit [--stats] [--show-values] [--tail N]
    rdx shadow clean
    rdx <anything-else>             (catch-all: execute with output redaction)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from rdx.core.mappings import MappingCache
from rdx.core.redactor import Redactor
from rdx.core.rules import (
    add_rule,
    get_rules_path,
    load_rules,
    load_rules_file,
    save_rules_file,
    validate_rules_file,
)
from rdx.core.scanner import hash_text
from rdx.core.unredactor import Unredactor
from rdx.detect.patterns import get_builtin_rules

PID_FILE = ".claude/rdx_proxy.pid"


# ── Helpers ────────────────────────────────────────────────────────


def _project_dir() -> Path:
    return Path.cwd()


def _pid_path() -> Path:
    return _project_dir() / PID_FILE


def _build_rules() -> list:
    rules = load_rules()
    rules.extend(get_builtin_rules())
    return rules


# ── proxy ──────────────────────────────────────────────────────────


def cmd_proxy_start(args: argparse.Namespace) -> int:
    """Start the redaction proxy server in the background."""
    port = args.port
    pid_path = _pid_path()

    # Check if already running
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 0)  # Check if process exists
            print(f"Proxy already running (pid {pid})")
            return 1
        except (OSError, ValueError):
            pid_path.unlink(missing_ok=True)

    pid_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "rdx.proxy.server:app",
            "--host", "127.0.0.1",
            "--port", str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid_path.write_text(str(proc.pid))
    print(f"Proxy started on http://127.0.0.1:{port} (pid {proc.pid})")
    return 0


def cmd_proxy_stop(args: argparse.Namespace) -> int:
    """Stop the redaction proxy server."""
    pid_path = _pid_path()
    if not pid_path.exists():
        print("Proxy not running")
        return 1

    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Proxy stopped (pid {pid})")
    except (OSError, ValueError) as e:
        print(f"Could not stop proxy: {e}")
    finally:
        pid_path.unlink(missing_ok=True)
    return 0


def cmd_proxy_status(args: argparse.Namespace) -> int:
    """Show proxy server status."""
    pid_path = _pid_path()
    if not pid_path.exists():
        print("Proxy: not running")
        return 0

    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, 0)
        print(f"Proxy: running (pid {pid})")
    except (OSError, ValueError):
        print("Proxy: not running (stale pid file)")
        pid_path.unlink(missing_ok=True)
    return 0


# ── init ───────────────────────────────────────────────────────────


def cmd_init(args: argparse.Namespace) -> int:
    """Run the interactive init wizard."""
    from rdx.init import run_init
    return run_init(
        project_dir=_project_dir(),
        non_interactive=args.non_interactive,
    )


# ── setup ──────────────────────────────────────────────────────────


def cmd_setup(args: argparse.Namespace) -> int:
    """Configure Claude Code integration."""
    if args.show:
        _show_setup()
        return 0
    if args.proxy:
        return _setup_proxy()
    if args.hooks:
        return _setup_hooks()
    print("Specify --proxy, --hooks, or --show")
    return 1


def _show_setup() -> None:
    """Display current configuration."""
    rules_path = get_rules_path()
    print(f"Project rules: {rules_path} ({'exists' if rules_path.exists() else 'not found'})")
    global_path = get_rules_path(global_=True)
    print(f"Global rules:  {global_path} ({'exists' if global_path.exists() else 'not found'})")
    pid_path = _pid_path()
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 0)
            print(f"Proxy:         running (pid {pid})")
        except (OSError, ValueError):
            print("Proxy:         not running")
    else:
        print("Proxy:         not running")


def _setup_proxy() -> int:
    """Set up proxy mode configuration."""
    print("Proxy setup: set ANTHROPIC_BASE_URL=http://127.0.0.1:8100")
    print("Then run: rdx proxy start")
    return 0


def _setup_hooks() -> int:
    """Set up hooks mode configuration."""
    print("Hooks setup: add to .claude/settings.json:")
    print(json.dumps({
        "hooks": {
            "PreToolUse": [{"command": "rdx hook"}],
            "PostToolUse": [{"command": "rdx hook"}],
            "UserPromptSubmit": [{"command": "rdx hook"}],
        }
    }, indent=2))
    return 0


# ── hook ───────────────────────────────────────────────────────────


def cmd_hook(args: argparse.Namespace) -> int:
    """Run as a Claude Code hook (reads JSON from stdin)."""
    from rdx.hooks.hook import run_hook
    return run_hook()


# ── rewrite ────────────────────────────────────────────────────────


def cmd_rewrite(args: argparse.Namespace) -> int:
    """Un-redact and rewrite a command for rdx proxy execution."""
    command = " ".join(args.command)
    if not command:
        return 0

    cache = MappingCache()
    unredactor = Unredactor(cache)
    from rdx.hooks.rewrite import rewrite_command
    result = rewrite_command(command, unredactor)
    print(result if result is not None else command)
    return 0


# ── rules ──────────────────────────────────────────────────────────


def cmd_rules_edit(args: argparse.Namespace) -> int:
    """Open rules file in $EDITOR, then validate."""
    path = get_rules_path(global_=args.global_)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rules: []\n")

    editor = os.environ.get("EDITOR", "vi")
    ret = subprocess.call([editor, str(path)])
    if ret != 0:
        return ret

    errors = validate_rules_file(path)
    if errors:
        print("Validation errors:")
        for err in errors:
            print(f"  - {err}")
        return 1
    print("Rules valid.")
    return 0


def cmd_rules_validate(args: argparse.Namespace) -> int:
    """Validate the rules file."""
    path = get_rules_path(global_=args.global_)
    if not path.exists():
        print(f"No rules file at {path}")
        return 0

    errors = validate_rules_file(path)
    if errors:
        for err in errors:
            print(f"  - {err}")
        return 1
    rules = load_rules_file(path)
    print(f"Valid: {len(rules)} rule(s)")
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    """List all rules."""
    if args.global_:
        rules = load_rules_file(get_rules_path(global_=True))
    else:
        rules = load_rules()
    if not rules:
        print("No rules configured.")
        return 0

    for r in rules:
        action = r.action.upper()
        target = f" target={r.target}" if r.target != "both" else ""
        tool = f" tool={r.tool}" if r.tool else ""
        hashed = " [hashed]" if r.hashed else ""
        pattern = r.pattern[:40] + "..." if r.pattern and len(r.pattern) > 40 else (r.pattern or "")
        desc = f" — {r.description}" if r.description else ""
        print(f"  {r.id:30s} {action:6s} {r.category:8s} {pattern}{hashed}{target}{tool}{desc}")
    return 0


# ── secret ─────────────────────────────────────────────────────────


def cmd_secret_add(args: argparse.Namespace) -> int:
    """Add a hashed secret rule."""
    rule_id = args.id
    secret = os.environ.get("REDACT_SECRET", "")
    if not secret:
        print("Enter the secret value (will be hashed, not stored):")
        secret = sys.stdin.readline().strip()
    if not secret:
        print("No secret provided.")
        return 1

    hashed = hash_text(secret)
    add_rule(
        rule_id,
        hashed,
        action=args.action,
        category=args.category,
        description=args.description or f"Hashed secret {rule_id}",
        global_=args.global_,
    )
    # Mark the rule as hashed by reloading and patching
    path = get_rules_path(global_=args.global_)
    rules = load_rules_file(path)
    for r in rules:
        if r.id == rule_id:
            r.hashed = True
            r.hash_extractor = args.extractor
            break
    save_rules_file(path, rules)

    print(f"Secret rule '{rule_id}' added (SHA-256: {hashed[:16]}...)")
    return 0


def cmd_secret_list(args: argparse.Namespace) -> int:
    """List hashed secret rules."""
    if args.global_:
        rules = load_rules_file(get_rules_path(global_=True))
    else:
        rules = load_rules()
    hashed = [r for r in rules if r.hashed]
    if not hashed:
        print("No hashed secret rules.")
        return 0
    for r in hashed:
        print(f"  {r.id:30s} {r.category:8s} {r.description}")
    return 0


# ── check ──────────────────────────────────────────────────────────


def _line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert character offset to (line, col) — both 0-based."""
    line = text.count("\n", 0, offset)
    last_nl = text.rfind("\n", 0, offset)
    col = offset if last_nl == -1 else offset - last_nl - 1
    return line, col


def cmd_check(args: argparse.Namespace) -> int:
    """Scan files or stdin for secrets."""
    rules = _build_rules()
    cache = MappingCache()
    redactor = Redactor(rules, cache)
    found = 0
    use_json = getattr(args, "json", False)
    json_matches: list[dict] = []

    def _scan(text: str, source: str) -> None:
        nonlocal found
        result = redactor.redact(text, target="both")
        if not result.matches:
            return
        found += len(result.matches)
        for m in result.matches:
            line, col = _line_col(text, m.start)
            if use_json:
                replacement = cache.get_or_create(
                    m.rule.id, m.text, m.rule.category, m.rule.replacement
                )
                json_matches.append({
                    "file": source, "line": line, "col": col,
                    "start": m.start, "end": m.end,
                    "original": m.text, "replacement": replacement,
                    "rule_id": m.rule.id, "category": m.rule.category,
                    "description": m.rule.description, "action": m.rule.action,
                })
            elif not args.quiet:
                print(f"  {source}:{line + 1}: [{m.rule.id}] {m.rule.description}")

    if args.stdin:
        _scan(sys.stdin.read(), "stdin")
    else:
        for file_path in args.files:
            p = Path(file_path)
            if not p.exists():
                print(f"  {file_path}: not found", file=sys.stderr)
                continue
            try:
                text = p.read_text()
            except (OSError, UnicodeDecodeError) as e:
                print(f"  {file_path}: {e}", file=sys.stderr)
                continue
            _scan(text, file_path)

    if use_json:
        json.dump({"matches": json_matches, "total": found}, sys.stdout, indent=2)
        print()
        return 1 if found else 0

    if found:
        print(f"\n{found} issue(s) found.")
        return 1
    if not args.quiet:
        print("No issues found.")
    return 0


# ── audit ──────────────────────────────────────────────────────────


def cmd_audit(args: argparse.Namespace) -> int:
    """View or manage the audit log."""
    from rdx.audit.logger import AuditLogger

    logger = AuditLogger()

    if args.clear:
        count = logger.clear()
        print(f"Cleared {count} audit entries.")
        return 0

    if args.stats:
        stats = logger.get_stats()
        if stats.get("total", 0) == 0:
            print("No audit entries.")
            return 0
        for key, val in sorted(stats.items()):
            print(f"  {key:30s} {val}")
        return 0

    entries = logger.get_recent(args.tail)
    if not entries:
        print("No audit entries.")
        return 0

    for entry in entries:
        ts = entry.timestamp[:19]
        tool = f" [{entry.tool}]" if entry.tool else ""
        rules = f" rules={','.join(entry.rule_ids)}" if entry.rule_ids else ""
        count = f" count={entry.count}" if entry.count else ""
        detail = f" {entry.detail}" if entry.detail else ""
        print(f"  {ts} {entry.event:10s} {entry.direction:10s}{tool}{rules}{count}{detail}")
    return 0


# ── shadow ─────────────────────────────────────────────────────────


def cmd_shadow_clean(args: argparse.Namespace) -> int:
    """Remove all shadow files."""
    from rdx.hooks.shadow import clean_shadows
    count = clean_shadows(_project_dir())
    print(f"Removed {count} shadow file(s).")
    return 0


# ── catch-all ──────────────────────────────────────────────────────


def cmd_catchall(args: argparse.Namespace) -> int:
    """Execute an arbitrary command with stdout/stderr redaction."""
    command = args.rest
    if not command:
        return 0

    rules = _build_rules()
    cache = MappingCache()
    redactor = Redactor(rules, cache)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(f"rdx: command not found: {command[0]}", file=sys.stderr)
        return 127

    if result.stdout:
        scan = redactor.redact(result.stdout, target="tool")
        sys.stdout.write(scan.redacted_text or result.stdout)
    if result.stderr:
        scan = redactor.redact(result.stderr, target="tool")
        sys.stderr.write(scan.redacted_text or result.stderr)

    return result.returncode


# ── Parser ─────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rdx",
        description="Redaction proxy for AI coding tools",
    )
    subparsers = parser.add_subparsers(dest="command")

    # proxy
    proxy_parser = subparsers.add_parser("proxy", help="Manage the proxy server")
    proxy_sub = proxy_parser.add_subparsers(dest="proxy_command")

    start_p = proxy_sub.add_parser("start", help="Start proxy server")
    start_p.add_argument("--port", type=int, default=8100, help="Port (default: 8100)")
    start_p.set_defaults(func=cmd_proxy_start)

    stop_p = proxy_sub.add_parser("stop", help="Stop proxy server")
    stop_p.set_defaults(func=cmd_proxy_stop)

    status_p = proxy_sub.add_parser("status", help="Show proxy status")
    status_p.set_defaults(func=cmd_proxy_status)

    # init
    init_p = subparsers.add_parser("init", help="Interactive setup wizard")
    init_p.add_argument("--non-interactive", action="store_true", help="Read JSON config from stdin")
    init_p.set_defaults(func=cmd_init)

    # setup
    setup_p = subparsers.add_parser("setup", help="Configure Claude Code integration")
    setup_p.add_argument("--proxy", action="store_true", help="Set up proxy mode")
    setup_p.add_argument("--hooks", action="store_true", help="Set up hooks mode")
    setup_p.add_argument("--show", action="store_true", help="Show current configuration")
    setup_p.set_defaults(func=cmd_setup)

    # hook
    hook_p = subparsers.add_parser("hook", help="Run as Claude Code hook (stdin JSON)")
    hook_p.set_defaults(func=cmd_hook)

    # rewrite
    rewrite_p = subparsers.add_parser("rewrite", help="Rewrite command for rdx proxy")
    rewrite_p.add_argument("command", nargs=argparse.REMAINDER, help="Command to rewrite")
    rewrite_p.set_defaults(func=cmd_rewrite)

    # rules
    rules_p = subparsers.add_parser("rules", help="Manage redaction rules")
    rules_sub = rules_p.add_subparsers(dest="rules_command")

    edit_p = rules_sub.add_parser("edit", help="Edit rules in $EDITOR")
    edit_p.add_argument("--global", dest="global_", action="store_true")
    edit_p.set_defaults(func=cmd_rules_edit)

    validate_p = rules_sub.add_parser("validate", help="Validate rules file")
    validate_p.add_argument("--global", dest="global_", action="store_true")
    validate_p.set_defaults(func=cmd_rules_validate)

    list_p = rules_sub.add_parser("list", help="List all rules")
    list_p.add_argument("--global", dest="global_", action="store_true")
    list_p.set_defaults(func=cmd_rules_list)

    # secret
    secret_p = subparsers.add_parser("secret", help="Manage hashed secrets")
    secret_sub = secret_p.add_subparsers(dest="secret_command")

    add_p = secret_sub.add_parser("add", help="Add a hashed secret rule")
    add_p.add_argument("--id", required=True, help="Rule ID")
    add_p.add_argument("--action", default="redact", help="Action (default: redact)")
    add_p.add_argument("--category", default="KEY", help="Category (default: KEY)")
    add_p.add_argument("--description", default="", help="Description")
    add_p.add_argument("--extractor", default=None, help="Hash extractor regex")
    add_p.add_argument("--global", dest="global_", action="store_true")
    add_p.set_defaults(func=cmd_secret_add)

    slist_p = secret_sub.add_parser("list", help="List hashed secret rules")
    slist_p.add_argument("--global", dest="global_", action="store_true")
    slist_p.set_defaults(func=cmd_secret_list)

    # check
    check_p = subparsers.add_parser("check", help="Scan files for secrets")
    check_p.add_argument("files", nargs="*", help="Files to scan")
    check_p.add_argument("--stdin", action="store_true", help="Read from stdin")
    check_p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    check_p.add_argument("--json", action="store_true", help="JSON output for tooling")
    check_p.set_defaults(func=cmd_check)

    # audit
    audit_p = subparsers.add_parser("audit", help="View audit log")
    audit_p.add_argument("--stats", action="store_true", help="Show aggregate stats")
    audit_p.add_argument("--clear", action="store_true", help="Clear the audit log")
    audit_p.add_argument("--tail", type=int, default=50, help="Number of recent entries (default 50)")
    audit_p.set_defaults(func=cmd_audit)

    # shadow
    shadow_p = subparsers.add_parser("shadow", help="Manage shadow files")
    shadow_sub = shadow_p.add_subparsers(dest="shadow_command")

    clean_p = shadow_sub.add_parser("clean", help="Remove all shadow files")
    clean_p.set_defaults(func=cmd_shadow_clean)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()

    # Catch-all: if first arg is not a known subcommand, treat as command to run
    known = {"proxy", "setup", "init", "hook", "rewrite", "rules", "secret", "check", "audit", "shadow"}
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] not in known and argv[0] not in ("-h", "--help"):
        ns = argparse.Namespace(rest=argv)
        return cmd_catchall(ns)

    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
