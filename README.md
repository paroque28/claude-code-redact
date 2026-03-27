# claude-code-redact

Redaction proxy for AI coding tools — prevent secrets, PII, and NDA material from leaving your machine.

**CLI command:** `rdx`

## The Problem

When using Claude Code, OpenCode, or similar AI coding tools, **everything** is sent to external API servers: file contents, command output, user prompts. This includes API keys, company names under NDA, employee PII, and proprietary code.

Additionally, [prompt injection attacks](https://github.com/gricha/dangerous-skills) can trick the AI into exfiltrating secrets to attacker-controlled servers — with success rates up to 100%.

## How It Works

`rdx` sits between your AI tool and the LLM API. It redacts sensitive data before it leaves your machine, and un-redacts the response so your local tools work normally.

```
                        rdx
                         │
You ← real values ← [un-redact] ← Claude (sees only redacted tokens)
You → real values → [ redact  ] → Anthropic API (receives only redacted tokens)
                         │
                    Your machine
                  (secrets stay here)
```

### Two Replacement Strategies

**Format-preserving** (user-defined): `pablo` → `peter` — Claude reasons naturally about the value.

**Auto-token** (discovered PII/secrets): `sk-secret123` → `__RDX_KEY_a1b2c3d4__` — Claude treats it as an opaque placeholder.

## Quick Start

```bash
# Install
uv tool install claude-code-redact

# Define what to redact
cat > .redaction_rules << 'EOF'
rules:
  - id: my-name
    pattern: 'Pablo Rodriguez'
    replacement: 'Peter Smith'
    category: NAME

  - id: company
    pattern: 'AcmeCorp'
    replacement: 'WidgetInc'
    category: PROJECT
EOF

# Proxy mode (complete coverage, recommended)
rdx setup --proxy
rdx proxy start
# Claude Code now sends only redacted data to the API

# OR: Hooks mode (no daemon, some coverage gaps)
rdx setup --hooks
```

## Two Operation Modes

### Proxy Mode (Recommended)

Intercepts all API traffic via `ANTHROPIC_BASE_URL`. Zero coverage gaps — every byte is scanned.

```bash
rdx proxy start              # Start on localhost:8642
rdx proxy status             # Check status
rdx proxy stop               # Stop
```

### Hooks Mode

Claude Code hooks for per-tool redaction. No daemon needed, but can't modify Read/Grep output.

```bash
rdx setup --hooks            # Configure hooks in settings.json
```

## Detection Layers

1. **Explicit rules** — Your `.redaction_rules` file. You define what to redact and what to replace it with.
2. **Built-in patterns** — 16 regex rules for AWS keys, GitHub tokens, OpenAI keys, JWTs, private key headers, etc.
3. **Entropy detection** — Flags high-entropy strings (likely random secrets/tokens).
4. **Context detection** — Finds secrets by their surroundings (`password=`, `api_key:`, `Authorization: Bearer`, etc.).
5. **NLP discovery** *(optional)* — Microsoft Presidio catches PII you didn't think to list (names, emails, phone numbers).

```bash
# Install with NLP support
uv tool install "claude-code-redact[nlp]"
```

## Commands

```bash
rdx setup --proxy              # Configure proxy mode
rdx setup --hooks              # Configure hooks mode
rdx proxy start/stop/status    # Manage proxy

rdx rules edit                 # Edit rules in $EDITOR
rdx rules validate             # Check rules syntax
rdx rules list                 # Show all active rules
rdx secret add --id NAME       # Add hashed secret
rdx check FILE...              # Scan files for detectable secrets

rdx audit                      # Recent redaction events
rdx audit --stats              # Summary by rule/direction
rdx audit --show-values        # Show original ↔ redacted pairs
```

## Configuration

### `.redaction_rules` format

Place a `.redaction_rules` file in your project root (and optionally at `~/.claude/.redaction_rules` for global rules):

```yaml
rules:
  # Format-preserving: Claude sees "Peter Smith" instead of the real name
  - id: developer-name
    pattern: 'Marco Vitale'
    replacement: 'Peter Smith'
    category: NAME
    description: Lead developer name

  # Company name
  - id: company
    pattern: 'AcmeCorp'
    replacement: 'WidgetInc'
    category: PROJECT
    is_regex: false                 # Literal match, no regex

  # Internal domains
  - id: internal-domain
    pattern: 'acmecorp\.internal'   # Regex (escape the dot)
    replacement: 'widgetinc.test'
    category: HOST

  # Auto-token: no replacement specified → generates __RDX_KEY_<hash>__
  - id: custom-api-token
    pattern: 'acmetk-[a-zA-Z0-9\-]{20,}'
    category: KEY
    description: AcmeCorp API tokens

  # Company-prefixed tokens (acme-deploy-..., acme-session-..., etc.)
  - id: acme-keys
    pattern: 'acme-[a-z]+-[a-zA-Z0-9]{16,}'
    category: KEY

  # Ticket IDs (use auto-token to avoid collisions between different tickets)
  - id: project-tickets
    pattern: 'PHOENIX-\d{3,}'
    category: PROJECT

  # Hashed secret: detect without storing plaintext in the rules file
  - id: secret-project-name
    hashed: true
    pattern: 'sha256-hash-of-the-secret-here'
    hash_extractor: '\b[A-Z][a-zA-Z]+\b'
    category: PROJECT

  # Tool-specific: only applies to Bash commands
  - id: block-no-verify
    pattern: '--no-verify'
    action: block
    tool: Bash
    description: Prevent bypassing git hooks
```

### Rule fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | — | Unique identifier |
| `pattern` | Yes* | — | Regex or literal string to match |
| `replacement` | No | auto-token | Format-preserving value, or omit for `__RDX_*__` |
| `category` | No | `CUSTOM` | `NAME`, `EMAIL`, `KEY`, `IP`, `HOST`, `PROJECT`, `PATH`, `CUSTOM` |
| `action` | No | `redact` | `redact`, `block`, or `warn` |
| `is_regex` | No | `true` | Set `false` for literal string matching |
| `target` | No | `both` | `llm`, `tool`, or `both` |
| `tool` | No | all | Restrict to a specific tool (`Bash`, `Read`, etc.) |
| `description` | No | — | Human-readable description |
| `hashed` | No | `false` | Match by SHA-256 hash (don't store plaintext) |
| `hash_extractor` | No | — | Regex to extract candidates for hash comparison |
| `path_pattern` | No | — | File path glob (e.g., `*.env`, `**/secrets/*`) |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RDX_UPSTREAM_URL` | `https://api.anthropic.com` | Upstream API for proxy mode |
| `RDX_PORT` | `8642` | Proxy listen port |
| `ANTHROPIC_BASE_URL` | — | Set to `http://localhost:8642` when using proxy mode |

## Security Model

- **No mapping file on disk.** The reverse map (token → original) exists only in proxy process memory. Nothing to steal.
- **Deterministic tokens.** Same input always produces the same token (SHA-256 based). Claude's memory stays coherent across sessions.
- **Defense against exfiltration.** Even if a prompt injection succeeds, the exfiltrated data is redacted tokens — not real secrets.

## How Claude Knows About Redaction

`rdx setup` generates an `RDX.md` file appended to your project's `CLAUDE.md`. This tells Claude that redaction is active, shows examples of what redacted values look like, and instructs it to treat them as opaque identifiers.

## Status

Core engine, proxy server, and hooks mode are implemented with 264 tests passing. CLI, audit log, and RDX.md generation are in development.

## License

Apache-2.0
