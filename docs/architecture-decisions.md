# Architecture Decisions

## ADR-001: API Proxy vs Hooks for Redaction

**Date**: 2026-03-27
**Status**: Proposed (API proxy preferred)

### Context

We need to prevent secrets, project names, company names, and NDA material from leaving the user's machine unredacted when using Claude Code.

### Approaches Considered

#### A. Hooks Only (Original Project)

Per-tool hooks in Claude Code's hook system (PreToolUse, PostToolUse, UserPromptSubmit).

**Pros**: Simple, no extra process, already partially implemented
**Cons**: Many coverage gaps (PostToolUse can't modify output, UserPromptSubmit can't modify prompt), requires tool-specific handling, shadow files, command wrapping

#### B. API Proxy (ANTHROPIC_BASE_URL)

Local HTTP proxy between Claude Code and Anthropic's API. Redact all outgoing messages, un-redact all incoming responses.

**Pros**: Zero coverage gaps, no tool-specific code, clean separation, works with all tools including future ones
**Cons**: Streaming complexity (SSE), extra process to manage, slightly more complex implementation

#### C. Hybrid (Recommended)

API proxy for redaction + hooks for access control (blocking dangerous commands, path restrictions).

**Pros**: Best of both worlds — complete redaction coverage + fine-grained access control
**Cons**: Two systems to maintain

### Decision

**Hybrid approach (C)**. The API proxy handles ALL redaction concerns. Hooks handle access control (blocking, path rules, command validation).

### Rationale

The fundamental problem with hooks-only is that PostToolUse cannot modify output. This creates gaps for Read, Grep, Glob, WebFetch, and any future tool. The API proxy eliminates all gaps because it operates at the message level — every byte going to Anthropic passes through it.

## ADR-002: Replacement Token Format

**Date**: 2026-03-27
**Status**: Proposed

### Context

When redacting values, we need replacement tokens that are:
1. Unique (won't appear in natural code)
2. Deterministic (same input → same token)
3. Typed (Claude understands what it represents)
4. Reversible (unambiguous reverse lookup)
5. Safe for search-replace (high confidence we won't ruin anything)

### Approaches Considered

#### A. Realistic Fakes (Current)

`pablo` → `redacted-a1b2c3@example.com` (for email type)

**Problem**: Fake values may collide with real values. Hard to un-redact safely. Claude might act on fake values (e.g., connecting to a fake hostname).

#### B. Simple Placeholders

`pablo` → `[REDACTED]`

**Problem**: Not unique. Multiple redacted values become indistinguishable. Claude can't work with them.

#### C. Prefixed Tokens (Recommended)

`pablo` → `__RDX_NAME_a1b2c3d4__`

**Pros**:
- `__RDX_` prefix is extremely unlikely in real code
- Category (`NAME`, `KEY`, `EMAIL`, etc.) helps Claude reason
- Hash suffix ensures uniqueness
- Double-underscore delimiters make boundaries clear
- Trivially reversible via lookup table
- Safe for search-replace across any codebase

### Decision

Use `__RDX_<CATEGORY>_<HASH>__` format.

### Categories

| Category | Used For |
|----------|----------|
| NAME | Person names |
| EMAIL | Email addresses |
| KEY | API keys, secrets, tokens |
| IP | IP addresses |
| HOST | Hostnames |
| PROJECT | Project/company names |
| PATH | Sensitive file paths |
| CUSTOM | User-defined |

## ADR-003: Secret Detection Strategy

**Date**: 2026-03-27
**Status**: Proposed

### Layers

1. **User-defined rules** (explicit patterns in `.redaction_rules`)
2. **Known secret patterns** (regex library: AWS keys, GitHub tokens, etc.)
3. **Entropy-based detection** (high-entropy strings > threshold)
4. **Context-based detection** (values after `password=`, `api_key:`, etc.)
5. **Hashed secrets** (SHA-256 comparison without storing plaintext)

### Priority

User-defined rules take precedence. Each layer is independently configurable.

## ADR-004: Mapping Cache Architecture

**Date**: 2026-03-27
**Status**: Proposed

### Requirements

- Consistent mapping across sessions (same input → same token)
- Fast lookup in both directions (redact and un-redact)
- Persistent across proxy restarts
- Auditable (can inspect all mappings)

### Design

Single JSON file at `.claude/rdx_mappings.json`:

```json
{
  "version": 1,
  "forward": {
    "name-pii": {
      "pablo": "__RDX_NAME_a1b2c3d4__",
      "rodriguez": "__RDX_NAME_e5f6g7h8__"
    }
  },
  "reverse": {
    "__RDX_NAME_a1b2c3d4__": {"original": "pablo", "rule": "name-pii"},
    "__RDX_NAME_e5f6g7h8__": {"original": "rodriguez", "rule": "name-pii"}
  },
  "stats": {
    "total_redactions": 1247,
    "total_unredactions": 892,
    "last_updated": "2026-03-27T14:00:00Z"
  }
}
```

Forward map: used during redaction (outgoing to Anthropic)
Reverse map: used during un-redaction (incoming from Anthropic)
Both maps updated atomically on new redaction discoveries.

## ADR-005: CLI Name `rdx`

**Date**: 2026-03-27
**Status**: Accepted

Three-letter acronym "ReDaX" — short, easy to type, follows RTK's naming convention.

```bash
rdx proxy start          # Start the redaction proxy
rdx proxy stop           # Stop the proxy
rdx audit                # Inspect redaction log
rdx secret add --id x    # Add secret rule
rdx check file.txt       # Scan files for matches
rdx setup                # Configure Claude Code to use proxy
```
