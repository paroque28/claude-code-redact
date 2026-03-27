# API Proxy Approach: Intercepting Claude Code ↔ Anthropic Traffic

Research conducted 2026-03-27.

## The Insight

Instead of hooking individual tools (with gaps), we can sit **between Claude Code and the Anthropic API** and redact ALL traffic bidirectionally.

```
Claude Code  →  rdx proxy (localhost:8642)  →  api.anthropic.com
   user            redact outgoing               Anthropic
   sees             un-redact incoming            sees only
   real data                                      redacted data
```

## Why This Is Better Than Hooks

| Aspect | Hooks Approach | API Proxy Approach |
|--------|---------------|-------------------|
| Read tool output | Shadow file hack | Redacted automatically |
| Grep tool output | Must block + redirect | Redacted automatically |
| Bash tool output | Must wrap with proxy | Redacted automatically |
| User prompts | Can only block | Redacted automatically |
| Glob output | Can't redact | Redacted automatically |
| WebFetch output | Can't redact | Redacted automatically |
| Tool-specific code | Yes (per tool) | No (one place) |
| Shadow files | Yes | Not needed |
| Command wrapping | Yes | Not needed |
| Coverage gaps | Many | **Zero** |

## How It Works

### Setup

```bash
# Set in Claude Code settings or shell profile
export ANTHROPIC_BASE_URL=http://localhost:8642
```

Claude Code sends ALL API requests to our proxy instead of `api.anthropic.com`.

### Request Flow (Outgoing → Redact)

1. Claude Code sends a Messages API request to `localhost:8642/v1/messages`
2. Request contains: system prompt, user messages, tool results (file content, command output, etc.)
3. Proxy scans ALL text content for patterns matching redaction rules
4. Replaces matches with unique tokens: `pablo` → `__RDX_NAME_a1b2c3__`
5. Forwards redacted request to `api.anthropic.com`
6. Anthropic/Claude only ever sees `__RDX_NAME_a1b2c3__`

### Response Flow (Incoming → Un-redact)

1. Anthropic streams SSE response back
2. Claude's response uses redacted tokens: "I updated `__RDX_NAME_a1b2c3__` in the file"
3. Claude's tool calls use redacted tokens: `Write(content="hello __RDX_NAME_a1b2c3__")`
4. Proxy un-redacts ALL text: `__RDX_NAME_a1b2c3__` → `pablo`
5. Claude Code receives: "I updated `pablo` in the file"
6. Tool calls execute with real content: `Write(content="hello pablo")`

### What Each Party Sees

| Actor | Sees |
|-------|------|
| **User** (terminal) | Real values (`pablo`) — their own data |
| **Claude Code** (local) | Real values (`pablo`) — executes real tool calls |
| **Anthropic API** | Redacted tokens (`__RDX_NAME_a1b2c3__`) |
| **Claude (LLM)** | Redacted tokens — works with them as if they're real |
| **Files on disk** | Real values (`pablo`) — never modified |

## Replacement Token Format

Tokens must be:
- **Unique**: won't appear in natural code/text
- **Deterministic**: same input → same token (for consistency)
- **Typed**: Claude can understand what category it is
- **Reversible**: unambiguous reverse lookup

### Format: `__RDX_<CATEGORY>_<HASH>__`

```
__RDX_NAME_a1b2c3d4__        # Person name
__RDX_EMAIL_e5f6g7h8__       # Email address
__RDX_KEY_i9j0k1l2__         # API key / secret
__RDX_HOST_m3n4o5p6__        # Hostname
__RDX_IP_q7r8s9t0__          # IP address
__RDX_PROJECT_u1v2w3x4__     # Project/company name
__RDX_CUSTOM_y5z6a7b8__      # User-defined category
```

Benefits:
- `__RDX_` prefix is extremely unlikely in real code (double underscore + unique prefix)
- `<CATEGORY>` tells Claude the semantic type (it can reason about "names" vs "keys")
- `<HASH>` is first 8 chars of SHA-256 of original, ensuring determinism
- `__` suffix clearly delimits the token

### Why Not Realistic Fakes?

The current project generates fake emails (`redacted-abc@example.com`), IPs (`10.x.x.x`), etc. But realistic fakes have problems:
- May collide with real values in the codebase
- Hard to un-redact reliably (is `10.0.1.5` real or fake?)
- Claude might make decisions based on fake values (e.g., connecting to a fake IP)

Obvious tokens like `__RDX_IP_a1b2c3d4__` are:
- Impossible to confuse with real values
- Trivially reversible via search-replace
- Claude understands they're placeholders and works with them correctly

## Secret Detection Strategies

### 1. User-Defined Rules (Existing)

```yaml
rules:
  - id: project-name
    pattern: 'AcmeCorp'
    action: redact
    category: PROJECT
```

### 2. Pattern-Based (Existing)

Regex patterns for known secret formats:
- AWS keys: `AKIA[0-9A-Z]{16}`
- GitHub tokens: `ghp_[a-zA-Z0-9]{36}`
- Generic API keys: `sk-[a-zA-Z0-9]{32,}`

### 3. Entropy-Based (New)

High-entropy strings are likely secrets:
```python
import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

# entropy > 4.5 on strings > 20 chars → likely a secret
```

### 4. Context-Based (New)

Detect secrets by their surroundings:
```
password = "..."     → value is likely a secret
api_key: "..."       → value is likely a secret
Authorization: "..." → value is likely a secret
```

### 5. Hashed Secrets (Existing)

For secrets that should be detectable without storing them in plaintext:
```bash
echo "SecretProjectName" | rdx secret add --id project-name
# Stores SHA-256 hash, matches via hash_extractor regex
```

## Mapping / Cache Architecture

### Forward Map (Redact)

```json
{
  "mappings": {
    "name-pii": {
      "pablo": "__RDX_NAME_a1b2c3d4__",
      "rodriguez": "__RDX_NAME_e5f6g7h8__"
    },
    "project-name": {
      "AcmeCorp": "__RDX_PROJECT_i9j0k1l2__"
    }
  }
}
```

### Reverse Map (Un-redact)

```json
{
  "__RDX_NAME_a1b2c3d4__": "pablo",
  "__RDX_NAME_e5f6g7h8__": "rodriguez",
  "__RDX_PROJECT_i9j0k1l2__": "AcmeCorp"
}
```

### Properties

- **Deterministic**: Same input always gets same token (SHA-256 based)
- **Persistent**: Saved to `.claude/rdx_mappings.json`
- **Collision-free**: 8-char hex hash + category prefix = effectively unique
- **Safe to search-replace**: `__RDX_` prefix won't match real code
- **Human-readable categories**: Claude can reason about the type

## Implementation Sketch

```python
# rdx proxy server (Python + httpx + uvicorn)

from fastapi import FastAPI, Request
import httpx

app = FastAPI()
ANTHROPIC_URL = "https://api.anthropic.com"

@app.post("/v1/messages")
async def proxy_messages(request: Request):
    body = await request.json()

    # Redact all text content in the request
    redacted_body = redact_messages(body)

    # Forward to real Anthropic API
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{ANTHROPIC_URL}/v1/messages",
            json=redacted_body,
            headers=forward_headers(request),
        )

    # Un-redact the response
    result = response.json()
    unredacted = unredact_messages(result)
    return unredacted

# For streaming (SSE), need to handle chunked responses
@app.post("/v1/messages")  # with stream=True header
async def proxy_messages_stream(request: Request):
    # ... buffer SSE events, un-redact text deltas, re-stream
```

## Streaming Considerations

The Anthropic API uses Server-Sent Events (SSE) for streaming. The proxy must:

1. **Buffer text deltas**: Claude sends text token-by-token. Redacted tokens may span multiple SSE events.
2. **Detect token boundaries**: Buffer until we see `__RDX_` ... `__` pattern complete, then un-redact and flush.
3. **Handle tool_use blocks**: Tool calls come as structured JSON in the stream. Parse, un-redact, re-emit.
4. **Minimize latency**: Only buffer when potentially mid-token. Flush immediately when no redaction pattern is in progress.

## Hybrid Approach: Proxy + Hooks

The proxy handles redaction (data never leaves the machine unredacted).
Hooks handle access control (blocking dangerous commands, path restrictions).

```
                        ┌─── Hooks (access control) ───┐
                        │  Block rm -rf                 │
Claude Code ──→ Hooks ──→ rdx proxy ──→ Anthropic API
                        │  Block /etc access            │
                        └───────────────────────────────┘
                              │
                              ▼ Redact outgoing
                              ▲ Un-redact incoming
```

## Audit Log

The proxy logs all redactions:
```jsonl
{"ts":"...","direction":"outgoing","redactions":5,"rules":["name-pii","project-name"]}
{"ts":"...","direction":"incoming","unredactions":3,"rules":["name-pii"]}
```

Inspect with `rdx audit` — see what was sent to Anthropic vs what Claude Code saw.

## Advantages Over Hooks

1. **Zero coverage gaps** — every byte going to Anthropic is scanned
2. **No tool-specific code** — one redaction pass on the full API payload
3. **No shadow files** — files on disk are never modified
4. **No command wrapping** — commands execute normally
5. **No `updatedInput` hacks** — clean architectural separation
6. **Works with ALL tools** — including future tools, MCP tools, custom tools
7. **Platform-agnostic** — works with any client using `ANTHROPIC_BASE_URL`
8. **Auditable** — complete log of what went to Anthropic

## Disadvantages

1. **Streaming complexity** — must handle SSE buffering and token boundary detection
2. **Latency** — adds a hop to every API call (localhost, so minimal)
3. **Process management** — proxy must be running before Claude Code starts
4. **Token overhead** — `__RDX_NAME_a1b2c3d4__` is longer than `pablo` (wastes context tokens)
5. **HTTPS handling** — need to forward TLS or terminate+re-establish
6. **More complex implementation** — async HTTP server vs simple stdin/stdout hooks
