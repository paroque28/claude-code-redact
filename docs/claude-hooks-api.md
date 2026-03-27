# Claude Code Hooks API Reference

Research conducted 2026-03-27.

## Hook Events

Claude Code supports these hook events (in lifecycle order):

| Event | Fires When | Can Modify Input | Can Modify Output | Can Block |
|-------|-----------|-----------------|-------------------|-----------|
| SessionStart | Session begins | N/A | N/A | Yes |
| UserPromptSubmit | User submits prompt | **No** (additionalContext only) | N/A | Yes |
| PreToolUse | Before tool executes | **Yes** (`updatedInput`) | N/A | Yes |
| PostToolUse | After tool succeeds | N/A | **No** (MCP only via `updatedMCPToolOutput`) | Yes |
| Stop | Claude finishes response | N/A | N/A | Yes (forces continuation) |

## PreToolUse: `updatedInput` Per Tool

This is the most important hook for redaction. It fires before a tool executes and can modify tool parameters.

| Tool | updatedInput Fields | Notes |
|------|-------------------|-------|
| **Bash** | `command` | Can rewrite shell command |
| **Read** | `file_path`, `offset`, `limit` | Can redirect to different file |
| **Write** | `file_path`, `content` | Can modify content before writing |
| **Edit** | `file_path`, `old_string`, `new_string` | Can modify both strings |
| **Grep** | `pattern`, `path`, `glob`, `-i`, etc. | Can modify search pattern |
| **Glob** | `pattern` | Can modify glob pattern |
| **WebFetch** | `url`, `prompt` | Can modify URL |
| **WebSearch** | `query`, `allowed_domains` | Can modify search query |
| **Agent** | `prompt`, `tool_allowlist` | Can modify sub-agent instructions |
| **MCP tools** | Tool-specific fields | Depends on MCP schema |

### PreToolUse Input (stdin JSON)

```json
{
  "session_id": "abc123",
  "cwd": "/project",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": {
    "file_path": "/path/to/file",
    "limit": 2000,
    "offset": 0
  }
}
```

### PreToolUse Output (stdout JSON)

**Allow with modified input:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Content redacted",
    "updatedInput": {
      "file_path": "/path/to/shadow/file"
    }
  }
}
```

**Deny:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by rule [aws-key]"
  }
}
```

## PostToolUse: Output Cannot Be Modified

This is the critical limitation for redaction:

- PostToolUse fires **after** the tool has executed
- The tool output has **already been sent to the LLM context**
- You can only **block** (prevent Claude from using the result) or add `additionalContext`
- **Exception**: MCP tools support `updatedMCPToolOutput` to modify their result
- Standard tools (Read, Bash, Grep, etc.) **cannot** have output modified

### PostToolUse Input (stdin JSON)

```json
{
  "hook_event_name": "PostToolUse",
  "tool_name": "Read",
  "tool_response": {
    "content": "file content here..."
  }
}
```

### PostToolUse Output (stdout JSON)

```json
{
  "decision": "block",
  "reason": "Tool output contains secrets",
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "Optional context for Claude"
  }
}
```

## UserPromptSubmit: Prompt Cannot Be Modified

- Cannot change the user's prompt text
- Can add `additionalContext` (appended to context)
- Can block the entire prompt

### UserPromptSubmit Output

```json
{
  "decision": "block",
  "reason": "Prompt contains sensitive value"
}
```

## Key Limitations Summary

1. **No output modification** for standard tools (Read, Bash, Grep, Glob, etc.)
2. **No prompt modification** (only additionalContext or block)
3. **No synthetic results** - cannot intercept a tool and return fake data without executing
4. **No tool type change** - cannot convert a Read call into a Bash call
5. **updatedInput does NOT override deny rules** - permission rules still apply

## Workarounds

| Limitation | Workaround |
|-----------|------------|
| Can't modify Read output | Redirect `file_path` to a pre-redacted shadow file |
| Can't modify Bash output | Wrap command with proxy that redacts before printing |
| Can't modify Grep output | Block and redirect to Bash proxy (`rdx rg`) |
| Can't modify prompt | Block if contains sensitive values |
| Can't modify Glob output | Accept (file paths only, low risk) |

## Alternative: API Proxy Approach

Instead of per-tool hooks, intercept ALL API traffic between Claude Code and Anthropic servers. See `docs/api-proxy-approach.md`.
