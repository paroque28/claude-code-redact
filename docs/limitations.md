# Known Limitations

## Claude Code Hook API Limitations

### 1. Cannot Modify Tool Output (PostToolUse)

PostToolUse hooks fire after the tool has executed. The output has already been sent to the LLM. You can only:
- **Block**: Prevent Claude from using the result
- **Add context**: Append advisory text via `additionalContext`
- **Exception**: MCP tools support `updatedMCPToolOutput`

**Impact**: Read, Grep, Glob output cannot be redacted in-place.
**Workaround**: Shadow files (Read), proxy wrapping (Bash), blocking with redirect (Grep).

### 2. Cannot Modify User Prompts (UserPromptSubmit)

Cannot change the user's prompt text. Only options:
- Block the entire prompt
- Add `additionalContext` (advisory, not a replacement)

**Impact**: If user types a secret, it reaches the LLM unless blocked.
**Workaround**: Block prompts containing un-redacted values.

### 3. Cannot Return Synthetic Results (PreToolUse)

PreToolUse can modify input or deny execution, but cannot return a fake result without executing the tool.

**Impact**: Cannot intercept Read and return redacted content directly.
**Workaround**: Redirect `file_path` to a pre-redacted shadow file.

### 4. Cannot Change Tool Type (PreToolUse)

A Read call cannot be converted to a Bash call. `updatedInput` modifies parameters of the current tool, not which tool runs.

**Impact**: Cannot transparently replace `Read file.py` with `rdx cat file.py`.
**Workaround**: Shadow file approach preserves the Read tool behavior.

### 5. Grep Output Leaks

Grep output cannot be modified. If we un-redact the search pattern (so it finds real matches), the output contains un-redacted values.

**Impact**: Claude sees real values in Grep results.
**Workaround**: Block Grep, redirect user to `rdx rg` via Bash.

## Redaction System Limitations

### 6. Mapping File Contains Originals

`redaction_mappings.json` stores `{"original_secret": "replacement"}`. Anyone with file access can see every value that was redacted.

**Mitigation**: File permissions, `.gitignore`, consider encrypting at rest.

### 7. No Streaming Redaction

All matching is done on full text buffers. Very large outputs may be slow.

**Mitigation**: Chunk processing for proxy output (future enhancement).

### 8. Replacement Collisions

If two different originals generate the same replacement, un-redaction becomes ambiguous.

**Mitigation**: Use unique prefixed replacements (e.g., `__RDX_a1b2c3__`). Deterministic hashing makes collisions extremely unlikely.

### 9. Partial Match Risk in Un-redaction

If a replacement string appears naturally in text (not from redaction), un-redacting would corrupt it.

**Mitigation**: Use distinctive replacement formats that don't appear in natural text (`__RDX_` prefix).

### 10. Shadow File Staleness

Shadow files may become stale if the original file changes between Read and Edit.

**Mitigation**: Check mtime before serving shadow file. Regenerate if original changed.

## Alternative Approaches

### API Proxy (Not Yet Implemented)

Instead of per-tool hooks, intercept ALL traffic between Claude Code and Anthropic's API. This would:
- Eliminate all tool-specific gaps
- Redact at the message level
- Work for all tools including Grep, Glob, etc.
- Handle streaming responses

Trade-offs: More complex, requires HTTPS handling, adds latency to API calls.

See `docs/api-proxy-approach.md` for analysis.
