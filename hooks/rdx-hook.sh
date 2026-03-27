#!/usr/bin/env bash
set -euo pipefail

# Thin shell hook for Claude Code — handles Bash rewriting in the fast path,
# delegates everything else to the Python hook handler.

# Read JSON from stdin
INPUT=$(cat)

# Extract tool name
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

# Only handle Bash via shell hook; everything else goes to Python
if [ "$TOOL" != "Bash" ]; then
    rdx hook <<< "$INPUT"
    exit $?
fi

CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0

# Try rewrite
REWRITTEN=$(rdx rewrite "$CMD" 2>/dev/null) || exit 0

# If same as original, no rewrite needed
[ "$REWRITTEN" = "$CMD" ] && exit 0

# Build updatedInput response
jq -n --arg cmd "$REWRITTEN" '{
    hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: "rdx command rewrite",
        updatedInput: { command: $cmd }
    }
}'
