# Platform Comparison: Claude Code vs OpenCode vs OpenClaw

Research conducted 2026-03-27 based on RTK plugin code analysis.

## Overview

| Feature | Claude Code | OpenCode | OpenClaw |
|---------|-------------|----------|----------|
| Language | TypeScript (Node) | TypeScript (Bun) | TypeScript (Node) |
| Hook system | Shell commands (JSON stdin/stdout) | TypeScript plugin exports | TypeScript plugin with event API |
| Plugin config | `settings.json` | Plugin export | `openclaw.json` + `openclaw.plugin.json` |
| Open source | No (npm package) | Yes (`@opencode-ai/plugin`) | Yes |

## Hook Capabilities

### Modify Tool Input Before Execution

| Platform | Hook Name | Mechanism |
|----------|-----------|-----------|
| Claude Code | `PreToolUse` | Return JSON with `updatedInput` |
| OpenCode | `tool.execute.before` | Mutate `args` object directly |
| OpenClaw | `before_tool_call` | Return `{ params: { ...modified } }` |

All three support modifying tool input. Implementation style differs.

### Modify Tool Output After Execution

| Platform | Hook Name | Can Modify? |
|----------|-----------|-------------|
| Claude Code | `PostToolUse` | **No** (block only, MCP exception) |
| OpenCode | Not observed | **Unknown** (no `tool.execute.after` in RTK plugin) |
| OpenClaw | Not observed | **Unknown** (no `after_tool_call` in RTK plugin) |

**Critical finding**: None of the three platforms demonstrate output modification capability. The proxy approach (wrapping commands so output is pre-filtered) is the only viable strategy on ALL platforms.

### Modify User Prompts

| Platform | Capability |
|----------|-----------|
| Claude Code | `additionalContext` only (cannot modify text) |
| OpenCode | Unknown |
| OpenClaw | Unknown |

## RTK Plugin Code Analysis

### OpenCode Plugin (`hooks/opencode-rtk.ts`)

```typescript
import type { Plugin } from "@opencode-ai/plugin"

export const RtkOpenCodePlugin: Plugin = async ({ $ }) => {
  return {
    "tool.execute.before": async (input, output) => {
      // Mutates output.args.command directly
      (args as Record<string, unknown>).command = rewritten
    },
  }
}
```

- Uses Bun shell (`$`) for subprocess execution
- Mutates args in-place (no return value needed)
- Only hooks `bash`/`shell` tools

### OpenClaw Plugin (`openclaw/index.ts`)

```typescript
export default function register(api: any) {
  api.on("before_tool_call", (event) => {
    return { params: { ...event.params, command: rewritten } };
  }, { priority: 10 });
}
```

- Event subscription pattern (`api.on()`)
- Returns modified params (immutable pattern)
- Priority system for hook ordering
- Config via `api.config`

## Conclusion

**Switching platforms does NOT unlock output modification.** The rdx proxy approach works identically on all three platforms:

1. Hook intercepts tool input (before execution)
2. Wraps command with `rdx` proxy
3. Proxy executes real command, redacts output
4. Redacted output enters LLM context

The only difference is the plugin/hook boilerplate code. The core architecture is platform-agnostic.

## Recommendation

Stay with Claude Code for development. The `rdx` proxy pattern is the best approach regardless of platform. If we later want to support OpenCode/OpenClaw, the core `rdx` binary stays the same — only the thin hook adapter changes.
