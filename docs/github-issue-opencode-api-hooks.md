# Feature Request: Pre/Post API call hooks for secret redaction

**Project**: opencode-ai/opencode

## Problem

When using OpenCode, all code, file contents, command outputs, and user prompts are sent to external LLM API servers (Anthropic, OpenAI, Gemini, etc.). This includes secrets, project names, company names, and NDA-protected material.

Organizations need the ability to **redact sensitive data before it leaves the machine** and un-redact AI responses before they reach local tools.

### Current plugin limitations

The existing plugin system provides `tool.execute.before` which intercepts tool calls. But this operates at the **tool level**, not the **API level**. There is no way to:

- Redact file contents read by tools before they're sent in the API request
- Redact user prompts before they reach the LLM provider
- Un-redact model responses before tool calls execute
- Cover all providers uniformly (Anthropic, OpenAI, Gemini, Bedrock, etc.)

## Proposed Solution

Add two hook points in the `Provider` interface, firing before/after the actual API call:

### Where in the code

The perfect interception point already exists in `internal/llm/provider/provider.go`:

```go
func (p *baseProvider[C]) SendMessages(ctx context.Context, messages []message.Message, tools []tools.BaseTool) (*ProviderResponse, error) {
    messages = p.cleanMessages(messages)
    // ← NEW: fire PreApiCall hooks here, allow modifying messages
    return p.client.send(ctx, messages, tools)
    // ← NEW: fire PostApiCall hooks here, allow modifying response
}

func (p *baseProvider[C]) StreamResponse(ctx context.Context, messages []message.Message, tools []tools.BaseTool) <-chan ProviderEvent {
    messages = p.cleanMessages(messages)
    // ← NEW: fire PreApiCall hooks here, allow modifying messages
    return p.client.stream(ctx, messages, tools)
    // ← NEW: fire PostApiCall hooks on each event, allow modifying content
}
```

### Implementation approach

A simple Go decorator pattern:

```go
// RedactingProvider wraps any Provider and applies redaction
type RedactingProvider struct {
    inner    Provider
    redactor Redactor  // interface with Redact(text) and Unredact(text)
}

func (r *RedactingProvider) SendMessages(ctx context.Context, messages []message.Message, tools []tools.BaseTool) (*ProviderResponse, error) {
    // Redact all message content before sending to API
    redactedMessages := r.redactMessages(messages)

    response, err := r.inner.SendMessages(ctx, redactedMessages, tools)
    if err != nil {
        return nil, err
    }

    // Un-redact response content before returning to agent
    r.unredactResponse(response)
    return response, nil
}
```

This approach:
- Works with **all providers** (Anthropic, OpenAI, Gemini, Bedrock, etc.) because it wraps the `Provider` interface
- Requires **minimal code changes** — just wrap the provider at creation time in `NewProvider()` or `agent.go`
- Is **testable** — the `Redactor` interface can be mocked
- Is **opt-in** — only activates when redaction rules are configured

### Plugin hook alternative

If a Go-level change is not preferred, expose these as plugin hooks:

```typescript
// Plugin API
api.on("api.request.before", (event: { messages: Message[] }) => {
    // Modify messages before they're sent to the LLM provider
    return { messages: redactMessages(event.messages) };
});

api.on("api.response.after", (event: { response: ProviderResponse }) => {
    // Modify response before it reaches the agent
    return { response: unredactResponse(event.response) };
});
```

## How it works end-to-end

```
1. User: "Check config.py for the AcmeCorp API key"
2. Agent reads file → gets content with real secret
3. Agent builds messages array with tool_result containing the secret
4. ✨ PreApiCall fires → redacts "sk-secret123" → "__REDACTED_KEY_c3d4__"
5. Redacted messages sent to LLM provider (Anthropic/OpenAI/etc.)
6. LLM responds using redacted tokens
7. ✨ PostApiCall fires → un-redacts tokens back to real values
8. Agent processes response with real values
9. Secret never left the machine
```

## Why this matters

- **Enterprise adoption**: Many organizations cannot send proprietary code to external APIs without redaction
- **GDPR/PII compliance**: Employee names, emails, internal data must be scrubbed
- **NDA protection**: Project names, client names, business logic
- **Provider-agnostic**: One redaction layer covers all LLM providers
- **Zero gaps**: Unlike tool-level hooks, API-level hooks cover everything

## Scope

This is a minimal change:
- Add 2 hook points in `provider.go` (or expose via plugin API)
- The actual redaction logic would live in external tools/plugins — OpenCode just needs to provide the interception point
