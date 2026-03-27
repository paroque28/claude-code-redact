#!/usr/bin/env python3
"""Minimal test proxy to verify rdx redaction with a real Claude Code session.

Usage:
    # Terminal 1: start proxy
    cd /home/pablorod/code/redact/claude-code-redact
    uv run python scripts/test_proxy.py

    # Terminal 2: run Claude Code
    ANTHROPIC_BASE_URL=http://localhost:8642 claude

    # Create .redaction_rules in your test project first.
"""

import json
import os
import sys
import copy
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor
from rdx.core.rules import load_rules
from rdx.core.unredactor import Unredactor
from rdx.detect.patterns import get_builtin_rules

UPSTREAM = os.environ.get("RDX_UPSTREAM_URL", "https://api.anthropic.com")
PORT = int(os.environ.get("RDX_PORT", "8642"))
VERBOSE = os.environ.get("RDX_VERBOSE", "0") == "1"
SHOW_VALUES = os.environ.get("RDX_SHOW_VALUES", "0") == "1"

# Shared state
cache = MappingCache()


def get_redactor() -> Redactor:
    rules = load_rules() + get_builtin_rules()
    return Redactor(rules, cache)


def get_unredactor() -> Unredactor:
    return Unredactor(cache)


def redact_text_recursive(obj: any, redactor: Redactor) -> any:
    """Recursively walk a JSON structure and redact all string values."""
    if isinstance(obj, str):
        result = redactor.redact(obj)
        return result.redacted_text if result.redacted_text else obj
    if isinstance(obj, list):
        return [redact_text_recursive(item, redactor) for item in obj]
    if isinstance(obj, dict):
        return {k: redact_text_recursive(v, redactor) for k, v in obj.items()}
    return obj


def unredact_text_recursive(obj: any, unredactor: Unredactor) -> any:
    """Recursively walk a JSON structure and un-redact all string values."""
    if isinstance(obj, str):
        return unredactor.unredact(obj)
    if isinstance(obj, list):
        return [unredact_text_recursive(item, unredactor) for item in obj]
    if isinstance(obj, dict):
        return {k: unredact_text_recursive(v, unredactor) for k, v in obj.items()}
    return obj


FORWARD_HEADERS = {
    "authorization", "anthropic-version", "anthropic-beta",
    "content-type", "x-api-key", "accept",
}


async def proxy_messages(request: Request) -> Response:
    redactor = get_redactor()
    unredactor = get_unredactor()

    # Read and redact request body
    body = await request.json()
    redacted_body = redact_text_recursive(copy.deepcopy(body), redactor)

    # Log redaction stats
    stats = cache.stats()
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"[rdx] → Outgoing request | {stats['mappings']} active mappings", file=sys.stderr)

    if VERBOSE:
        # Show all redactions applied in this request
        all_redactions = cache.get_all_redactions()
        new_in_request = [r for r in all_redactions]
        if new_in_request:
            print(f"[rdx]   Redactions applied:", file=sys.stderr)
            for r in new_in_request:
                if SHOW_VALUES:
                    print(f"[rdx]     {r.category:8s} {r.original[:40]:40s} → {r.replacement[:30]}", file=sys.stderr)
                else:
                    print(f"[rdx]     {r.category:8s} [{r.rule_id}] ({len(r.original)} chars) → {r.replacement[:30]}", file=sys.stderr)

    # Forward headers
    headers = {}
    for key, value in request.headers.items():
        if key.lower() in FORWARD_HEADERS:
            headers[key] = value

    # Check if streaming
    is_stream = body.get("stream", False)

    if is_stream:
        # Streaming mode — pipe through with un-redaction
        async def stream_generator():
            async with httpx.AsyncClient(timeout=300.0) as client:
                async with client.stream(
                    "POST",
                    f"{UPSTREAM}/v1/messages",
                    json=redacted_body,
                    headers=headers,
                ) as response:
                    buffer = ""
                    async for line in response.aiter_lines():
                        if not line:
                            yield "\n"
                            continue

                        # SSE format: "event: xxx" or "data: {json}"
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "[DONE]":
                                yield f"{line}\n"
                                continue
                            try:
                                event_data = json.loads(data_str)
                                # Un-redact text deltas
                                if event_data.get("type") == "content_block_delta":
                                    delta = event_data.get("delta", {})
                                    if delta.get("type") == "text_delta" and "text" in delta:
                                        # Buffer for potential __RDX_ tokens
                                        buffer += delta["text"]
                                        # Check if buffer contains a complete token or no token start
                                        if "__RDX_" not in buffer or buffer.count("__") >= 2:
                                            unredacted = unredactor.unredact(buffer)
                                            delta["text"] = unredacted
                                            buffer = ""
                                            yield f"data: {json.dumps(event_data)}\n"
                                            continue
                                        else:
                                            # Still buffering, don't yield yet
                                            continue
                                    elif delta.get("type") == "input_json_delta" and "partial_json" in delta:
                                        buffer += delta["partial_json"]
                                        continue
                                elif event_data.get("type") == "content_block_stop":
                                    # Flush any remaining buffer
                                    if buffer:
                                        # Try to un-redact whatever we have
                                        unredacted = unredactor.unredact(buffer)
                                        # Re-emit as a text delta before the stop
                                        flush_event = {
                                            "type": "content_block_delta",
                                            "index": event_data.get("index", 0),
                                            "delta": {"type": "text_delta", "text": unredacted},
                                        }
                                        yield f"data: {json.dumps(flush_event)}\n"
                                        buffer = ""

                                # Un-redact tool_use inputs at block stop
                                unredacted_event = unredact_text_recursive(event_data, unredactor)
                                yield f"data: {json.dumps(unredacted_event)}\n"
                            except json.JSONDecodeError:
                                yield f"{line}\n"
                        else:
                            yield f"{line}\n"

        if VERBOSE:
            reverse = cache.get_reverse_map()
            unredact_count = sum(1 for r in reverse if any(r in str(v) for v in [r]))
            print(f"[rdx] ← Streaming response | {len(reverse)} values available for un-redaction", file=sys.stderr)
        else:
            print(f"[rdx] ← Streaming response", file=sys.stderr)
        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "connection": "keep-alive"},
        )
    else:
        # Non-streaming — simple buffer mode
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{UPSTREAM}/v1/messages",
                json=redacted_body,
                headers=headers,
            )

        response_body = response.json()
        unredacted_body = unredact_text_recursive(response_body, unredactor)

        print(f"[rdx] ← Response un-redacted", file=sys.stderr)
        return JSONResponse(unredacted_body, status_code=response.status_code)


async def health(request: Request) -> JSONResponse:
    stats = cache.stats()
    return JSONResponse({"status": "ok", **stats})


async def passthrough(request: Request) -> Response:
    """Forward request without redaction."""
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}

    async with httpx.AsyncClient(timeout=300.0) as client:
        response = await client.request(
            request.method,
            f"{UPSTREAM}{request.url.path}",
            content=body,
            headers=headers,
        )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )


app = Starlette(
    routes=[
        Route("/v1/messages", proxy_messages, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
        Route("/{path:path}", passthrough, methods=["GET", "POST", "PUT", "DELETE"]),
    ],
)

if __name__ == "__main__":
    print(f"[rdx] Starting redaction proxy on http://localhost:{PORT}", file=sys.stderr)
    print(f"[rdx] Upstream: {UPSTREAM}", file=sys.stderr)
    print(f"[rdx] Rules loaded from: .redaction_rules", file=sys.stderr)
    rules = load_rules() + get_builtin_rules()
    user_rules = [r for r in rules if r.replacement]
    print(f"[rdx] {len(rules)} rules ({len(user_rules)} format-preserving)", file=sys.stderr)
    print(f"[rdx] Verbose: {'ON' if VERBOSE else 'OFF (set RDX_VERBOSE=1)'}", file=sys.stderr)
    print(f"[rdx] Show values: {'ON (UNSAFE)' if SHOW_VALUES else 'OFF (set RDX_SHOW_VALUES=1)'}", file=sys.stderr)
    print(f"[rdx]", file=sys.stderr)
    print(f"[rdx] To use: ANTHROPIC_BASE_URL=http://localhost:{PORT} claude", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
