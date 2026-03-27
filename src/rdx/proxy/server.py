"""Minimal ASGI proxy server that sits between Claude Code and the Anthropic API."""

from __future__ import annotations

import json
import os

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from rdx.core.mappings import MappingCache
from rdx.core.redactor import Redactor
from rdx.core.rules import load_rules
from rdx.core.unredactor import Unredactor
from rdx.detect.patterns import get_builtin_rules

from .handler import redact_request_body, unredact_response_body
from .stream import unredact_stream

# Headers to forward from client to upstream.
_FORWARD_HEADERS = frozenset({
    "authorization",
    "anthropic-version",
    "anthropic-beta",
    "content-type",
})

DEFAULT_UPSTREAM = "https://api.anthropic.com"


def _get_upstream_url() -> str:
    return os.environ.get("RDX_UPSTREAM_URL", DEFAULT_UPSTREAM)


def _build_rules() -> list:
    """Load user rules and merge with builtins."""
    user_rules = load_rules()
    builtin_rules = get_builtin_rules()
    # User rules first so they take priority in scanning
    seen_ids = {r.id for r in user_rules}
    merged = list(user_rules)
    for r in builtin_rules:
        if r.id not in seen_ids:
            merged.append(r)
    return merged


# Shared mapping cache — lives for the lifetime of the server process.
_cache = MappingCache()


async def health(request: Request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "ok"})


async def proxy_messages(request: Request) -> StreamingResponse | JSONResponse:
    """Proxy POST /v1/messages — redact outgoing, un-redact incoming."""
    rules = _build_rules()
    redactor = Redactor(rules, _cache)
    unredactor = Unredactor(_cache)

    body = await request.json()
    redacted_body = redact_request_body(body, redactor)

    is_streaming = redacted_body.get("stream", False)

    # Build upstream headers
    headers = {}
    for key in _FORWARD_HEADERS:
        value = request.headers.get(key)
        if value is not None:
            headers[key] = value

    upstream_url = _get_upstream_url() + "/v1/messages"

    async with httpx.AsyncClient() as client:
        if is_streaming:
            upstream_resp = await client.send(
                client.build_request(
                    "POST",
                    upstream_url,
                    headers=headers,
                    content=json.dumps(redacted_body).encode(),
                ),
                stream=True,
            )

            if upstream_resp.status_code != 200:
                error_body = await upstream_resp.aread()
                return JSONResponse(
                    json.loads(error_body),
                    status_code=upstream_resp.status_code,
                )

            return StreamingResponse(
                unredact_stream(upstream_resp, unredactor),
                media_type="text/event-stream",
                headers={
                    "cache-control": "no-cache",
                    "connection": "keep-alive",
                },
            )
        else:
            upstream_resp = await client.post(
                upstream_url,
                headers=headers,
                content=json.dumps(redacted_body).encode(),
                timeout=300.0,
            )

            if upstream_resp.status_code != 200:
                return JSONResponse(
                    upstream_resp.json(),
                    status_code=upstream_resp.status_code,
                )

            response_body = upstream_resp.json()
            unredacted_body = unredact_response_body(response_body, unredactor)
            return JSONResponse(unredacted_body)


async def proxy_count_tokens(request: Request) -> JSONResponse:
    """Proxy POST /v1/messages/count_tokens — passthrough, no redaction."""
    headers = {}
    for key in _FORWARD_HEADERS:
        value = request.headers.get(key)
        if value is not None:
            headers[key] = value

    body = await request.body()
    upstream_url = _get_upstream_url() + "/v1/messages/count_tokens"

    async with httpx.AsyncClient() as client:
        upstream_resp = await client.post(
            upstream_url,
            headers=headers,
            content=body,
            timeout=60.0,
        )
        return JSONResponse(
            upstream_resp.json(),
            status_code=upstream_resp.status_code,
        )


app = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Route("/v1/messages", proxy_messages, methods=["POST"]),
        Route("/v1/messages/count_tokens", proxy_count_tokens, methods=["POST"]),
    ],
)
