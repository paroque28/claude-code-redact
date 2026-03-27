"""Minimal ASGI proxy server that sits between Claude Code and the Anthropic API."""

from __future__ import annotations

import json
import logging
import os
import sys

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

logger = logging.getLogger(__name__)

# Headers to forward from client to upstream.
_FORWARD_HEADERS = frozenset({
    "authorization",
    "anthropic-version",
    "anthropic-beta",
    "content-type",
})

DEFAULT_UPSTREAM = "https://api.anthropic.com"
DEFAULT_TIMEOUT = 300.0


def _get_upstream_url() -> str:
    return os.environ.get("RDX_UPSTREAM_URL", DEFAULT_UPSTREAM)


def _get_timeout() -> float:
    """Get timeout from RDX_TIMEOUT env var (seconds), default 300."""
    try:
        return float(os.environ.get("RDX_TIMEOUT", str(DEFAULT_TIMEOUT)))
    except (ValueError, TypeError):
        return DEFAULT_TIMEOUT


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
    timeout = _get_timeout()

    body = await request.json()

    try:
        redacted_body = redact_request_body(body, redactor)
    except Exception:
        logger.exception("Redaction failed on request body — passing through unredacted")
        redacted_body = body

    is_streaming = redacted_body.get("stream", False)

    # Build upstream headers
    headers = {}
    for key in _FORWARD_HEADERS:
        value = request.headers.get(key)
        if value is not None:
            headers[key] = value

    upstream_url = _get_upstream_url() + "/v1/messages"

    async with httpx.AsyncClient(timeout=timeout) as client:
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
                try:
                    error_json = json.loads(error_body)
                except json.JSONDecodeError:
                    error_json = {"error": error_body.decode(errors="replace")}
                return JSONResponse(
                    error_json,
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
            )

            if upstream_resp.status_code != 200:
                try:
                    error_json = upstream_resp.json()
                except (json.JSONDecodeError, ValueError):
                    error_json = {"error": upstream_resp.text}
                return JSONResponse(
                    error_json,
                    status_code=upstream_resp.status_code,
                )

            response_body = upstream_resp.json()
            try:
                unredacted_body = unredact_response_body(response_body, unredactor)
            except Exception:
                logger.exception("Un-redaction failed on response — passing through as-is")
                unredacted_body = response_body
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
    timeout = _get_timeout()

    async with httpx.AsyncClient(timeout=timeout) as client:
        upstream_resp = await client.post(
            upstream_url,
            headers=headers,
            content=body,
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
