"""Request/response body processing for the Anthropic Messages API."""

from __future__ import annotations

import copy
from typing import Any

from rdx.core.redactor import Redactor
from rdx.core.unredactor import Unredactor


def _redact_text(text: str, redactor: Redactor) -> str:
    """Redact a single text string, returning the redacted version."""
    result = redactor.redact(text)
    return result.redacted_text if result.redacted_text is not None else text


def _redact_content_blocks(blocks: list[dict[str, Any]], redactor: Redactor) -> list[dict[str, Any]]:
    """Redact a list of content blocks in-place style (on a deep copy)."""
    out: list[dict[str, Any]] = []
    for block in blocks:
        block = copy.deepcopy(block)
        block_type = block.get("type")
        if block_type == "text":
            block["text"] = _redact_text(block["text"], redactor)
        elif block_type == "tool_result":
            content = block.get("content")
            if isinstance(content, str):
                block["content"] = _redact_text(content, redactor)
            elif isinstance(content, list):
                block["content"] = _redact_content_blocks(content, redactor)
        elif block_type == "tool_use":
            if "input" in block:
                block["input"] = _redact_value(block["input"], redactor)
        out.append(block)
    return out


def _redact_value(value: Any, redactor: Redactor) -> Any:
    """Recursively redact string values in dicts/lists."""
    if isinstance(value, str):
        return _redact_text(value, redactor)
    if isinstance(value, dict):
        return {k: _redact_value(v, redactor) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, redactor) for item in value]
    return value


def redact_request_body(body: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    """Walk the Messages API request body and redact all text content."""
    body = copy.deepcopy(body)

    # Redact system message
    system = body.get("system")
    if isinstance(system, str):
        body["system"] = _redact_text(system, redactor)
    elif isinstance(system, list):
        body["system"] = _redact_content_blocks(system, redactor)

    # Redact messages
    messages = body.get("messages", [])
    for i, msg in enumerate(messages):
        content = msg.get("content")
        if isinstance(content, str):
            messages[i]["content"] = _redact_text(content, redactor)
        elif isinstance(content, list):
            messages[i]["content"] = _redact_content_blocks(content, redactor)

    return body


def _unredact_value(value: Any, unredactor: Unredactor) -> Any:
    """Recursively un-redact string values in dicts/lists."""
    if isinstance(value, str):
        return unredactor.unredact(value)
    if isinstance(value, dict):
        return {k: _unredact_value(v, unredactor) for k, v in value.items()}
    if isinstance(value, list):
        return [_unredact_value(item, unredactor) for item in value]
    return value


def unredact_response_body(body: dict[str, Any], unredactor: Unredactor) -> dict[str, Any]:
    """Walk the Messages API response body and un-redact all text content."""
    body = copy.deepcopy(body)

    content_blocks = body.get("content", [])
    for i, block in enumerate(content_blocks):
        block_type = block.get("type")
        if block_type == "text":
            content_blocks[i]["text"] = unredactor.unredact(block["text"])
        elif block_type == "tool_use":
            if "input" in block:
                content_blocks[i]["input"] = _unredact_value(block["input"], unredactor)

    return body
