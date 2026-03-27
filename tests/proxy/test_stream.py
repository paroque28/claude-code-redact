"""Tests for SSE streaming handler."""

import json
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor
from rdx.core.unredactor import Unredactor
from rdx.proxy.stream import TextDeltaBuffer, ToolUseBuffer, unredact_stream


def _setup(secret: str = "sk-ant-abcdefghij") -> tuple[Redactor, Unredactor, MappingCache]:
    cache = MappingCache()
    rules = [
        Rule(
            id="test-key",
            pattern=r"sk-ant-[a-zA-Z0-9\-]{10,}",
            category="KEY",
        ),
    ]
    redactor = Redactor(rules, cache)
    # Populate cache by redacting the secret
    redactor.redact(secret)
    return redactor, Unredactor(cache), cache


def _get_token(cache: MappingCache, original: str) -> str:
    """Get the redaction token for a given original value."""
    reverse = cache.get_reverse_map()
    for replacement, orig in reverse.items():
        if orig == original:
            return replacement
    raise ValueError(f"No token found for {original}")


class TestTextDeltaBuffer:
    def test_plain_text_passthrough(self):
        _, unredactor, _ = _setup()
        buf = TextDeltaBuffer(unredactor)
        assert buf.feed("Hello world") == "Hello world"

    def test_complete_token_in_single_feed(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")
        buf = TextDeltaBuffer(unredactor)
        result = buf.feed(f"Key: {token}")
        assert "sk-ant-abcdefghij" in result
        assert "__RDX_" not in result

    def test_token_split_across_feeds(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")
        buf = TextDeltaBuffer(unredactor)

        # Split the token across two feeds
        mid = len(token) // 2
        part1 = token[:mid]
        part2 = token[mid:]

        result1 = buf.feed(f"Key: {part1}")
        result2 = buf.feed(part2)
        remaining = buf.flush_remaining()

        combined = result1 + result2 + remaining
        assert "sk-ant-abcdefghij" in combined
        assert "__RDX_" not in combined

    def test_partial_prefix_buffered(self):
        _, unredactor, _ = _setup()
        buf = TextDeltaBuffer(unredactor)
        # Feed text ending with partial prefix
        result = buf.feed("hello __RD")
        # Should buffer the partial prefix
        assert "hello " == result or result == "hello "
        # Next feed completes a non-token
        result2 = buf.feed("UMMY text")
        remaining = buf.flush_remaining()
        combined = result + result2 + remaining
        assert "hello __RDUMMY text" == combined

    def test_flush_remaining(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")
        buf = TextDeltaBuffer(unredactor)

        # Feed partial token then flush
        buf.feed(token[:5])
        remaining = buf.flush_remaining()
        # Since it's incomplete it should just pass through
        assert remaining == token[:5]

    def test_multiple_tokens(self):
        cache = MappingCache()
        rules = [
            Rule(id="r1", pattern=r"secret1", is_regex=False, category="KEY"),
            Rule(id="r2", pattern=r"secret2", is_regex=False, category="NAME"),
        ]
        redactor = Redactor(rules, cache)
        redactor.redact("secret1 and secret2")
        unredactor = Unredactor(cache)

        tok1 = _get_token(cache, "secret1")
        tok2 = _get_token(cache, "secret2")

        buf = TextDeltaBuffer(unredactor)
        result = buf.feed(f"{tok1} and {tok2}")
        remaining = buf.flush_remaining()
        combined = result + remaining
        assert "secret1" in combined
        assert "secret2" in combined
        assert "__RDX_" not in combined


class TestToolUseBuffer:
    def test_accumulate_and_flush(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")
        buf = ToolUseBuffer()

        json_str = json.dumps({"key": token})
        # Feed in chunks
        buf.feed(0, json_str[:10])
        buf.feed(0, json_str[10:])

        result = buf.flush(0, unredactor)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["key"] == "sk-ant-abcdefghij"

    def test_flush_unknown_index(self):
        _, unredactor, _ = _setup()
        buf = ToolUseBuffer()
        assert buf.flush(99, unredactor) is None

    def test_malformed_json_fallback(self):
        _, unredactor, _ = _setup()
        buf = ToolUseBuffer()
        buf.feed(0, "not valid json {{{")
        result = buf.flush(0, unredactor)
        assert result is not None
        assert "not valid json" in result


class _FakeResponse:
    """Mock httpx.Response that yields SSE lines."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self.status_code = 200

    async def aiter_lines(self) -> AsyncIterator[str]:
        for line in self._lines:
            yield line


class TestUnredactStream:
    @pytest.mark.asyncio
    async def test_complete_text_delta_event(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")

        lines = [
            "event: content_block_delta",
            f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"Key: {token}"}}}}',
            "event: content_block_stop",
            'data: {"type":"content_block_stop","index":0}',
        ]
        resp = _FakeResponse(lines)
        chunks = []
        async for chunk in unredact_stream(resp, unredactor):
            chunks.append(chunk.decode())

        combined = "".join(chunks)
        assert "sk-ant-abcdefghij" in combined
        assert "__RDX_" not in combined

    @pytest.mark.asyncio
    async def test_passthrough_non_content_events(self):
        _, unredactor, _ = _setup()

        message_start = {
            "type": "message_start",
            "message": {"id": "msg_123", "model": "claude-sonnet-4-20250514"},
        }
        lines = [
            "event: message_start",
            f"data: {json.dumps(message_start)}",
        ]
        resp = _FakeResponse(lines)
        chunks = []
        async for chunk in unredact_stream(resp, unredactor):
            chunks.append(chunk.decode())

        combined = "".join(chunks)
        assert "message_start" in combined
        assert "msg_123" in combined

    @pytest.mark.asyncio
    async def test_text_delta_across_events(self):
        """Token split across multiple text_delta SSE events."""
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")

        mid = len(token) // 2
        part1 = token[:mid]
        part2 = token[mid:]

        lines = [
            "event: content_block_delta",
            f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{part1}"}}}}',
            "event: content_block_delta",
            f'data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{part2}"}}}}',
            "event: content_block_stop",
            'data: {"type":"content_block_stop","index":0}',
        ]
        resp = _FakeResponse(lines)
        chunks = []
        async for chunk in unredact_stream(resp, unredactor):
            chunks.append(chunk.decode())

        combined = "".join(chunks)
        assert "sk-ant-abcdefghij" in combined
        assert "__RDX_" not in combined

    @pytest.mark.asyncio
    async def test_tool_use_input_delta(self):
        _, unredactor, cache = _setup()
        token = _get_token(cache, "sk-ant-abcdefghij")
        input_json = json.dumps({"file": "config.txt", "key": token})

        lines = [
            "event: content_block_delta",
            f'data: {{"type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":"{input_json[:20]}"}}}}',
            "event: content_block_delta",
            f'data: {{"type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":"{input_json[20:]}"}}}}',
            "event: content_block_stop",
            'data: {"type":"content_block_stop","index":1}',
        ]
        resp = _FakeResponse(lines)
        chunks = []
        async for chunk in unredact_stream(resp, unredactor):
            chunks.append(chunk.decode())

        # The input_json_delta events are passed through as-is
        # (un-redaction happens at block stop for tool use internally)
        combined = "".join(chunks)
        assert "content_block_delta" in combined

    @pytest.mark.asyncio
    async def test_ping_passthrough(self):
        _, unredactor, _ = _setup()
        lines = [
            "event: ping",
            'data: {"type":"ping"}',
        ]
        resp = _FakeResponse(lines)
        chunks = []
        async for chunk in unredact_stream(resp, unredactor):
            chunks.append(chunk.decode())

        combined = "".join(chunks)
        assert "ping" in combined
