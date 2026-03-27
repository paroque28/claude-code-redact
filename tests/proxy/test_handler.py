"""Tests for proxy request/response body processing."""

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor
from rdx.core.unredactor import Unredactor
from rdx.proxy.handler import redact_request_body, unredact_response_body


def _make_redactor(rules: list[Rule] | None = None) -> tuple[Redactor, Unredactor, MappingCache]:
    cache = MappingCache()
    if rules is None:
        rules = [
            Rule(
                id="test-secret",
                pattern=r"sk-ant-[a-zA-Z0-9\-]{10,}",
                category="KEY",
                description="Test API key",
            ),
            Rule(
                id="test-name",
                pattern=r"John Doe",
                is_regex=False,
                category="NAME",
                description="Test name",
            ),
        ]
    redactor = Redactor(rules, cache)
    unredactor = Unredactor(cache)
    return redactor, unredactor, cache


class TestRedactRequestBody:
    def test_simple_text_message(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {"role": "user", "content": "My key is sk-ant-abcdefghij"}
            ],
        }
        result = redact_request_body(body, redactor)
        assert "sk-ant-abcdefghij" not in result["messages"][0]["content"]
        assert "__RDX_KEY_" in result["messages"][0]["content"]
        # Original body should not be mutated
        assert "sk-ant-abcdefghij" in body["messages"][0]["content"]

    def test_content_blocks_with_text(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Secret: sk-ant-abcdefghij"},
                    ],
                }
            ],
        }
        result = redact_request_body(body, redactor)
        assert "sk-ant-abcdefghij" not in result["messages"][0]["content"][0]["text"]
        assert "__RDX_KEY_" in result["messages"][0]["content"][0]["text"]

    def test_tool_result_string_content(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_123",
                            "content": "Found key: sk-ant-abcdefghij",
                        },
                    ],
                }
            ],
        }
        result = redact_request_body(body, redactor)
        assert "sk-ant-abcdefghij" not in result["messages"][0]["content"][0]["content"]

    def test_tool_result_block_content(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_123",
                            "content": [
                                {"type": "text", "text": "Key: sk-ant-abcdefghij"},
                            ],
                        },
                    ],
                }
            ],
        }
        result = redact_request_body(body, redactor)
        nested = result["messages"][0]["content"][0]["content"][0]
        assert "sk-ant-abcdefghij" not in nested["text"]

    def test_tool_use_input_redaction(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_456",
                            "name": "write_file",
                            "input": {
                                "path": "/tmp/config",
                                "content": "api_key=sk-ant-abcdefghij",
                            },
                        },
                    ],
                }
            ],
        }
        result = redact_request_body(body, redactor)
        tool_input = result["messages"][0]["content"][0]["input"]
        assert "sk-ant-abcdefghij" not in tool_input["content"]

    def test_system_message_string(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "system": "You are helping John Doe with their code.",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        result = redact_request_body(body, redactor)
        assert "John Doe" not in result["system"]
        assert "__RDX_NAME_" in result["system"]

    def test_system_message_blocks(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "system": [
                {"type": "text", "text": "User is John Doe."},
            ],
            "messages": [{"role": "user", "content": "Hello"}],
        }
        result = redact_request_body(body, redactor)
        assert "John Doe" not in result["system"][0]["text"]

    def test_mixed_content_blocks(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Here's my key: sk-ant-abcdefghij"},
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_789",
                            "content": "Name is John Doe",
                        },
                    ],
                }
            ],
        }
        result = redact_request_body(body, redactor)
        assert "sk-ant-abcdefghij" not in result["messages"][0]["content"][0]["text"]
        assert "John Doe" not in result["messages"][0]["content"][1]["content"]

    def test_no_secrets_passthrough(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {"role": "user", "content": "Hello, how are you?"}
            ],
        }
        result = redact_request_body(body, redactor)
        assert result["messages"][0]["content"] == "Hello, how are you?"

    def test_preserves_model_and_other_fields(self):
        redactor, _, _ = _make_redactor()
        body = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "temperature": 0.7,
            "messages": [{"role": "user", "content": "hi"}],
        }
        result = redact_request_body(body, redactor)
        assert result["model"] == "claude-sonnet-4-20250514"
        assert result["max_tokens"] == 1024
        assert result["temperature"] == 0.7


class TestUnredactResponseBody:
    def test_text_content(self):
        redactor, unredactor, _ = _make_redactor()
        # First redact to populate the cache
        req = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "My key is sk-ant-abcdefghij"}],
        }
        redacted = redact_request_body(req, redactor)
        token = redacted["messages"][0]["content"].split("My key is ")[1]

        # Now simulate a response that echoes the token
        response = {
            "content": [
                {"type": "text", "text": f"I see your key is {token}"},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 20},
        }
        result = unredact_response_body(response, unredactor)
        assert "sk-ant-abcdefghij" in result["content"][0]["text"]
        assert token not in result["content"][0]["text"]

    def test_tool_use_in_response(self):
        redactor, unredactor, _ = _make_redactor()
        req = {
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "My name is John Doe"}],
        }
        redacted = redact_request_body(req, redactor)
        # Find the token used for "John Doe"
        redacted_content = redacted["messages"][0]["content"]
        token = redacted_content.replace("My name is ", "")

        response = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "tu_001",
                    "name": "grep",
                    "input": {"query": token, "path": "/home/user"},
                },
            ],
        }
        result = unredact_response_body(response, unredactor)
        assert result["content"][0]["input"]["query"] == "John Doe"

    def test_round_trip(self):
        """Redact a request body, then un-redact a response that echoes it."""
        redactor, unredactor, _ = _make_redactor()
        secret = "sk-ant-abcdefghij"
        name = "John Doe"

        req = {
            "model": "claude-sonnet-4-20250514",
            "system": f"Helping {name}",
            "messages": [
                {"role": "user", "content": f"Key: {secret}, name: {name}"},
            ],
        }
        redacted_req = redact_request_body(req, redactor)
        # Secrets should be gone
        assert secret not in str(redacted_req)
        assert name not in str(redacted_req)

        # Simulate response echoing the tokens
        response = {
            "content": [
                {
                    "type": "text",
                    "text": redacted_req["messages"][0]["content"],
                },
            ],
        }
        result = unredact_response_body(response, unredactor)
        assert secret in result["content"][0]["text"]
        assert name in result["content"][0]["text"]

    def test_preserves_usage(self):
        _, unredactor, _ = _make_redactor()
        response = {
            "content": [{"type": "text", "text": "Hello"}],
            "usage": {"input_tokens": 42, "output_tokens": 7},
        }
        result = unredact_response_body(response, unredactor)
        assert result["usage"] == {"input_tokens": 42, "output_tokens": 7}

    def test_no_mutation_of_original(self):
        _, unredactor, _ = _make_redactor()
        response = {
            "content": [{"type": "text", "text": "Some text"}],
        }
        original_text = response["content"][0]["text"]
        unredact_response_body(response, unredactor)
        assert response["content"][0]["text"] == original_text
