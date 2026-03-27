"""Tests for context-based secret detection."""

from rdx.detect.context import scan_context


class TestPasswordAssignment:
    def test_password_equals_quoted(self) -> None:
        text = 'password = "secret123"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "secret123"

    def test_passwd_colon_quoted(self) -> None:
        text = "passwd: 'my_password_value'"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "my_password_value"

    def test_pwd_assignment(self) -> None:
        text = 'pwd = "hunter2_long"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "hunter2_long"


class TestSecretAssignment:
    def test_token_assignment(self) -> None:
        text = 'token = "abc123xyz789"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "abc123xyz789"

    def test_api_key_assignment(self) -> None:
        text = 'api_key: "my-api-key-value"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "my-api-key-value"

    def test_auth_token_assignment(self) -> None:
        text = 'auth_token = "bearer_token_here"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "bearer_token_here"


class TestEnvExport:
    def test_export_api_key(self) -> None:
        text = 'export API_KEY="abc123def456"'
        matches = scan_context(text)
        assert len(matches) >= 1
        # The captured value may include the trailing quote depending on \S+
        assert "abc123def456" in matches[0].text

    def test_export_secret_token(self) -> None:
        text = "export MY_SECRET_TOKEN=some_long_value_here"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert "some_long_value_here" in matches[0].text

    def test_export_password(self) -> None:
        text = "export DB_PASSWORD=supersecretpwd"
        matches = scan_context(text)
        assert len(matches) >= 1


class TestConnectionString:
    def test_postgres_password(self) -> None:
        text = "postgres://admin:p4ssw0rd_here@db.example.com:5432/mydb"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "p4ssw0rd_here"

    def test_mysql_password(self) -> None:
        text = "mysql://root:secret_pass@localhost/test"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "secret_pass"

    def test_redis_password(self) -> None:
        text = "redis://default:redis_pass@cache.local:6379"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "redis_pass"


class TestHTTPHeaders:
    def test_bearer_token(self) -> None:
        text = "Authorization: Bearer tok123abc456"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "tok123abc456"

    def test_x_api_key_header(self) -> None:
        text = "X-API-Key: my-secret-api-key"
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "my-secret-api-key"


class TestEdgeCases:
    def test_normal_text_returns_empty(self) -> None:
        text = "This is a normal sentence without any secrets."
        matches = scan_context(text)
        assert matches == []

    def test_short_values_skipped(self) -> None:
        # Values shorter than 4 chars should be ignored
        text = 'password = "ab"'
        matches = scan_context(text)
        assert matches == []

    def test_exactly_four_chars_included(self) -> None:
        text = 'password = "abcd"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].text == "abcd"

    def test_match_score(self) -> None:
        text = 'token = "some_value_here"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].score == 0.8

    def test_match_rule_id_encodes_context(self) -> None:
        text = 'password = "secret123"'
        matches = scan_context(text)
        assert len(matches) >= 1
        assert matches[0].rule.id.startswith("context-")

    def test_case_insensitive(self) -> None:
        text = 'PASSWORD = "my_password_123"'
        matches = scan_context(text)
        assert len(matches) >= 1

    def test_start_end_positions(self) -> None:
        text = 'password = "secret123"'
        matches = scan_context(text)
        assert len(matches) >= 1
        m = matches[0]
        assert text[m.start : m.end] == m.text
