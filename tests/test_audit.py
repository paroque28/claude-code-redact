"""Tests for the audit logger."""

from pathlib import Path

from rdx.audit.logger import AuditLogger


class TestLog:
    def test_creates_file_and_writes_entry(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        entry = logger.log("redact", "outgoing", rule_ids=["aws-key"], count=2)
        assert entry.event == "redact"
        assert entry.direction == "outgoing"
        assert logger.path.exists()

    def test_appends_multiple_entries(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log("redact", "outgoing", count=1)
        logger.log("block", "incoming", tool="Read")
        logger.log("warn", "tool", detail="test warning")
        lines = logger.path.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_entry_has_timestamp(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        entry = logger.log("redact", "outgoing")
        assert entry.timestamp  # non-empty ISO timestamp

    def test_entry_optional_fields(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        entry = logger.log("redact", "outgoing", tool="Bash", detail="testing")
        assert entry.tool == "Bash"
        assert entry.detail == "testing"


class TestGetRecent:
    def test_returns_most_recent(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        for i in range(10):
            logger.log("redact", "outgoing", count=i)
        recent = logger.get_recent(3)
        assert len(recent) == 3
        assert recent[-1].count == 9  # Most recent is last

    def test_returns_all_when_fewer_than_n(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log("redact", "outgoing")
        logger.log("block", "incoming")
        recent = logger.get_recent(50)
        assert len(recent) == 2

    def test_returns_empty_when_no_file(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        assert logger.get_recent() == []


class TestGetStats:
    def test_counts_by_event_and_direction(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log("redact", "outgoing", count=3)
        logger.log("redact", "outgoing", count=2)
        logger.log("block", "incoming", count=1)
        stats = logger.get_stats()
        assert stats["total"] == 3
        assert stats["event:redact"] == 2
        assert stats["event:block"] == 1
        assert stats["direction:outgoing"] == 2
        assert stats["direction:incoming"] == 1
        assert stats["redactions"] == 6

    def test_empty_log_returns_zero_total(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        stats = logger.get_stats()
        assert stats == {"total": 0}


class TestClear:
    def test_removes_file_and_returns_count(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log("redact", "outgoing")
        logger.log("block", "incoming")
        count = logger.clear()
        assert count == 2
        assert not logger.path.exists()

    def test_returns_zero_when_no_file(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        assert logger.clear() == 0
