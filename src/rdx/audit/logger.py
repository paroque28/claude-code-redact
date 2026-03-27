"""JSONL audit log for redaction events.

Writes structured audit entries to ``.claude/rdx_audit.jsonl`` in the project
directory.  Each line is a self-contained JSON object matching
:class:`~rdx.core.models.AuditEntry`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rdx.core.models import AuditEntry

AUDIT_FILE = ".claude/rdx_audit.jsonl"


class AuditLogger:
    """Append-only JSONL audit logger."""

    def __init__(self, project_dir: Path | None = None) -> None:
        self.project_dir = project_dir or Path.cwd()
        self.path = self.project_dir / AUDIT_FILE

    def log(
        self,
        event: str,
        direction: str,
        *,
        tool: str | None = None,
        rule_ids: list[str] | None = None,
        count: int = 0,
        detail: str = "",
    ) -> AuditEntry:
        """Append an audit entry. Returns the entry written."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event=event,
            direction=direction,
            tool=tool,
            rule_ids=rule_ids or [],
            count=count,
            detail=detail,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(_entry_to_dict(entry)) + "\n")
        return entry

    def get_recent(self, n: int = 50) -> list[AuditEntry]:
        """Return the *n* most recent entries (newest last)."""
        if not self.path.exists():
            return []
        lines = self.path.read_text().strip().splitlines()
        recent = lines[-n:] if len(lines) > n else lines
        return [_dict_to_entry(json.loads(line)) for line in recent]

    def get_stats(self) -> dict[str, int]:
        """Return aggregate counts: total, by event type, by direction."""
        if not self.path.exists():
            return {"total": 0}
        stats: dict[str, int] = {"total": 0}
        for line in self.path.read_text().strip().splitlines():
            if not line:
                continue
            data = json.loads(line)
            stats["total"] += 1
            event = data.get("event", "unknown")
            stats[f"event:{event}"] = stats.get(f"event:{event}", 0) + 1
            direction = data.get("direction", "unknown")
            stats[f"direction:{direction}"] = stats.get(f"direction:{direction}", 0) + 1
            stats["redactions"] = stats.get("redactions", 0) + data.get("count", 0)
        return stats

    def clear(self) -> int:
        """Remove the audit log file. Returns the number of entries removed."""
        if not self.path.exists():
            return 0
        lines = self.path.read_text().strip().splitlines()
        count = len([l for l in lines if l.strip()])
        self.path.unlink()
        return count


def _entry_to_dict(entry: AuditEntry) -> dict:
    """Serialize an AuditEntry to a plain dict for JSON output."""
    d: dict = {
        "timestamp": entry.timestamp,
        "event": entry.event,
        "direction": entry.direction,
    }
    if entry.tool:
        d["tool"] = entry.tool
    if entry.rule_ids:
        d["rule_ids"] = entry.rule_ids
    if entry.count:
        d["count"] = entry.count
    if entry.detail:
        d["detail"] = entry.detail
    return d


def _dict_to_entry(d: dict) -> AuditEntry:
    """Deserialize a dict back to an AuditEntry."""
    return AuditEntry(
        timestamp=d.get("timestamp", ""),
        event=d.get("event", ""),
        direction=d.get("direction", ""),
        tool=d.get("tool"),
        rule_ids=d.get("rule_ids", []),
        count=d.get("count", 0),
        detail=d.get("detail", ""),
    )
