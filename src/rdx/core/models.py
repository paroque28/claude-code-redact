"""Data models for the rdx redaction proxy."""

from dataclasses import dataclass, field
from typing import Literal

Action = Literal["redact", "block", "warn"]
Category = Literal["NAME", "EMAIL", "KEY", "IP", "HOST", "PROJECT", "PATH", "CUSTOM"]
Target = Literal["llm", "tool", "both"]


@dataclass
class Rule:
    """A redaction rule defining a pattern, action, and category."""

    id: str
    pattern: str | None = None  # Regex or fixed string
    path_pattern: str | None = None  # File path glob
    is_regex: bool = True
    hashed: bool = False
    hash_extractor: str | None = None
    action: Action = "redact"
    replacement: str | None = None  # Format-preserving: "peter". None = auto-token
    category: Category = "CUSTOM"
    target: Target = "both"
    tool: str | None = None  # Filter to specific tool
    description: str = ""


@dataclass
class Match:
    """A match found by scanning text against rules."""

    rule: Rule
    start: int
    end: int
    text: str  # The matched original text
    entity_type: str | None = None  # From Presidio: "PERSON", "EMAIL_ADDRESS", etc.
    score: float = 1.0  # Detection confidence
    segment_hash: str | None = None  # For hashed matching


@dataclass
class Redaction:
    """A single redaction mapping from original text to replacement."""

    original: str
    replacement: str  # "peter" or "__RDX_NAME_a1b2c3d4__"
    rule_id: str
    category: Category


@dataclass
class ScanResult:
    """Result of scanning text for matches."""

    matches: list[Match] = field(default_factory=list)
    block_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    redacted_text: str | None = None


@dataclass
class AuditEntry:
    """An entry in the audit log."""

    timestamp: str
    event: str  # "redact", "unredact", "block", "warn"
    direction: str  # "outgoing", "incoming", "tool"
    tool: str | None = None
    rule_ids: list[str] = field(default_factory=list)
    count: int = 0  # Number of redactions/unredactions
    detail: str = ""  # Human-readable summary
