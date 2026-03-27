"""Shadow file management for Read tool redaction.

When Claude's Read tool requests a file containing secrets, we create a
redacted shadow copy and redirect the Read to the shadow path instead.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from rdx.core.redactor import Redactor

SHADOW_DIR = ".claude/rdx_shadow"


def get_shadow_path(original_path: str, project_dir: Path) -> Path:
    """Return the deterministic shadow file path for *original_path*."""
    h = hashlib.sha256(original_path.encode()).hexdigest()[:16]
    return project_dir / SHADOW_DIR / f"{h}.txt"


def create_shadow(
    original_path: str,
    project_dir: Path,
    redactor: Redactor,
) -> Path | None:
    """Read original file, redact, write shadow.

    Returns the shadow path if redaction was applied, or ``None`` if the file
    is clean, missing, or unreadable.
    """
    p = Path(original_path)
    if not p.exists():
        return None
    try:
        content = p.read_text()
    except (OSError, UnicodeDecodeError):
        return None

    result = redactor.redact(content, target="tool")
    if not result.redacted_text or result.redacted_text == content:
        return None  # No redaction needed

    shadow = get_shadow_path(original_path, project_dir)
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_text(result.redacted_text)
    return shadow


def clean_shadows(project_dir: Path) -> int:
    """Remove all shadow files. Returns count removed."""
    shadow_dir = project_dir / SHADOW_DIR
    if not shadow_dir.exists():
        return 0
    count = 0
    for f in shadow_dir.glob("*.txt"):
        f.unlink()
        count += 1
    return count
