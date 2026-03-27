"""Tests for shadow file management."""

from pathlib import Path

from rdx.core.mappings import MappingCache
from rdx.core.models import Rule
from rdx.core.redactor import Redactor
from rdx.hooks.shadow import clean_shadows, create_shadow, get_shadow_path


def _make_redactor(rules: list[Rule] | None = None, cache: MappingCache | None = None) -> Redactor:
    if cache is None:
        cache = MappingCache()
    if rules is None:
        rules = [
            Rule(
                id="test-secret",
                pattern=r"SECRET_VALUE_\w+",
                category="KEY",
                description="Test secret pattern",
            )
        ]
    return Redactor(rules, cache)


class TestGetShadowPath:
    def test_deterministic(self, tmp_path: Path) -> None:
        """Same input always produces the same shadow path."""
        p1 = get_shadow_path("/foo/bar.txt", tmp_path)
        p2 = get_shadow_path("/foo/bar.txt", tmp_path)
        assert p1 == p2

    def test_different_inputs_different_paths(self, tmp_path: Path) -> None:
        p1 = get_shadow_path("/foo/bar.txt", tmp_path)
        p2 = get_shadow_path("/foo/baz.txt", tmp_path)
        assert p1 != p2

    def test_path_under_shadow_dir(self, tmp_path: Path) -> None:
        p = get_shadow_path("/foo/bar.txt", tmp_path)
        assert ".claude/rdx_shadow" in str(p)
        assert p.suffix == ".txt"


class TestCreateShadow:
    def test_creates_shadow_with_redacted_content(self, tmp_path: Path) -> None:
        """File with a secret produces a shadow with the secret replaced."""
        original = tmp_path / "config.txt"
        original.write_text("key = SECRET_VALUE_ABC123")

        redactor = _make_redactor()
        shadow = create_shadow(str(original), tmp_path, redactor)

        assert shadow is not None
        assert shadow.exists()
        content = shadow.read_text()
        assert "SECRET_VALUE_ABC123" not in content
        assert "__RDX_" in content

    def test_returns_none_for_clean_file(self, tmp_path: Path) -> None:
        """File without secrets returns None — no shadow needed."""
        clean = tmp_path / "clean.txt"
        clean.write_text("nothing sensitive here")

        redactor = _make_redactor()
        shadow = create_shadow(str(clean), tmp_path, redactor)
        assert shadow is None

    def test_returns_none_for_nonexistent_file(self, tmp_path: Path) -> None:
        redactor = _make_redactor()
        shadow = create_shadow("/nonexistent/file.txt", tmp_path, redactor)
        assert shadow is None

    def test_returns_none_for_binary_file(self, tmp_path: Path) -> None:
        """Binary file that can't be decoded returns None."""
        binary = tmp_path / "data.bin"
        binary.write_bytes(b"\x80\x81\x82\x83" * 100)

        redactor = _make_redactor()
        shadow = create_shadow(str(binary), tmp_path, redactor)
        assert shadow is None


class TestCleanShadows:
    def test_removes_shadow_files(self, tmp_path: Path) -> None:
        shadow_dir = tmp_path / ".claude" / "rdx_shadow"
        shadow_dir.mkdir(parents=True)
        (shadow_dir / "abc123.txt").write_text("redacted")
        (shadow_dir / "def456.txt").write_text("redacted")

        count = clean_shadows(tmp_path)
        assert count == 2
        assert not list(shadow_dir.glob("*.txt"))

    def test_returns_zero_when_no_shadows(self, tmp_path: Path) -> None:
        count = clean_shadows(tmp_path)
        assert count == 0
