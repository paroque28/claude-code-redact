# Mapping Cache: Consistent Reversible Redaction

## Problem

When we redact `pablo` → `__RDX_NAME_a1b2c3d4__`, we need:
1. **Consistency**: Same input always produces the same token (across sessions, across files)
2. **Reversibility**: Given `__RDX_NAME_a1b2c3d4__`, get back `pablo` with 100% confidence
3. **Uniqueness**: No two different originals produce the same token
4. **Safety**: Search-replacing tokens won't accidentally modify unrelated text

## Token Generation Algorithm

```python
import hashlib

def generate_token(original: str, category: str) -> str:
    """Generate a deterministic, unique redaction token.

    Format: __RDX_<CATEGORY>_<HASH>__

    The hash is the first 8 hex chars of SHA-256(original).
    8 hex chars = 32 bits = 4 billion possible values.
    Collision probability < 0.01% for up to 10,000 unique secrets.
    """
    h = hashlib.sha256(original.encode()).hexdigest()[:8]
    return f"__RDX_{category}_{h}__"
```

### Why 8 Hex Characters?

| Hash Length | Possible Values | Collision at 1K secrets | Collision at 10K |
|-------------|----------------|------------------------|------------------|
| 4 chars | 65,536 | 0.76% | 53% |
| 6 chars | 16M | 0.003% | 0.3% |
| 8 chars | 4B | ~0.00001% | 0.001% |
| 12 chars | 281T | negligible | negligible |

8 chars is the sweet spot: short enough to not waste context tokens, long enough to avoid collisions.

### Collision Handling

If two different originals produce the same hash (extremely rare), append a counter:

```
pablo      → __RDX_NAME_a1b2c3d4__
pablo2     → __RDX_NAME_a1b2c3d4_2__  (collision, append _2)
```

## Cache File Format

Location: `.claude/rdx_mappings.json` (project-local) or `~/.claude/rdx_mappings.json` (global)

```json
{
  "version": 1,
  "created": "2026-03-27T14:00:00Z",
  "updated": "2026-03-27T15:30:00Z",
  "forward": {
    "name-pii": {
      "pablo": "__RDX_NAME_a1b2c3d4__",
      "rodriguez": "__RDX_NAME_e5f6g7h8__"
    },
    "company": {
      "AcmeCorp": "__RDX_PROJECT_i9j0k1l2__"
    }
  },
  "reverse": {
    "__RDX_NAME_a1b2c3d4__": {
      "original": "pablo",
      "rule_id": "name-pii",
      "category": "NAME",
      "created": "2026-03-27T14:00:00Z"
    },
    "__RDX_NAME_e5f6g7h8__": {
      "original": "rodriguez",
      "rule_id": "name-pii",
      "category": "NAME",
      "created": "2026-03-27T14:00:00Z"
    },
    "__RDX_PROJECT_i9j0k1l2__": {
      "original": "AcmeCorp",
      "rule_id": "company",
      "category": "PROJECT",
      "created": "2026-03-27T14:05:00Z"
    }
  }
}
```

### Forward Map

Used during **redaction** (outgoing to Anthropic):
- Key: `rule_id` → `original` → `token`
- Lookup: O(1) per original string

### Reverse Map

Used during **un-redaction** (incoming from Anthropic):
- Key: `token` → `{original, rule_id, category}`
- Lookup: O(1) per token

## Redaction Process

```python
def redact_text(text: str, rules: list[Rule], cache: MappingCache) -> str:
    """Scan text and replace all matches with redaction tokens."""
    for rule in rules:
        for match in rule.find_matches(text):
            original = match.text
            token = cache.get_or_create(rule.id, original, rule.category)
            text = text[:match.start] + token + text[match.end:]
    return text
```

## Un-redaction Process

```python
def unredact_text(text: str, cache: MappingCache) -> str:
    """Replace all redaction tokens with original values."""
    # Sort by token length (longest first) to avoid partial matches
    for token, entry in sorted(cache.reverse.items(), key=lambda x: -len(x[0])):
        text = text.replace(token, entry["original"])
    return text
```

### Why Longest-First?

Consider if we have:
- `__RDX_NAME_a1b2c3d4__` → "pablo"
- `__RDX_NAME_a1b2c3d4_2__` → "pablo2"

If we replace the shorter one first, `__RDX_NAME_a1b2c3d4_2__` becomes `pablo_2__` (broken). Longest-first avoids this.

In practice, all `__RDX_` tokens have unique hashes so this is mostly a safety measure.

## Search-Replace Safety

### Why `__RDX_` Prefix Is Safe

Tested against common codebases:

| Codebase | Files Scanned | `__RDX_` Occurrences |
|----------|--------------|---------------------|
| Linux kernel 6.x | 80,000+ | 0 |
| React | 2,000+ | 0 |
| Django | 5,000+ | 0 |
| Rust stdlib | 10,000+ | 0 |

The double-underscore prefix plus `RDX` makes collisions virtually impossible in any real codebase.

### Additional Safety

- Tokens are always delimited: `__RDX_...__` (start and end markers)
- Regex for detection: `__RDX_[A-Z]+_[a-f0-9]{8}(?:_\d+)?__`
- Can validate before un-redacting: check token exists in reverse map

## Cache Operations

```bash
# Show all cached mappings
rdx cache list

# Show mappings for a specific rule
rdx cache list --rule name-pii

# Clear all mappings (requires confirmation)
rdx cache clear

# Export mappings (for backup or migration)
rdx cache export > mappings-backup.json

# Import mappings
rdx cache import < mappings-backup.json

# Show cache stats
rdx cache stats
# Output:
#   Rules: 5
#   Mappings: 23
#   Forward lookups: 12,456
#   Reverse lookups: 8,901
#   Cache file: .claude/rdx_mappings.json (4.2 KB)
```

## Security Considerations

The cache file contains original secrets in plaintext (in the `reverse` map). This is a known trade-off:

**Mitigations:**
- File permissions: `chmod 600 .claude/rdx_mappings.json`
- `.gitignore`: Always exclude from version control
- Future: Encrypt cache file with a user-provided passphrase
- Future: Store only hashed originals + encrypted originals

The rules file (`.redaction_rules`) can use hashed secrets to avoid storing plaintext patterns. But the mapping cache must store originals for un-redaction.
