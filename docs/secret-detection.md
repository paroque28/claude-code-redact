# Secret Detection Strategies

## Overview

rdx uses multiple layers of detection to find secrets, PII, and sensitive data before it leaves the machine.

## Layer 1: User-Defined Rules (Highest Priority)

Explicit patterns in `.redaction_rules`:

```yaml
rules:
  # Exact name replacement
  - id: my-name
    pattern: 'Pablo Rodriguez'
    action: redact
    category: NAME

  # Company name
  - id: company
    pattern: 'AcmeCorp'
    action: redact
    is_regex: false
    category: PROJECT

  # Custom regex
  - id: internal-urls
    pattern: 'https://[a-z]+\.acmecorp\.internal'
    action: redact
    category: HOST
```

These always take priority. The user knows best what's sensitive in their context.

## Layer 2: Known Secret Patterns

Built-in regex library for common secret formats:

| Pattern | Regex | Category |
|---------|-------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | KEY |
| AWS Secret Key | `aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}` | KEY |
| GitHub Token | `ghp_[a-zA-Z0-9]{36,}` | KEY |
| GitLab Token | `glpat-[a-zA-Z0-9\-]{20,}` | KEY |
| OpenAI Key | `sk-[a-zA-Z0-9]{32,}` | KEY |
| Anthropic Key | `sk-ant-[a-zA-Z0-9\-]{40,}` | KEY |
| Slack Token | `xox[bpras]-[a-zA-Z0-9\-]+` | KEY |
| Private Key Header | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` | KEY |
| JWT | `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+` | KEY |
| Generic API Key | `[a-zA-Z_]*api[_-]?key["\s:=]+["']?[a-zA-Z0-9]{20,}` | KEY |

## Layer 3: Entropy-Based Detection

High-entropy strings are statistically likely to be secrets (random tokens, keys, passwords).

```python
import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def is_likely_secret(s: str) -> bool:
    """Heuristic: high entropy + sufficient length = likely secret."""
    if len(s) < 16:
        return False
    entropy = shannon_entropy(s)
    # English text: ~3.5-4.5 bits/char
    # Random base64: ~5.5-6.0 bits/char
    # Random hex: ~4.0 bits/char
    return entropy > 4.5 and len(s) >= 20
```

### Entropy Thresholds

| String Type | Typical Entropy | Detection |
|-------------|----------------|-----------|
| English text | 3.5 - 4.5 | Below threshold |
| Code identifiers | 3.0 - 4.0 | Below threshold |
| Base64 secrets | 5.5 - 6.0 | Above threshold |
| Hex tokens | 4.0 - 4.5 | Borderline (combine with length) |
| UUIDs | 3.7 (limited charset) | Below (use pattern instead) |

### False Positive Mitigation

- Only flag strings > 20 characters
- Ignore known non-secret patterns (UUIDs, hashes in comments, test data)
- Allow user to whitelist patterns
- Entropy detection is advisory (warn) not blocking by default

## Layer 4: Context-Based Detection

Detect secrets by their surrounding context:

```python
CONTEXT_PATTERNS = [
    # Key-value assignment patterns
    r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:secret|token|api_key|apikey)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:auth|authorization|bearer)\s*[:=]\s*["\']([^"\']+)["\']',

    # Environment variable patterns
    r'export\s+\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\s*=\s*["\']?(\S+)',

    # Connection string patterns
    r'(?:mysql|postgres|mongodb|redis)://\w+:([^@]+)@',

    # Header patterns
    r'Authorization:\s*Bearer\s+(\S+)',
    r'X-API-Key:\s*(\S+)',
]
```

The captured group (the value) is what gets redacted, not the context itself. This preserves the structure while hiding the secret:

```
# Before
password = "super_secret_123"

# After (API proxy redacts)
password = "__RDX_KEY_a1b2c3d4__"
```

## Layer 5: Hashed Secrets

For secrets that shouldn't be stored even in the rules file:

```bash
echo "SecretProjectName" | rdx secret add --id project-name --category PROJECT
```

This stores the SHA-256 hash. At scan time, candidate strings are hashed and compared. The plaintext never touches disk.

## Configuration

All layers are independently configurable in `.redaction_rules`:

```yaml
detection:
  user_rules: true        # Layer 1 (always on)
  known_patterns: true    # Layer 2
  entropy: true           # Layer 3
  entropy_threshold: 4.5  # Bits per character
  entropy_min_length: 20  # Minimum string length
  context: true           # Layer 4
  hashed: true            # Layer 5

rules:
  - id: my-secret
    # ... user-defined rules
```

## Testing Secret Detection

```bash
# Scan files for detected secrets
rdx check src/ tests/

# Dry-run: show what would be redacted without modifying anything
rdx check --verbose src/config.py

# Test a specific string
echo "AKIAIOSFODNN7EXAMPLE" | rdx check --stdin

# List all detection rules (built-in + user-defined)
rdx rules list
```
