"""Built-in regex pattern library for known secret formats."""

from rdx.core.models import Rule


def get_builtin_rules() -> list[Rule]:
    """Return built-in secret detection rules.

    Each rule targets a well-known secret format and defaults to action="redact".
    Rules are evaluated in order; first match wins when patterns overlap.
    """
    return [
        # --- Cloud provider keys ---
        Rule(
            id="aws-access-key",
            pattern=r"AKIA[0-9A-Z]{16}",
            category="KEY",
            description="AWS Access Key ID",
        ),
        Rule(
            id="aws-secret-key",
            pattern=r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
            category="KEY",
            description="AWS Secret Access Key",
        ),
        Rule(
            id="gcp-service-account",
            pattern=r'"type"\s*:\s*"service_account"',
            category="KEY",
            description="GCP Service Account JSON marker",
        ),
        # --- Git platform tokens ---
        Rule(
            id="github-token",
            pattern=r"ghp_[a-zA-Z0-9]{36,}",
            category="KEY",
            description="GitHub Personal Access Token",
        ),
        Rule(
            id="github-fine-grained",
            pattern=r"github_pat_[a-zA-Z0-9_]{22,}",
            category="KEY",
            description="GitHub Fine-Grained Token",
        ),
        Rule(
            id="gitlab-token",
            pattern=r"glpat-[a-zA-Z0-9\-]{20,}",
            category="KEY",
            description="GitLab Personal Access Token",
        ),
        # --- AI provider keys ---
        Rule(
            id="anthropic-key",
            pattern=r"sk-ant-[a-zA-Z0-9\-]{40,}",
            category="KEY",
            description="Anthropic API Key",
        ),
        Rule(
            id="openai-key",
            pattern=r"sk-(?!ant-)[a-zA-Z0-9\-_]{32,}",
            category="KEY",
            description="OpenAI API Key",
        ),
        # --- SaaS / messaging tokens ---
        Rule(
            id="slack-token",
            pattern=r"xox[bpras]-[a-zA-Z0-9\-]+",
            category="KEY",
            description="Slack Token",
        ),
        Rule(
            id="stripe-key",
            pattern=r"sk_live_[a-zA-Z0-9]{24,}",
            category="KEY",
            description="Stripe Secret Key",
        ),
        Rule(
            id="stripe-restricted",
            pattern=r"rk_live_[a-zA-Z0-9]{24,}",
            category="KEY",
            description="Stripe Restricted Key",
        ),
        Rule(
            id="twilio-key",
            pattern=r"SK[0-9a-fA-F]{32}",
            category="KEY",
            description="Twilio API Key",
        ),
        Rule(
            id="sendgrid-key",
            pattern=r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}",
            category="KEY",
            description="SendGrid API Key",
        ),
        # --- Cryptographic material ---
        Rule(
            id="private-key",
            pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            category="KEY",
            description="Private Key Header",
        ),
        Rule(
            id="jwt",
            pattern=r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            category="KEY",
            description="JSON Web Token",
        ),
        # --- Generic catch-all (lower priority — place last) ---
        Rule(
            id="generic-secret-assignment",
            pattern=(
                r"(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token|"
                r"access_token|private_key)\s*[:=]\s*[\"']([^\"']{8,})[\"']"
            ),
            category="KEY",
            description="Generic secret assignment",
        ),
    ]
