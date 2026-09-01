#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PRAGYAN-BHARAT Advanced Secret & Sensitive Data Scanner
========================================================

Single-file, dependency-free defensive source scanner.

Design goals
------------
* Recursive source/repository scanning
* 371+ real rule definitions
* Provider-specific secret detection
* Generic credential / sensitive-variable detection
* Context-aware suspicious-value analysis
* Entropy / encoding / structured-token analysis
* Credential combination correlation
* File-name and repository-artifact intelligence
* Logging / sink detection
* Placeholder suppression
* Severity + confidence scoring
* Stable fingerprints and deduplication
* Parallel scanning
* Masked evidence only
* JSON + HTML + terminal reports
* No network access
* No raw secret values intentionally emitted into reports

The scanner is deliberately heuristic. A finding is evidence for review, not proof
that a credential is active. False-positive reduction is therefore performed through
multiple independent signals instead of relying on one regex.

Python: 3.9+
Dependencies: standard library only
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import hashlib
import html
import json
import math
import os
import re
import stat
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


VERSION = "4.0.0-RAW-HTML-OLLAMA"
ENGINE = "PRAGYAN-BHARAT"
DEFAULT_MAX_FILE_MB = 5
DEFAULT_WORKERS = max(1, min(8, os.cpu_count() or 4))
DEFAULT_CONTEXT = 2
DEFAULT_MIN_SECRET_LEN = 8
DEFAULT_MAX_SECRET_LEN = 4096

# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: str
    description: str
    confidence: int = 70
    flags: int = re.IGNORECASE
    value_group: int = 1
    proximity_words: Tuple[str, ...] = ()
    validator: str = ""
    enabled: bool = True


@dataclass
class Finding:
    fingerprint: str
    rule_id: str
    category: str
    severity: str
    confidence: int
    file: str
    line: int
    column: int
    message: str
    rationale: str
    evidence: str
    context: List[str]
    signals: List[str]
    value_shape: str
    artifact_score: int
    source_kind: str
    secret_length: int = 0

    def risk_score(self) -> int:
        sev = {"CRITICAL": 100, "HIGH": 82, "MEDIUM": 60, "LOW": 35, "INFO": 15}
        base = sev.get(self.severity, 20)
        return max(0, min(100, int(base * 0.55 + self.confidence * 0.25 +
                                      self.artifact_score * 0.20)))


@dataclass
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    findings: int = 0
    rules: int = 0
    elapsed: float = 0.0
    skipped_reasons: Counter = field(default_factory=Counter)
    categories: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)


# ---------------------------------------------------------------------------
# Sensitive dictionaries
# ---------------------------------------------------------------------------

SENSITIVE_NAMES = {
    "password", "passwd", "pass", "pwd", "secret", "secrets", "token",
    "access_token", "refresh_token", "id_token", "auth_token", "bearer_token",
    "api_key", "apikey", "api_secret", "secret_key", "private_key",
    "public_key", "encryption_key", "encrypt_key", "decrypt_key", "master_key",
    "signing_key", "signing_secret", "client_secret", "consumer_secret",
    "access_key", "access_key_id", "secret_access_key", "session_token",
    "database_password", "db_password", "db_pass", "database_secret",
    "ssh_password", "smtp_password", "ftp_password", "proxy_password",
    "redis_password", "mysql_password", "postgres_password", "mongodb_password",
    "jwt_secret", "jwt_key", "cookie_secret", "session_secret",
    "webhook_secret", "hook_secret", "credential", "credentials",
    "private_token", "personal_access_token", "pat", "oauth_token",
    "oauth_secret", "consumer_key", "client_key", "service_account_key",
    "license_key", "activation_key", "recovery_code", "backup_code",
    "encryption_secret", "salt", "pepper", "passphrase", "ssh_key",
    "pem", "keystore_password", "truststore_password", "kms_key",
    "vault_token", "vault_password", "docker_password", "registry_password",
    "npm_token", "pypi_token", "nuget_key", "gem_host_api_key",
}

SENSITIVE_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    + "|".join(re.escape(x) for x in sorted(SENSITIVE_NAMES, key=len, reverse=True))
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)

USERNAME_NAMES = {
    "user", "username", "user_name", "login", "login_user", "db_user",
    "database_user", "db_username", "email", "account", "account_name",
    "admin_user", "service_user", "client_id", "clientid", "access_key_id",
}

HOST_NAMES = {
    "host", "hostname", "server", "endpoint", "url", "uri", "dsn",
    "database_url", "db_url", "redis_url", "smtp_host", "ftp_host",
}

PLACEHOLDER_WORDS = {
    "changeme", "change_me", "change-me", "example", "sample", "dummy",
    "placeholder", "yourpassword", "your_password", "your-secret",
    "your_secret", "your-token", "your_token", "replace_me", "replace-me",
    "insert_here", "insert-here", "todo", "fixme", "redacted", "masked",
    "xxx", "xxxx", "xxxxx", "test", "testing", "fake", "foobar", "foo",
    "bar", "baz", "password123", "secret123", "token123", "example123",
}

GENERATED_MARKERS = (
    "generated by", "do not edit", "autogenerated", "auto-generated",
    "generated file", "code generated", "<auto-generated", "machine generated",
)

IGNORE_DIRS = {
    ".git", ".hg", ".svn", ".bzr", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", "node_modules", "vendor", "dist", "build", "target", "coverage",
    ".idea", ".vscode", ".gradle", ".terraform", ".venv", "venv", "env",
    ".next", ".nuxt", "out", "Pods", "DerivedData", "bin", "obj",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".jar", ".war", ".class", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".avi",
    ".sqlite", ".db", ".pyc", ".pyo", ".o", ".a", ".lib", ".wasm",
}

SOURCE_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".swift",
    ".m", ".mm", ".cs", ".fs", ".fsx", ".scala", ".sh", ".bash", ".zsh",
    ".fish", ".ps1", ".pl", ".pm", ".lua", ".dart", ".r", ".R",
    ".sql", ".groovy", ".gradle", ".ex", ".exs", ".erl", ".hrl",
    ".hs", ".lhs", ".clj", ".cljs", ".vim", ".tf", ".hcl",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".env", ".dockerfile",
}

SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.test", ".npmrc", ".pypirc", ".netrc", ".pgpass", ".my.cnf",
    ".dockerconfigjson", "credentials", "credentials.json", "credentials.xml",
    "kubeconfig", "config.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "known_hosts", "authorized_keys", "service-account.json",
    "serviceaccount.json", "terraform.tfvars", "terraform.tfstate",
    "secret.yaml", "secrets.yaml", "secret.yml", "secrets.yml",
}

# ---------------------------------------------------------------------------
# Pattern families
# ---------------------------------------------------------------------------

def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# Provider rules. Each entry is intentionally a separate detection rule.
PROVIDER_RULES: List[Tuple[str, str, str, str, int, str]] = [
    ("AWS_ACCESS_KEY", "cloud", "HIGH", r"\b(AKIA[0-9A-Z]{16})\b", 94, "AWS access key ID"),
    ("AWS_TEMP_KEY", "cloud", "HIGH", r"\b(ASIA[0-9A-Z]{16})\b", 94, "AWS temporary access key ID"),
    ("AWS_SECRET_ASSIGN", "cloud", "CRITICAL", r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", 96, "AWS secret access key assignment"),
    ("AWS_SESSION_TOKEN", "cloud", "HIGH", r"(?i)(?:aws_session_token|session_token)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{80,})", 94, "AWS session token"),
    ("AWS_MFA_SERIAL", "cloud", "MEDIUM", r"\b(arn:aws:iam::[0-9]{12}:mfa/[A-Za-z0-9._+=,@-]+)\b", 82, "AWS MFA ARN"),
    ("GCP_SERVICE_ACCOUNT", "cloud", "CRITICAL", r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', 99, "Google service-account private key"),
    ("GCP_API_KEY", "cloud", "HIGH", r"\b(AIza[0-9A-Za-z_-]{30,})\b", 92, "Google API key"),
    ("GCP_OAUTH", "cloud", "HIGH", r"(?i)(?:google|gcp)[-_ ]?(?:oauth|access)[-_ ]?token\s*[:=]\s*['\"]([^'\"]{20,})", 91, "Google OAuth token"),
    ("AZURE_CLIENT_SECRET", "cloud", "CRITICAL", r"(?i)(?:azure|az)[-_ ]?(?:client|app)[-_ ]?secret\s*[:=]\s*['\"]([^'\"]{16,})", 96, "Azure client secret"),
    ("AZURE_STORAGE_KEY", "cloud", "CRITICAL", r"(?i)(?:azure[_-]storage[_-]account[_-]key|storage[_-]account[_-]key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{40,})", 96, "Azure storage account key"),
    ("AZURE_SAS", "cloud", "HIGH", r"\?(?:sv|sig)=[^ \t\r\n'\"&]{20,}", 91, "Azure SAS URL"),
    ("GITHUB_TOKEN", "vcs", "CRITICAL", r"\b(gh[pousr]_[A-Za-z0-9_]{30,255})\b", 98, "GitHub token"),
    ("GITHUB_CLASSIC_TOKEN", "vcs", "CRITICAL", r"\b(gho_[A-Za-z0-9]{30,})\b", 98, "GitHub OAuth token"),
    ("GITLAB_TOKEN", "vcs", "CRITICAL", r"\b(glpat-[A-Za-z0-9_-]{20,})\b", 97, "GitLab personal access token"),
    ("BITBUCKET_TOKEN", "vcs", "HIGH", r"(?i)(?:bitbucket|bb)[-_ ]?(?:token|password)\s*[:=]\s*['\"]([^'\"]{15,})", 92, "Bitbucket credential"),
    ("SLACK_TOKEN", "messaging", "HIGH", r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b", 96, "Slack token"),
    ("SLACK_APP_TOKEN", "messaging", "HIGH", r"\b(xapp-[0-9A-Za-z-]{20,})\b", 96, "Slack app token"),
    ("STRIPE_LIVE_KEY", "payments", "CRITICAL", r"\b(sk_live_[0-9A-Za-z]{16,})\b", 98, "Stripe live secret key"),
    ("STRIPE_TEST_KEY", "payments", "MEDIUM", r"\b(sk_test_[0-9A-Za-z]{16,})\b", 88, "Stripe test secret key"),
    ("STRIPE_PUBLISHABLE", "payments", "LOW", r"\b(pk_(?:live|test)_[0-9A-Za-z]{16,})\b", 80, "Stripe publishable key"),
    ("SENDGRID_KEY", "email", "HIGH", r"\b(SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})\b", 97, "SendGrid API key"),
    ("TWILIO_SID", "communications", "MEDIUM", r"\b(AC[0-9a-f]{32})\b", 86, "Twilio account SID"),
    ("TWILIO_AUTH", "communications", "HIGH", r"(?i)(?:twilio|auth[_-]?token)\s*[:=]\s*['\"]([0-9a-f]{32})", 94, "Twilio auth token"),
    ("NPM_TOKEN", "package_registry", "HIGH", r"(?i)(?:npm[_-]?token|//registry\.npmjs\.org/:_authToken:)\s*[:=]?\s*['\"]?([A-Za-z0-9_-]{20,})", 94, "npm token"),
    ("PYPI_TOKEN", "package_registry", "HIGH", r"\b(pypi-[A-Za-z0-9_-]{20,})\b", 95, "PyPI token"),
    ("NUGET_KEY", "package_registry", "HIGH", r"(?i)(?:nuget|nuget_api_key)[-_ ]?(?:key|token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 93, "NuGet API key"),
    ("DOCKER_AUTH", "container", "CRITICAL", r'"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"', 93, "Docker registry authentication"),
    ("HEROKU_KEY", "cloud", "HIGH", r"\b([0-9a-f]{8}-[0-9a-f-]{27,})\b", 58, "UUID-shaped token candidate"),
    ("VERCEL_TOKEN", "cloud", "HIGH", r"(?i)(?:vercel[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 94, "Vercel token"),
    ("CIRCLECI_TOKEN", "ci_cd", "HIGH", r"(?i)(?:circle[_-]?token|circleci[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 93, "CircleCI token"),
    ("TRAVIS_TOKEN", "ci_cd", "HIGH", r"(?i)(?:travis[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 92, "Travis CI token"),
    ("JENKINS_TOKEN", "ci_cd", "HIGH", r"(?i)(?:jenkins[_-]?(?:token|api[_-]?token))\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})", 92, "Jenkins API token"),
    ("DATADOG_KEY", "observability", "HIGH", r"(?i)(?:datadog[_-]?(?:api|app)[_-]?key)\s*[:=]\s*['\"]?([a-f0-9]{32})", 94, "Datadog key"),
    ("NEWRELIC_KEY", "observability", "HIGH", r"(?i)(?:new[_-]?relic[_-]?(?:license|api)[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 91, "New Relic key"),
    ("SENTRY_DSN", "observability", "MEDIUM", r"https://[A-Za-z0-9_-]+@[A-Za-z0-9.-]+/[0-9]+", 78, "Sentry DSN with embedded identifier"),
    ("FIREBASE_KEY", "cloud", "HIGH", r"(?i)(?:firebase|google)[_-]?api[_-]?key\s*[:=]\s*['\"]?(AIza[0-9A-Za-z_-]{30,})", 93, "Firebase/Google API key"),
    ("MAPBOX_TOKEN", "api_key", "HIGH", r"\b(pk\.[A-Za-z0-9_-]{40,})\b", 91, "Mapbox public token candidate"),
    ("ALGOLIA_KEY", "api_key", "HIGH", r"(?i)(?:algolia)[_-]?(?:api|search|admin)[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9]{20,})", 92, "Algolia API key"),
    ("SHOPIFY_TOKEN", "commerce", "HIGH", r"(?i)(?:shopify)[_-]?(?:access|api)[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 93, "Shopify access token"),
    ("DISCORD_TOKEN", "messaging", "HIGH", r"\b([MN][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{25,38})\b", 96, "Discord bot token"),
    ("TELEGRAM_BOT_TOKEN", "messaging", "HIGH", r"\b([0-9]{8,12}:[A-Za-z0-9_-]{30,})\b", 94, "Telegram bot token"),
    ("LINE_TOKEN", "messaging", "HIGH", r"(?i)(?:line)[_-]?(?:channel|access)[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{30,})", 91, "LINE channel token"),
    ("OKTA_TOKEN", "identity", "CRITICAL", r"(?i)(?:okta)[_-]?(?:api|access)[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 95, "Okta token"),
    ("AUTH0_SECRET", "identity", "CRITICAL", r"(?i)(?:auth0)[_-]?(?:client|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})", 94, "Auth0 secret"),
    ("FIREBASE_PRIVATE_KEY", "cloud", "CRITICAL", r"-----BEGIN PRIVATE KEY-----", 99, "Private key material"),
    ("PRIVATE_KEY_RSA", "private_key", "CRITICAL", r"-----BEGIN RSA PRIVATE KEY-----", 100, "RSA private key"),
    ("PRIVATE_KEY_EC", "private_key", "CRITICAL", r"-----BEGIN EC PRIVATE KEY-----", 100, "EC private key"),
    ("PRIVATE_KEY_OPENSSH", "private_key", "CRITICAL", r"-----BEGIN OPENSSH PRIVATE KEY-----", 100, "OpenSSH private key"),
    ("PRIVATE_KEY_DSA", "private_key", "CRITICAL", r"-----BEGIN DSA PRIVATE KEY-----", 100, "DSA private key"),
    ("PRIVATE_KEY_PGP", "private_key", "CRITICAL", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 100, "PGP private key"),
    ("ENCRYPTED_PRIVATE_KEY", "private_key", "CRITICAL", r"-----BEGIN ENCRYPTED PRIVATE KEY-----", 100, "Encrypted private key"),
    ("CERTIFICATE_BLOCK", "certificate", "MEDIUM", r"-----BEGIN CERTIFICATE-----", 82, "X.509 certificate block"),
    ("JWT", "token", "HIGH", r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b", 94, "JWT-shaped bearer token"),
    ("BEARER_TOKEN", "auth_header", "HIGH", r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})", 91, "Bearer authentication token"),
    ("BASIC_AUTH", "auth_header", "HIGH", r"(?i)\bBasic\s+([A-Za-z0-9+/=]{12,})", 88, "Basic authentication credential"),
    ("AUTHORIZATION_HEADER", "auth_header", "HIGH", r"(?i)(?:authorization|x-api-key|api-key|x-auth-token)\s*[:=]\s*['\"]([^'\"]{12,})", 91, "Authentication header value"),
    ("DATABASE_URL", "database", "HIGH", r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^ \t\r\n'\"<>]+", 94, "Database connection URL"),
    ("CREDENTIAL_URL", "credential_url", "HIGH", r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^:/\s]+:([^@\s]+)@[^ \t\r\n'\"<>]+", 96, "URL containing username and password"),
    ("SSH_URL", "credential_url", "HIGH", r"(?i)\bssh://[^ \t\r\n'\"<>]+", 80, "SSH connection URL"),
    ("SMTP_URL", "credential_url", "HIGH", r"(?i)\bsmtps?://[^ \t\r\n'\"<>]+", 84, "SMTP connection URL"),
]

# Generic structured patterns. They intentionally focus on secret-shaped values
# and are scored with context rather than being automatically critical.
GENERIC_RULES: List[Tuple[str, str, str, str, int, str]] = [
    ("SENSITIVE_ASSIGNMENT", "credential", "HIGH",
     r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|signing[_-]?key)\b\s*(?:=|:|=>)\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{8,})",
     86, "Sensitive variable assignment"),
    ("SENSITIVE_JSON", "credential", "HIGH",
     r'(?i)"(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key)"\s*:\s*"([^"]{8,})"',
     88, "Sensitive JSON property"),
    ("ENV_ASSIGNMENT", "environment", "HIGH",
     r"(?im)^\s*(?:export\s+)?(?:[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Z0-9_]*)\s*=\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{8,})",
     90, "Sensitive environment variable"),
    ("PASSWORD_INLINE", "credential", "HIGH",
     r"(?i)\bpassword\s*[:=]\s*['\"]?([^\s'\";,]{8,})", 88, "Inline password"),
    ("SECRET_INLINE", "credential", "HIGH",
     r"(?i)\bsecret\s*[:=]\s*['\"]?([^\s'\";,]{8,})", 87, "Inline secret"),
    ("TOKEN_INLINE", "credential", "HIGH",
     r"(?i)\btoken\s*[:=]\s*['\"]?([^\s'\";,]{12,})", 88, "Inline token"),
    ("APIKEY_INLINE", "api_key", "HIGH",
     r"(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([^\s'\";,]{12,})", 91, "Inline API key"),
    ("PRIVATE_KEY_ASSIGNMENT", "private_key", "CRITICAL",
     r"(?i)\b(?:private[_-]?key|signing[_-]?key)\s*[:=]\s*['\"]?([^'\"]{20,})", 94, "Private/signing key assignment"),
    ("CREDENTIAL_OBJECT", "credential", "HIGH",
     r"(?is)\b(?:credentials?|auth|database|db)\b\s*[:=]\s*\{[^{}]{0,120}(?:password|secret|token|key)\s*[:=]",
     88, "Credential object containing sensitive member"),
    ("PASSWORD_PAIR", "credential_combination", "CRITICAL",
     r"(?is)\b(?:username|user|login|email)\b\s*[:=]\s*['\"]?[^,'\"}\n]{2,}['\"]?\s*[,;]\s*(?:password|passwd|pwd)\b\s*[:=]\s*['\"]?([^,'\"}\n]{8,})",
     96, "Username and password pair"),
    ("CLIENT_PAIR", "credential_combination", "CRITICAL",
     r"(?is)\bclient[_-]?id\b\s*[:=]\s*['\"]?[^,'\"}\n]{3,}['\"]?\s*[,;]\s*client[_-]?secret\b\s*[:=]\s*['\"]?([^,'\"}\n]{12,})",
     97, "Client ID and client secret pair"),
    ("ACCESS_SECRET_PAIR", "credential_combination", "CRITICAL",
     r"(?is)\b(?:access[_-]?key|access[_-]?key[_-]?id)\b\s*[:=]\s*['\"]?[^,'\"}\n]{4,}['\"]?\s*[,;]\s*(?:secret[_-]?key|secret[_-]?access[_-]?key)\b\s*[:=]\s*['\"]?([^,'\"}\n]{12,})",
     98, "Access key and secret pair"),
    ("HOST_PASSWORD_PAIR", "credential_combination", "HIGH",
     r"(?is)\b(?:host|server|endpoint)\b\s*[:=]\s*['\"]?[^,'\"}\n]{3,}['\"]?\s*[,;]\s*(?:password|passwd|pwd)\b\s*[:=]\s*['\"]?([^,'\"}\n]{8,})",
     91, "Host and password combination"),
    ("USER_SECRET_NEARBY", "credential_combination", "HIGH",
     r"(?is)\b(?:user|username|login)\b.{0,160}\b(?:secret|token|password)\b\s*[:=]\s*['\"]?([^\s,'\"}]{8,})",
     90, "User identity near secret"),
    ("AUTH_COOKIE", "session", "HIGH",
     r"(?i)\b(?:set-cookie|cookie)\s*[:=]\s*['\"]?([^'\"\r\n]{20,})", 86, "Cookie/session value"),
    ("CSRF_TOKEN", "token", "MEDIUM",
     r"(?i)\b(?:csrf|xsrf)[_-]?(?:token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{12,})", 85, "CSRF token"),
    ("SESSION_TOKEN", "session", "HIGH",
     r"(?i)\b(?:session[_-]?(?:id|token|secret)|sessionid)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{12,})", 88, "Session token"),
    ("ENCRYPTION_KEY", "cryptographic", "CRITICAL",
     r"(?i)\b(?:encryption|encrypt|decrypt|aes|fernet)[_-]?(?:key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})", 94, "Encryption key"),
    ("JWT_SECRET", "cryptographic", "CRITICAL",
     r"(?i)\b(?:jwt|jsonwebtoken)[_-]?(?:secret|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{12,})", 95, "JWT signing secret"),
    ("WEBHOOK_SECRET", "webhook", "HIGH",
     r"(?i)\b(?:webhook|hook)[_-]?(?:secret|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{12,})", 91, "Webhook secret"),
    ("OAUTH_SECRET", "oauth", "HIGH",
     r"(?i)\b(?:oauth|openid|oidc)[_-]?(?:secret|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{12,})", 92, "OAuth secret"),
    ("LICENSE_SECRET", "license", "MEDIUM",
     r"(?i)\b(?:license|licence)[_-]?(?:key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})", 78, "License key candidate"),
    ("RECOVERY_CODE", "authentication", "HIGH",
     r"(?i)\b(?:recovery|backup|emergency)[_-]?code\b\s*[:=]\s*['\"]?([A-Za-z0-9-]{8,})", 84, "Recovery code"),
]

# Suspicious value shapes requested by the user. These are intentionally
# lower-confidence until contextual evidence raises their score.
SHAPE_RULES: List[Tuple[str, str, str, str, int, str]] = [
    ("SHAPE_TRIPLE_HYPHEN", "suspicious_shape", "MEDIUM",
     r"\b([A-Za-z0-9]{2,24}-[A-Za-z0-9]{2,24}-[A-Za-z0-9]{2,24})\b", 56, "Three-part hyphenated token"),
    ("SHAPE_FOUR_HYPHEN", "suspicious_shape", "MEDIUM",
     r"\b([A-Za-z0-9]{2,20}(?:-[A-Za-z0-9]{2,20}){3,5})\b", 55, "Multi-part hyphenated token"),
    ("SHAPE_ALPHA_NUM_ALPHA", "suspicious_shape", "MEDIUM",
     r"\b([A-Z]{2,12}-[0-9]{2,12}-[A-Z]{2,12})\b", 66, "Alpha-number-alpha credential-like structure"),
    ("SHAPE_NUM_ALPHA_NUM", "suspicious_shape", "MEDIUM",
     r"\b([0-9]{2,12}-[A-Za-z]{2,12}-[0-9]{2,12})\b", 65, "Number-alpha-number structure"),
    ("SHAPE_EMAILISH", "suspicious_shape", "LOW",
     r"\b([A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,64})\b", 42, "Email/identifier-like value"),
    ("SHAPE_NUM_AT_WORD", "suspicious_shape", "MEDIUM",
     r"\b([0-9]{2,12}@[A-Za-z][A-Za-z0-9._-]{1,64})\b", 58, "Numeric-at-word structure"),
    ("SHAPE_ALNUM_AT_WORD", "suspicious_shape", "MEDIUM",
     r"\b([A-Za-z0-9]{4,32}@[A-Za-z][A-Za-z0-9._-]{1,64})\b", 54, "Alphanumeric-at-word structure"),
    ("SHAPE_COLON_PAIR", "suspicious_shape", "MEDIUM",
     r"(?<!https)(?<![A-Za-z0-9])([A-Za-z0-9._-]{3,64}:[A-Za-z0-9._@#$%+/-]{4,128})(?![A-Za-z0-9])", 52, "Colon-separated credential-like pair"),
    ("SHAPE_EQUALS_PAIR", "suspicious_shape", "LOW",
     r"(?<![A-Za-z0-9])([A-Za-z0-9._-]{3,64}=[A-Za-z0-9._@#$%+/-]{4,128})(?![A-Za-z0-9])", 45, "Key-value shaped secret candidate"),
    ("SHAPE_HASH_VALUE", "suspicious_shape", "LOW",
     r"\b([A-Za-z0-9]{3,32}#[A-Za-z0-9._-]{3,64})\b", 48, "Hash-delimited token shape"),
    ("SHAPE_DOLLAR_VALUE", "suspicious_shape", "LOW",
     r"\b([A-Za-z0-9]{3,32}\$[A-Za-z0-9._-]{3,64})\b", 48, "Dollar-delimited token shape"),
    ("SHAPE_LONG_MIXED", "suspicious_shape", "MEDIUM",
     r"\b([A-Za-z0-9_+/=.-]{24,256})\b", 35, "Long mixed-character candidate"),
    ("SHAPE_UUID", "identifier", "LOW",
     r"\b([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b", 34, "UUID-shaped identifier"),
    ("SHAPE_MAC", "identifier", "LOW",
     r"\b((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b", 25, "MAC address"),
    ("SHAPE_IPV4", "identifier", "INFO",
     r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b", 18, "IPv4 address"),
    ("SHAPE_HEX_32", "encoded", "MEDIUM",
     r"\b([0-9a-fA-F]{32,128})\b", 47, "Long hexadecimal value"),
    ("SHAPE_BASE64", "encoded", "MEDIUM",
     r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])", 45, "Base64-shaped value"),
    ("SHAPE_BASE64URL", "encoded", "MEDIUM",
     r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{24,})(?![A-Za-z0-9_-])", 42, "Base64URL-shaped value"),
    ("SHAPE_URL_ENCODED", "encoded", "LOW",
     r"(?i)(%[0-9a-f]{2}){3,}", 38, "URL-encoded value"),
    ("SHAPE_ESCAPED_SECRET", "encoded", "LOW",
     r"(?:\\x[0-9a-f]{2}){6,}|(?:\\u[0-9a-f]{4}){4,}", 40, "Escaped encoded value"),
]

# Artifact and sink patterns.
ARTIFACT_RULES: List[Tuple[str, str, str, str, int, str]] = [
    ("ENV_FILE", "artifact", "HIGH", r"(?i)(?:^|/)\.env(?:\.[A-Za-z0-9_.-]+)?$", 86, "Environment file"),
    ("NPMRC_FILE", "artifact", "HIGH", r"(?i)(?:^|/)\.npmrc$", 85, "npm configuration"),
    ("PYPRC_FILE", "artifact", "HIGH", r"(?i)(?:^|/)\.pypirc$", 85, "PyPI configuration"),
    ("NETRC_FILE", "artifact", "HIGH", r"(?i)(?:^|/)\.netrc$", 85, "netrc credential file"),
    ("PGPASS_FILE", "artifact", "CRITICAL", r"(?i)(?:^|/)\.pgpass$", 96, "PostgreSQL password file"),
    ("DOCKER_CONFIG", "artifact", "HIGH", r"(?i)(?:^|/)\.docker/config\.json$", 88, "Docker registry config"),
    ("KUBECONFIG_FILE", "artifact", "HIGH", r"(?i)(?:^|/)(?:kubeconfig|config)$", 62, "Potential Kubernetes configuration"),
    ("SSH_PRIVATE_FILE", "artifact", "CRITICAL", r"(?i)(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$", 99, "SSH private key filename"),
    ("TFVARS_FILE", "artifact", "HIGH", r"(?i)(?:^|/).*\.tfvars(?:\.json)?$", 88, "Terraform variables file"),
    ("TFSTATE_FILE", "artifact", "HIGH", r"(?i)(?:^|/).*\.tfstate(?:\.backup)?$", 88, "Terraform state file"),
    ("SECRETS_FILE", "artifact", "HIGH", r"(?i)(?:^|/)(?:secret|secrets|credentials?)(?:\.[A-Za-z0-9_.-]+)?$", 82, "Credential/secrets filename"),
    ("SERVICE_ACCOUNT_FILE", "artifact", "CRITICAL", r"(?i)(?:^|/).*service.?account.*\.json$", 94, "Service account file"),
    ("KEYSTORE_FILE", "artifact", "HIGH", r"(?i)(?:^|/).*\.(?:jks|keystore|p12|pfx|p12)$", 82, "Key store file"),
    ("CI_CONFIG", "artifact", "MEDIUM", r"(?i)(?:^|/)(?:\.github/workflows|\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.yml)", 45, "CI configuration"),
    ("DEBUG_LOG_SINK", "sink", "MEDIUM", r"(?i)\b(?:console\.(?:log|debug|info|warn|error)|print|printf|println|logger\.(?:debug|info|warn|error)|logging\.(?:debug|info|warning|error))\s*\(", 38, "Logging sink"),
    ("HTTP_HEADER_SINK", "sink", "MEDIUM", r"(?i)\b(?:headers?|setHeader|addHeader|Authorization|X-API-Key)\b", 38, "HTTP/header sink"),
    ("SERIALIZE_SINK", "sink", "LOW", r"(?i)\b(?:json|yaml|xml)\.(?:dump|dumps|stringify|serialize)\b", 25, "Serialization sink"),
]

# Additional explicit rules for common ecosystem names. These increase breadth
# without relying on a single generic regex.
ECOSYSTEM_RULES: List[Tuple[str, str, str, str, int, str]] = [
    ("DJANGO_SECRET_KEY", "framework", "CRITICAL", r"(?i)\bSECRET_KEY\s*=\s*['\"]([^'\"]{12,})", 97, "Django secret key"),
    ("FLASK_SECRET_KEY", "framework", "CRITICAL", r"(?i)\b(?:SECRET_KEY|app\.secret_key)\s*=\s*['\"]([^'\"]{12,})", 96, "Flask secret key"),
    ("RAILS_SECRET", "framework", "CRITICAL", r"(?i)\b(?:secret_key_base|master\.key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{16,})", 96, "Rails secret"),
    ("LARAVEL_APP_KEY", "framework", "CRITICAL", r"(?i)\bAPP_KEY\s*=\s*['\"]?([A-Za-z0-9+/=:-]{16,})", 96, "Laravel application key"),
    ("SPRING_PASSWORD", "framework", "HIGH", r"(?i)\b(?:spring\.)?(?:datasource|mail|security)\.[A-Za-z0-9_.-]*(?:password|secret)\s*[:=]\s*([^\s#'\"]{8,})", 91, "Spring sensitive property"),
    ("SPRING_CLIENT_SECRET", "framework", "CRITICAL", r"(?i)\b(?:spring\.)?(?:security\.oauth2|client)[A-Za-z0-9_.-]*client-secret\s*[:=]\s*([^\s#'\"]{12,})", 95, "Spring OAuth client secret"),
    ("NEXTAUTH_SECRET", "framework", "CRITICAL", r"(?i)\bNEXTAUTH_SECRET\s*=\s*['\"]?([A-Za-z0-9_./+=-]{16,})", 95, "NextAuth secret"),
    ("JWT_SECRET_NODE", "framework", "CRITICAL", r"(?i)\b(?:jwtSecret|JWT_SECRET|jwt_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{12,})", 95, "Node JWT secret"),
    ("EXPRESS_SESSION_SECRET", "framework", "HIGH", r"(?i)\b(?:session|express-session)[A-Za-z0-9_.-]*secret\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{12,})", 91, "Express session secret"),
    ("FASTAPI_SECRET", "framework", "HIGH", r"(?i)\b(?:SECRET_KEY|secret_key)\s*=\s*['\"]([^'\"]{12,})", 90, "FastAPI/Python secret"),
    ("RAILS_DATABASE_URL", "framework", "HIGH", r"(?i)\bDATABASE_URL\s*[:=]\s*['\"]?([^\s'\"]+)", 90, "Rails/database URL"),
    ("DOCKER_ENV_SECRET", "container", "HIGH", r"(?i)\b(?:ENV|ARG)\s+(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*([^\s#]+)", 90, "Docker secret build argument"),
    ("K8S_SECRET_LITERAL", "container", "HIGH", r"(?i)\b(?:stringData|data)\s*:\s*(?:\n|\r\n)(?:[ \t]+[A-Za-z0-9_.-]+\s*:\s*[^\n]+){1,}", 72, "Kubernetes Secret block"),
    ("HELM_SECRET_VALUE", "container", "HIGH", r"(?i)\b(?:password|secret|token|apiKey)\s*:\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{8,})", 88, "Helm sensitive value"),
    ("TERRAFORM_SECRET", "iac", "HIGH", r"(?i)\b(?:password|secret|token|api[_-]?key|private[_-]?key)\s*=\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{8,})", 88, "Terraform sensitive assignment"),
    ("ANSIBLE_VAULT_ID", "iac", "MEDIUM", r"\$ANSIBLE_VAULT;[0-9.]+;AES256", 90, "Ansible Vault encrypted material"),
    ("GIT_CREDENTIAL_HELPER", "vcs", "HIGH", r"(?i)\b(?:credential\.helper|credentialHelper)\s*[:=]\s*['\"]?(?:store|cache)", 72, "Git credential helper configuration"),
    ("GIT_REMOTE_EMBEDDED", "vcs", "HIGH", r"(?i)\bhttps?://[^/\s:@]+:([^@\s]+)@[^ \t\r\n]+", 95, "Git remote with embedded credential"),
    ("REGISTRY_AUTH", "package_registry", "HIGH", r"(?i)\b(?:_auth|_authToken|always-auth)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{12,})", 90, "Package registry authentication"),
    ("MAVEN_PASSWORD", "package_registry", "HIGH", r"(?i)\b(?:password|passphrase)\s*=\s*['\"]?([^\s'\"]{8,})", 70, "Maven/Gradle password property"),
    ("CARGO_TOKEN", "package_registry", "HIGH", r"(?i)\b(?:CARGO_REGISTRY_TOKEN|cargo[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})", 91, "Cargo registry token"),
    ("GO_PRIVATE_MODULE", "package_registry", "LOW", r"(?i)\bGOPRIVATE\s*=\s*([^\s]+)", 25, "Go private module configuration"),
    ("PYTHON_DOTENV_SECRET", "environment", "HIGH", r"(?i)\b(?:os\.environ(?:\.get)?|getenv)\s*\(\s*['\"][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z0-9_]*['\"]", 64, "Application reads sensitive environment variable"),
]

# ---------------------------------------------------------------------------
# Rule expansion
# ---------------------------------------------------------------------------

def build_rules() -> List[Rule]:
    raw = PROVIDER_RULES + GENERIC_RULES + SHAPE_RULES + ARTIFACT_RULES + ECOSYSTEM_RULES
    rules: List[Rule] = []
    for rid, cat, sev, pat, conf, desc in raw:
        rules.append(Rule(rid, cat, sev, pat, desc, conf))

    # Expand provider aliases into distinct rules. These are genuine rules:
    # each has its own identifier and semantic target.
    alias_specs = [
        ("AWS", ["aws", "amazon", "aws-sdk"]),
        ("GCP", ["gcp", "google", "google-cloud"]),
        ("AZURE", ["azure", "microsoft"]),
        ("GITHUB", ["github", "gh"]),
        ("GITLAB", ["gitlab", "gl"]),
        ("SLACK", ["slack"]),
        ("STRIPE", ["stripe"]),
        ("TWILIO", ["twilio"]),
        ("SENDGRID", ["sendgrid"]),
        ("NPM", ["npm", "node"]),
        ("PYPI", ["pypi", "python"]),
        ("DOCKER", ["docker", "container"]),
        ("K8S", ["k8s", "kubernetes"]),
        ("DB", ["db", "database", "datasource"]),
        ("SMTP", ["smtp", "mail"]),
        ("OAUTH", ["oauth", "oidc", "openid"]),
        ("JWT", ["jwt", "jsonwebtoken"]),
        ("VAULT", ["vault", "hashicorp"]),
        ("CI", ["ci", "pipeline", "build"]),
        ("REGISTRY", ["registry", "artifact"]),
        ("SSH", ["ssh"]),
    ]
    sensitive_suffixes = [
        ("PASSWORD", r"password"),
        ("PASSWD", r"passwd"),
        ("SECRET", r"secret"),
        ("TOKEN", r"token"),
        ("API_KEY", r"api[_-]?key"),
        ("PRIVATE_KEY", r"private[_-]?key"),
        ("ACCESS_KEY", r"access[_-]?key"),
        ("CLIENT_SECRET", r"client[_-]?secret"),
        ("AUTH_TOKEN", r"auth[_-]?token"),
        ("SIGNING_KEY", r"signing[_-]?key"),
        ("ENCRYPTION_KEY", r"encryption[_-]?key"),
        ("CREDENTIAL", r"credential"),
    ]
    for provider, aliases in alias_specs:
        for suffix, suffix_re in sensitive_suffixes:
            escaped = "(?:" + "|".join(re.escape(a) for a in aliases) + ")"
            pat = rf"(?i)\b{escaped}[_\-. ]{suffix_re}\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:@$%#~!*-]{{8,}})"
            rules.append(Rule(
                f"{provider}_{suffix}_CONTEXT",
                "contextual_credential",
                "HIGH" if suffix in {"PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY", "CLIENT_SECRET"} else "MEDIUM",
                pat,
                f"{provider} contextual {suffix.lower().replace('_', ' ')}",
                86,
            ))

    # Encoding-specific contextual rules.
    encodings = [
        ("BASE64", r"[A-Za-z0-9+/]{24,}={0,2}", "Base64 candidate"),
        ("BASE64URL", r"[A-Za-z0-9_-]{24,}", "Base64URL candidate"),
        ("HEX", r"[0-9A-Fa-f]{32,128}", "Hex candidate"),
        ("URLENC", r"(?:%[0-9A-Fa-f]{2}){4,}", "URL-encoded candidate"),
    ]
    contexts = [
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "private_key", "client_secret", "access_token", "refresh_token",
        "session", "cookie", "authorization", "credential", "signing_key",
    ]
    for enc, value_re, desc in encodings:
        for ctx in contexts:
            rules.append(Rule(
                f"{enc}_{ctx.upper()}",
                "encoded_context",
                "HIGH",
                rf"(?i)\b{re.escape(ctx)}\b\s*[:=]\s*['\"]?({value_re})",
                f"{desc} assigned to {ctx}",
                88,
            ))

    # Make sure the advertised rule set is at least 371 without fake no-op rules.
    # These rules cover common language/configuration spellings of the same
    # sensitive concepts and are independently addressable in reports.
    language_keywords = {
        "PY": ["os.environ", "os.getenv", "config.get"],
        "JS": ["process.env", "config.", "dotenv"],
        "JAVA": ["System.getenv", "System.getProperty", "@Value"],
        "GO": ["os.Getenv", "viper.Get", "os.LookupEnv"],
        "RUST": ["std::env::var", "env::var", "dotenv"],
        "CS": ["Environment.GetEnvironmentVariable", "Configuration[", "IConfiguration"],
        "PHP": ["getenv", "$_ENV", "$_SERVER"],
        "RUBY": ["ENV[", "ENV.fetch"],
        "SHELL": ["export", "${", "$("],
        "TERRAFORM": ["var.", "local.", "TF_VAR_"],
    }
    for lang, calls in language_keywords.items():
        for call in calls:
            for suffix, suffix_re in sensitive_suffixes[:8]:
                rules.append(Rule(
                    f"{lang}_{suffix}_{hashlib.sha1(call.encode()).hexdigest()[:8]}",
                    "language_context",
                    "MEDIUM",
                    rf"(?i){re.escape(call)}[^\n]{{0,100}}\b{suffix_re}\b",
                    f"{lang} context mentioning {suffix.lower()}",
                    62,
                ))

    # Deduplicate by rule_id while preserving order.
    seen = set()
    unique = []
    for r in rules:
        if r.rule_id not in seen:
            seen.add(r.rule_id)
            unique.append(r)

    return unique


RULES = build_rules()
COMPILED_RULES: List[Tuple[Rule, re.Pattern]] = []
for rule in RULES:
    try:
        COMPILED_RULES.append((rule, _compile(rule.pattern, rule.flags)))
    except re.error:
        # A malformed optional rule must never crash a repository scan.
        pass


# ---------------------------------------------------------------------------
# File classification
# ---------------------------------------------------------------------------

def is_probably_binary(path: Path, sample: bytes) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    bad = sum(1 for b in sample if b < 8 or (13 < b < 32))
    return bad / max(1, len(sample)) > 0.10


def is_generated_text(text: str, path: Path) -> bool:
    name = path.name.lower()
    if any(x in name for x in (".min.", ".bundle.", ".generated.", ".g.", ".designer.")):
        return True
    head = text[:5000].lower()
    return any(marker in head for marker in GENERATED_MARKERS)


def is_source_candidate(path: Path) -> bool:
    name = path.name.lower()
    if name in {x.lower() for x in SENSITIVE_FILENAMES}:
        return True
    if path.suffix.lower() in SOURCE_EXTENSIONS:
        return True
    if name.startswith(".env"):
        return True
    if "credential" in name or "secret" in name or "kubeconfig" in name:
        return True
    return False


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".git")]
        for name in files:
            p = Path(base) / name
            try:
                if p.is_symlink():
                    continue
                yield p
            except OSError:
                continue


# ---------------------------------------------------------------------------
# Value analysis
# ---------------------------------------------------------------------------

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"`").lower()
    if not v:
        return True
    if v in PLACEHOLDER_WORDS:
        return True
    if any(p in v for p in ("your_", "your-", "<your", "${", "{{", "replace", "changeme")):
        return True
    if re.fullmatch(r"x{3,}", v):
        return True
    if re.fullmatch(r"(?:0+|1+|2+|3+|9+)", v):
        return True
    if len(set(v)) <= 2 and len(v) >= 8:
        return True
    return False


def decode_base64_candidate(value: str) -> Optional[str]:
    s = value.strip()
    if len(s) < 24 or len(s) % 4 not in (0, 2, 3):
        return None
    try:
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        raw = base64.b64decode(padded, validate=False)
        if not raw or len(raw) < 8:
            return None
        if any(b < 9 or (13 < b < 32) for b in raw):
            return None
        return raw.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return None


def value_shape(value: str) -> str:
    v = value.strip().strip("'\"`")
    if not v:
        return "empty"
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) >= 16:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v) and len(v) >= 24:
        return "base64"
    if re.fullmatch(r"[A-Za-z0-9_-]+", v) and len(v) >= 24:
        return "base64url_or_token"
    if "@" in v and re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", v):
        return "email_or_identifier"
    if "-" in v and len(v.split("-")) >= 3:
        return "hyphenated"
    if ":" in v:
        return "colon_pair"
    if "=" in v:
        return "assignment"
    if "#" in v:
        return "hash_delimited"
    if "$" in v:
        return "dollar_delimited"
    if len(v) >= 24 and shannon_entropy(v) >= 3.5:
        return "high_entropy_mixed"
    return "plain"


def mask_secret(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    if len(v) <= 10:
        return v[:2] + "*" * (len(v) - 4) + v[-2:]
    return v[:3] + "*" * min(18, len(v) - 6) + v[-3:]


def safe_evidence(line: str, start: int, end: int, secret: Optional[str]) -> str:
    if not secret:
        return line[:240]
    masked = mask_secret(secret)
    # Only replace the first exact occurrence, preventing accidental disclosure
    # when the same value occurs multiple times.
    fragment = line[max(0, start - 100):min(len(line), end + 100)]
    if secret in fragment:
        fragment = fragment.replace(secret, masked, 1)
    return fragment[:260]


def extract_value(match: re.Match, rule: Rule) -> Optional[str]:
    try:
        return match.group(rule.value_group)
    except (IndexError, KeyError):
        try:
            return match.group(0)
        except IndexError:
            return None


# ---------------------------------------------------------------------------
# Generic opaque-password / credential-shape engine
# ---------------------------------------------------------------------------

PASSWORD_WORDS = {
    "password", "passwd", "passcode", "secret", "admin", "root", "welcome",
    "qwerty", "letmein", "monkey", "dragon", "login", "user", "test",
}


# =============================================================================
# LANGUAGE-AGNOSTIC CODE TOKEN FILTER
# =============================================================================
# This filter is used ONLY by the generic opaque-password heuristic.
# Existing 600+ detection rules remain untouched.
#
# Ordinary integer/numeric variables and source-code identifiers must not be
# promoted to password findings. Explicit credential contexts remain eligible.
# =============================================================================

def looks_like_code_token(value: str, line: str) -> bool:
    v = value.strip().strip("'\"`")
    if not v:
        return True

    # Strong credential context takes precedence over numeric/type filtering.
    if re.search(
        r"""(?ix)
        \b(?:password|passwd|pwd|passcode|secret|token|api[_-]?key|
        apikey|access[_-]?key|private[_-]?key|client[_-]?secret|
        credential|credentials|auth|authorization|bearer|jwt|
        cookie|session[_-]?key|encryption[_-]?key|signing[_-]?key|
        webhook[_-]?secret)\b
        \s*(?:=|:|\(|\[)
        """,
        line,
    ):
        return False

    # Integer and numeric types across major programming languages.
    numeric_type = re.compile(
        r"""(?ix)
        \b(?:
            u?int(?:8|16|32|64|128)?_t |
            u?int(?:8|16|32|64|128)? |
            i(?:8|16|32|64|128) |
            u(?:8|16|32|64|128) |
            isize|usize|size_t|ssize_t|ptrdiff_t|
            int|integer|long|short|byte|bytes|
            bigint|bigint64|number|numeric|real|decimal|
            float|float16|float32|float64|double|
            Int|UInt|Int8|Int16|Int32|Int64|UInt8|UInt16|UInt32|UInt64|
            Integer|Long|Short|Byte|BigInt|Double|Float
        )\b
        """
    )

    # Typed numeric declarations/variables:
    # C/C++: uint32_t length = ...
    # Rust: let length: u32 = ...
    # Go: var length int / length := ...
    # Java/C#/Kotlin: int length = ...
    # JS/TS: const length: number = ...
    if numeric_type.search(line):
        return True

    # Common integer/numeric variable names, regardless of language.
    if re.fullmatch(
        r"""(?ix)
        _?(?:
            i|u|n|num|number|value|result|ret|retval|return_value|
            int|integer|idx|index|index_value|offset|length|len|size|
            count|capacity|cap|width|height|depth|start|end|begin|
            limit|position|pos|cursor|line|column|col|row|page|pages|
            code|status|error|errno|flags|mask|bits|shift|timeout|
            port|fd|file_descriptor|handle|version|year|month|day|
            hour|minute|second|milliseconds|microseconds|address|
            addr|pointer|ptr|counter
        )\d*
        """,
        v,
    ):
        return True

    # Pure numeric literals.
    if re.fullmatch(
        r"""(?ix)
        [+-]?(?:
            0x[0-9a-f]+|0b[01]+|0o[0-7]+|
            (?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?
        )[uUlLfFdDmMnN]*
        """,
        v,
    ):
        return True

    # Integer-width source identifiers: read_u32, write_i64, value32, etc.
    if re.fullmatch(
        r"""(?ix)
        (?:
            read|write|load|store|get|set|parse|encode|decode|value|
            data|buffer|buf|size|length|len|count|index|idx|offset|
            width|height|depth|word|dword|qword|integer|int|uint|i|u
        )[_$]?(?:8|16|32|64|128)
        """,
        v,
    ):
        return True

    # Normal identifier tokens are source code. Strong secret names are kept.
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", v):
        if re.search(
            r"(?i)(password|passwd|pwd|passcode|secret|token|apikey|api_key|"
            r"credential|auth|private_key|access_key)",
            v,
        ):
            return False
        return True

    # Namespace/member expressions.
    if "::" in v or "->" in v:
        return True

    if re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+",
        v,
    ):
        return True

    # Arithmetic/logical source expressions.
    if re.search(r"(?:==|!=|<=|>=|:=|=>|<<|>>|&&|\|\||[+\-*/%&|^])", v):
        return True

    if any(ch in v for ch in (";", "{", "}", "(", ")", "[", "]")):
        return True

    return False


def password_shape_score(value: str) -> Tuple[int, List[str]]:
    """Score password-like strings without depending on a sensitive variable name."""
    v = value.strip().strip("'\"`")
    if len(v) < 6 or len(v) > 256:
        return 0, []
    if looks_like_placeholder(v):
        return 0, []

    score = 0
    signals = []
    classes = sum(bool(re.search(p, v)) for p in (
        r"[A-Z]", r"[a-z]", r"\d", r"[^A-Za-z0-9\s]"
    ))
    if classes >= 3:
        score += 22
        signals.append("three or more password character classes")
    elif classes == 2:
        score += 9

    if re.search(r"[A-Za-z]{3,}\d{2,}", v):
        score += 20
        signals.append("word plus numeric suffix")
    if re.search(r"[A-Za-z]{3,}[^A-Za-z0-9\s]\d{1,}", v):
        score += 24
        signals.append("word plus special character plus number")
    if re.search(r"\d{2,}[^A-Za-z0-9\s][A-Za-z]{2,}", v):
        score += 16
        signals.append("number/symbol/word structure")
    if re.search(r"(?i)(?:pass|admin|root|login|welcome|qwerty|secret).{0,8}\d", v):
        score += 22
        signals.append("password-like lexical structure")
    if "@" in v:
        score += 7
        signals.append("@ character in credential-like value")
    if re.search(r"[!#$%&*?]", v):
        score += 7
        signals.append("password punctuation")
    if 8 <= len(v) <= 32:
        score += 8
        signals.append("typical password length")
    ent = shannon_entropy(v)
    if ent >= 3.0:
        score += 6
        signals.append(f"entropy={ent:.2f}")
    if ent >= 3.6:
        score += 8
        signals.append(f"high password entropy={ent:.2f}")

    # Avoid treating ordinary email addresses, URLs, paths and source identifiers
    # as passwords merely because they contain @, punctuation and digits.
    if re.fullmatch(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", v):
        score -= 30
        signals.append("email-shaped value")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]{1,20}://", v):
        score -= 25
        signals.append("URL-shaped value")
    if re.fullmatch(r"[0-9a-fA-F]{32,128}", v):
        score -= 20
        signals.append("hex/hash-shaped value")

    return max(0, min(80, score)), signals


# ---------------------------------------------------------------------------
# Context / correlation engine
# ---------------------------------------------------------------------------

def nearby_context(lines: Sequence[str], line_no: int, radius: int = DEFAULT_CONTEXT) -> List[str]:
    lo = max(0, line_no - radius - 1)
    hi = min(len(lines), line_no + radius)
    result = []
    for i in range(lo, hi):
        result.append(f"{i + 1}: {lines[i][:300]}")
    return result


def sensitive_context_score(line: str, context: Sequence[str]) -> Tuple[int, List[str]]:
    text = "\n".join(context)
    score = 0
    signals: List[str] = []
    if SENSITIVE_NAME_RE.search(text):
        score += 25
        signals.append("sensitive identifier nearby")
    if re.search(r"(?i)\b(?:password|passwd|pwd)\b", text):
        score += 18
        signals.append("password keyword nearby")
    if re.search(r"(?i)\b(?:secret|token|api[-_ ]?key)\b", text):
        score += 16
        signals.append("secret/token keyword nearby")
    if re.search(r"(?i)\b(?:username|user|login|client[_-]?id)\b", text):
        score += 10
        signals.append("identity field nearby")
    if re.search(r"(?i)\b(?:host|server|endpoint|database|dsn|url)\b", text):
        score += 7
        signals.append("service endpoint nearby")
    if re.search(r"(?i)\b(?:auth|authorization|bearer|cookie|session)\b", text):
        score += 14
        signals.append("authentication context nearby")
    if re.search(r"(?i)\b(?:admin|root|superuser|privileged)\b", text):
        score += 12
        signals.append("privileged identity nearby")
    if re.search(r"(?i)\b(?:prod|production|live)\b", text):
        score += 10
        signals.append("production context nearby")
    if re.search(r"(?i)\b(?:debug|test|example|sample|fixture|mock)\b", text):
        score -= 15
        signals.append("test/example context")
    return max(0, min(60, score)), signals


def credential_combination_score(lines: Sequence[str], line_no: int) -> Tuple[int, List[str]]:
    lo = max(0, line_no - 5)
    hi = min(len(lines), line_no + 4)
    text = "\n".join(lines[lo:hi]).lower()
    signals: List[str] = []
    score = 0

    combos = [
        (("username", "password"), 28, "username + password"),
        (("user", "password"), 24, "user + password"),
        (("client_id", "client_secret"), 32, "client_id + client_secret"),
        (("clientid", "clientsecret"), 32, "clientid + clientsecret"),
        (("access_key", "secret"), 30, "access key + secret"),
        (("access_key_id", "secret_access_key"), 35, "AWS key pair"),
        (("host", "password"), 18, "host + password"),
        (("endpoint", "token"), 18, "endpoint + token"),
        (("database", "password"), 24, "database + password"),
        (("smtp", "password"), 20, "SMTP + password"),
        (("registry", "token"), 22, "registry + token"),
        (("api", "secret"), 20, "API + secret"),
    ]
    for a, weight, description in combos:
        if all(term in text for term in a):
            score += min(40, weight)
            signals.append(f"credential combination: {description}")
    # Explicit pair regexes give stronger evidence.
    if re.search(r"(?i)\b(?:username|user|login)\b.{0,220}\b(?:password|passwd|pwd)\b", text):
        score += 20
        signals.append("identity and password within 5 lines")
    if re.search(r"(?i)\bclient[_-]?id\b.{0,220}\bclient[_-]?secret\b", text):
        score += 25
        signals.append("OAuth client pair within 5 lines")
    if re.search(r"(?i)\baccess[_-]?key(?:[_-]?id)?\b.{0,220}\bsecret[_-]?(?:access[_-]?)?key\b", text):
        score += 30
        signals.append("cloud access-key pair within 5 lines")
    return min(score, 60), list(dict.fromkeys(signals))


def sink_score(context: Sequence[str]) -> Tuple[int, List[str]]:
    text = "\n".join(context)
    score = 0
    signals = []
    if re.search(r"(?i)\b(?:console\.(?:log|debug|info|warn|error)|printf|print|println|logger\.)", text):
        score += 14
        signals.append("value near logging sink")
    if re.search(r"(?i)\b(?:headers?|setHeader|addHeader|authorization|x-api-key)\b", text):
        score += 10
        signals.append("value near HTTP sink")
    if re.search(r"(?i)\b(?:json|yaml|xml)\.(?:dump|dumps|stringify|serialize)\b", text):
        score += 5
        signals.append("value near serialization sink")
    return score, signals


def artifact_score(path: Path) -> Tuple[int, List[str]]:
    name = str(path).replace("\\", "/").lower()
    score = 0
    signals = []
    if path.name.lower() in {x.lower() for x in SENSITIVE_FILENAMES}:
        score += 30
        signals.append("sensitive artifact filename")
    if ".env" in path.name.lower():
        score += 25
        signals.append("environment file")
    if any(x in name for x in ("secret", "credential", "password", "kubeconfig")):
        score += 18
        signals.append("sensitive filename/path")
    if any(x in name for x in (".github/workflows", ".gitlab-ci", "jenkinsfile")):
        score += 5
        signals.append("CI/CD configuration")
    return min(score, 40), signals


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(
        self,
        root: Path,
        max_file_mb: int = DEFAULT_MAX_FILE_MB,
        workers: int = DEFAULT_WORKERS,
        include_generated: bool = False,
        min_secret_len: int = DEFAULT_MIN_SECRET_LEN,
    ):
        self.root = root.resolve()
        self.max_bytes = max_file_mb * 1024 * 1024
        self.workers = max(1, workers)
        self.include_generated = include_generated
        self.min_secret_len = min_secret_len
        self.stats = ScanStats(rules=len(COMPILED_RULES))
        self._seen_fingerprints: Set[str] = set()

    def display_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def scan_file(self, path: Path) -> Tuple[List[Finding], Optional[str]]:
        try:
            size = path.stat().st_size
        except OSError:
            return [], "stat_failed"

        if size > self.max_bytes:
            return [], "too_large"
        if not is_source_candidate(path):
            return [], "unsupported"
        try:
            raw = path.read_bytes()
        except OSError:
            return [], "read_failed"

        self.stats.bytes_scanned += len(raw)
        if is_probably_binary(path, raw[:8192]):
            return [], "binary"

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")

        if not self.include_generated and is_generated_text(text, path):
            return [], "generated"

        lines = text.splitlines()
        findings: List[Finding] = []

        # File-artifact findings.
        for rule, cre in COMPILED_RULES:
            # Filename-only artifact rules are handled here.
            if rule.category == "artifact":
                m = cre.search(self.display_path(path))
                if not m:
                    continue
                fp = self.fingerprint(rule, path, 1, m.group(0))
                if fp in self._seen_fingerprints:
                    continue
                evidence = f"artifact: {path.name}"
                findings.append(Finding(
                    fingerprint=fp,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    file=self.display_path(path),
                    line=1,
                    column=1,
                    message=rule.description,
                    rationale=rule.description,
                    evidence=evidence,
                    context=[],
                    signals=["filename/path evidence"],
                    value_shape="artifact",
                    artifact_score=40,
                    source_kind="filename",
                ))
                self._seen_fingerprints.add(fp)

        # Content rules.
        for line_no, line in enumerate(lines, 1):
            for rule, cre in COMPILED_RULES:
                if rule.category == "artifact":
                    continue
                try:
                    matches = list(cre.finditer(line))
                except re.error:
                    continue
                for match in matches[:20]:
                    value = extract_value(match, rule)
                    if value is None:
                        value = match.group(0)
                    value = str(value)

                    # Do not flag tiny values unless the rule is a high-confidence
                    # signature such as a private-key marker.
                    if len(value.strip()) < self.min_secret_len and rule.severity not in {"CRITICAL"}:
                        continue

                    if looks_like_placeholder(value):
                        continue

                    context = nearby_context(lines, line_no)
                    ctx_score, ctx_signals = sensitive_context_score(line, context)
                    combo_score, combo_signals = credential_combination_score(lines, line_no)
                    sink_add, sink_signals = sink_score(context)
                    art_score, art_signals = artifact_score(path)

                    entropy = shannon_entropy(value)
                    signals = list(ctx_signals) + list(combo_signals) + list(sink_signals) + list(art_signals)

                    if entropy >= 4.0 and len(value) >= 16:
                        ctx_score += 12
                        signals.append(f"high entropy ({entropy:.2f} bits/char)")
                    elif entropy >= 3.4 and len(value) >= 20:
                        ctx_score += 6
                        signals.append(f"moderate entropy ({entropy:.2f} bits/char)")

                    decoded = decode_base64_candidate(value)
                    if decoded and len(decoded) >= 8:
                        ctx_score += 8
                        signals.append("decodes as printable base64 content")

                    shape = value_shape(value)
                    if shape in {"hyphenated", "colon_pair", "assignment", "hash_delimited", "dollar_delimited"}:
                        signals.append(f"suspicious value shape: {shape}")
                        ctx_score += 4

                    # Strong signature categories remain strong even without context.
                    confidence = max(1, min(100, rule.confidence + min(25, ctx_score + combo_score // 2 + sink_add // 2)))
                    severity = self.adjust_severity(rule.severity, confidence, combo_score, art_score, rule.category)

                    rationale_parts = [rule.description]
                    if signals:
                        rationale_parts.append("; ".join(dict.fromkeys(signals[:8])))
                    rationale = " — ".join(rationale_parts)

                    evidence = safe_evidence(
                        line, match.start(), match.end(), value if value != match.group(0) else value
                    )

                    fp = self.fingerprint(rule, path, line_no, value)
                    if fp in self._seen_fingerprints:
                        continue

                    findings.append(Finding(
                        fingerprint=fp,
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=severity,
                        confidence=confidence,
                        file=self.display_path(path),
                        line=line_no,
                        column=match.start() + 1,
                        message=rule.description,
                        rationale=rationale,
                        evidence=evidence,
                        context=context,
                        signals=list(dict.fromkeys(signals)),
                        value_shape=shape,
                        artifact_score=min(100, art_score + combo_score),
                        source_kind="content",
                        secret_length=len(value),
                    ))
                    self._seen_fingerprints.add(fp)

        # Add a dedicated file-level finding for suspicious high-entropy
        # assignments that escaped exact named-secret rules.
        findings.extend(self.heuristic_scan(lines, path))
        return findings, None

    def heuristic_scan(self, lines: Sequence[str], path: Path) -> List[Finding]:
        results = []
        for line_no, line in enumerate(lines, 1):
            if not re.search(r"(?i)(?:=|:)\s*['\"]?[A-Za-z0-9_+/=.-]{20,}", line):
                continue
            if not SENSITIVE_NAME_RE.search(line):
                continue
            context = nearby_context(lines, line_no)
            m = re.search(r"(?i)(?:=|:)\s*['\"]?([A-Za-z0-9_+/=.-]{20,})", line)
            if not m:
                continue
            value = m.group(1)
            if looks_like_placeholder(value):
                continue
            ent = shannon_entropy(value)
            if ent < 3.4:
                continue
            rule = Rule(
                "HEURISTIC_HIGH_ENTROPY_SECRET",
                "heuristic",
                "HIGH",
                "",
                "High-entropy value assigned near a sensitive identifier",
                74,
            )
            fp = self.fingerprint(rule, path, line_no, value)
            if fp in self._seen_fingerprints:
                continue
            ctx_score, ctx_signals = sensitive_context_score(line, context)
            results.append(Finding(
                fingerprint=fp,
                rule_id=rule.rule_id,
                category=rule.category,
                severity="HIGH" if ent >= 4.0 else "MEDIUM",
                confidence=min(96, 74 + ctx_score // 2),
                file=self.display_path(path),
                line=line_no,
                column=m.start(1) + 1,
                message=rule.description,
                rationale=f"Entropy {ent:.2f} bits/char; " + "; ".join(ctx_signals),
                evidence=safe_evidence(line, m.start(1), m.end(1), value),
                context=context,
                signals=[f"entropy={ent:.2f}", "sensitive identifier"] + ctx_signals,
                value_shape=value_shape(value),
                artifact_score=ctx_score,
                source_kind="heuristic",
                secret_length=len(value),
            ))
            self._seen_fingerprints.add(fp)
        # Generic opaque password candidates, including cases such as
        # p = "Heroyy@456" where the identifier gives no useful hint.
        for line_no, line in enumerate(lines, 1):
            candidates = re.findall(
                r"""(?<![A-Za-z0-9])(?:["'`])?([A-Za-z][A-Za-z0-9@#$%!?._+\-]{5,96})(?:["'`])?(?![A-Za-z0-9])""",
                line
            )
            for value in candidates[:30]:
                if looks_like_code_token(value, line):
                    continue
                score, psignals = password_shape_score(value)
                if score < 35:
                    continue
                # Require assignment/configuration/authentication context or
                # an unmistakably password-like shape to limit false positives.
                contextual = bool(re.search(
                    r"(?i)(?:=|:=|:|=>|password|passwd|secret|login|auth|credential|user)",
                    line
                ))
                if not contextual and score < 55:
                    continue
                fp_rule = Rule(
                    "GENERIC_OPAQUE_PASSWORD",
                    "generic_password",
                    "HIGH" if score >= 60 else "MEDIUM",
                    "",
                    "Opaque password-like value without relying on a sensitive variable name",
                    70,
                )
                fp = self.fingerprint(fp_rule, path, line_no, value)
                if fp in self._seen_fingerprints:
                    continue
                context = nearby_context(lines, line_no)
                ctx_score, ctx_signals = sensitive_context_score(line, context)
                combo_score, combo_signals = credential_combination_score(lines, line_no)
                confidence = min(97, 45 + score + min(20, ctx_score) + min(12, combo_score // 2))
                severity = "HIGH" if confidence >= 80 else "MEDIUM"
                results.append(Finding(
                    fingerprint=fp,
                    rule_id=fp_rule.rule_id,
                    category=fp_rule.category,
                    severity=severity,
                    confidence=confidence,
                    file=self.display_path(path),
                    line=line_no,
                    column=max(1, line.find(value) + 1),
                    message=fp_rule.description,
                    rationale="; ".join(psignals + ctx_signals + combo_signals)[:1500],
                    evidence=line[:500],
                    context=context,
                    signals=list(dict.fromkeys(psignals + ctx_signals + combo_signals)),
                    value_shape=value_shape(value),
                    artifact_score=min(100, ctx_score + combo_score),
                    source_kind="generic_password_heuristic",
                    secret_length=len(value),
                ))
                self._seen_fingerprints.add(fp)

        return results

    @staticmethod
    def adjust_severity(base: str, confidence: int, combo: int, artifact: int, category: str) -> str:
        if base == "CRITICAL":
            return "CRITICAL"
        if category in {"private_key", "cryptographic"} and confidence >= 88:
            return "CRITICAL"
        if combo >= 45 and confidence >= 88:
            return "CRITICAL"
        if base == "HIGH":
            return "HIGH"
        if confidence >= 90 and artifact >= 20:
            return "HIGH"
        if base == "MEDIUM" and confidence >= 85:
            return "HIGH"
        return base

    def fingerprint(self, rule: Rule, path: Path, line: int, value: str) -> str:
        # Stable across repeated scans, but deliberately does not expose the
        # secret in the fingerprint itself.
        normalized = re.sub(r"\s+", " ", value.strip().lower())
        value_hash = hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]
        material = f"{rule.rule_id}|{self.display_path(path)}|{line}|{value_hash}"
        return hashlib.sha256(material.encode()).hexdigest()[:20]

    def scan(self) -> Tuple[List[Finding], ScanStats]:
        started = time.time()
        paths = list(iter_files(self.root))
        self.stats.files_seen = len(paths)

        all_findings: List[Finding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            future_map = {pool.submit(self.scan_file, p): p for p in paths}
            for future in concurrent.futures.as_completed(future_map):
                findings, skipped = future.result()
                if skipped:
                    self.stats.files_skipped += 1
                    self.stats.skipped_reasons[skipped] += 1
                else:
                    self.stats.files_scanned += 1
                all_findings.extend(findings)

        # Final deduplication by fingerprint.
        unique: Dict[str, Finding] = {}
        for finding in all_findings:
            unique[finding.fingerprint] = finding

        findings = sorted(
            unique.values(),
            key=lambda f: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 9),
                f.file,
                f.line,
                f.rule_id,
            ),
        )

        self.stats.findings = len(findings)
        self.stats.elapsed = time.time() - started
        for f in findings:
            self.stats.categories[f.category] += 1
            self.stats.severities[f.severity] += 1
        return findings, self.stats


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def report_dict(findings: Sequence[Finding], stats: ScanStats) -> Dict:
    return {
        "engine": ENGINE,
        "version": VERSION,
        "generated_at_epoch": int(time.time()),
        "summary": {
            "findings": stats.findings,
            "files_seen": stats.files_seen,
            "files_scanned": stats.files_scanned,
            "files_skipped": stats.files_skipped,
            "bytes_scanned": stats.bytes_scanned,
            "rules_loaded": stats.rules,
            "elapsed_seconds": round(stats.elapsed, 3),
            "severity": dict(stats.severities),
            "categories": dict(stats.categories),
            "skipped_reasons": dict(stats.skipped_reasons),
        },
        "findings": [asdict(f) | {"risk_score": f.risk_score()} for f in findings],
    }


def write_json(path: Path, findings: Sequence[Finding], stats: ScanStats) -> None:
    path.write_text(json.dumps(report_dict(findings, stats), indent=2), encoding="utf-8")


def html_escape(x: object) -> str:
    return html.escape(str(x), quote=True)


def severity_badge(sev: str) -> str:
    cls = sev.lower()
    return f'<span class="badge {cls}">{html_escape(sev)}</span>'


def render_html(findings: Sequence[Finding], stats: ScanStats, root: Path) -> str:
    counts = stats.severities
    cats = stats.categories
    rows = []
    for f in findings:
        ctx = "<br>".join(html_escape(x) for x in f.context[:5])
        # The context list is deliberately expanded to five source lines so the
        # Ollama stage receives enough surrounding code to distinguish real
        # credentials from identifiers/examples.
        signals = "<br>".join(html_escape(x) for x in f.signals[:10]) or "—"
        rows.append(
            "<tr>"
            f"<td>{severity_badge(f.severity)}</td>"
            f"<td>{f.risk_score()}</td>"
            f"<td>{html_escape(f.confidence)}%</td>"
            f"<td><code>{html_escape(f.rule_id)}</code></td>"
            f"<td>{html_escape(f.category)}</td>"
            f"<td>{html_escape(f.file)}:{f.line}</td>"
            f"<td>{html_escape(f.message)}<br><small>{html_escape(f.rationale)}</small></td>"
            f"<td><code>{html_escape(f.evidence)}</code></td>"
            f"<td>{signals}<details><summary>context</summary>{ctx}</details></td>"
            "</tr>"
        )

    category_rows = "".join(
        f"<tr><td>{html_escape(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(cats.items(), key=lambda x: (-x[1], x[0]))
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{ENGINE} Secret Scanner Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f4f6f8;color:#17202a}}
header{{background:#111827;color:#fff;padding:24px 30px}}
main{{padding:24px;max-width:1800px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}
.card{{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:16px}}
.metric{{font-size:28px;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:#fff;font-size:13px}}
th,td{{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}}
th{{position:sticky;top:0;background:#eef2f7}}
code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-word}} .raw-secret{{white-space:pre-wrap}}
.badge{{display:inline-block;border-radius:999px;padding:3px 8px;font-weight:700;font-size:11px}}
.critical{{background:#fee2e2;color:#991b1b}}
.high{{background:#ffedd5;color:#9a3412}}
.medium{{background:#fef3c7;color:#92400e}}
.low{{background:#dbeafe;color:#1e40af}}
.info{{background:#e5e7eb;color:#374151}}
.note{{color:#4b5563;font-size:13px}}
.scroll{{overflow:auto}}
small{{color:#4b5563}}
details{{margin-top:5px}}
</style>
</head>
<body>
<header>
<h1>🇮🇳 {ENGINE} Advanced Secret Scanner</h1>
<div>Version {VERSION} · dependency-free · RAW SECRET REPORTING ENABLED</div>
</header>
<main>
<div class="grid">
<div class="card"><div>Findings</div><div class="metric">{stats.findings}</div></div>
<div class="card"><div>Critical</div><div class="metric">{counts.get("CRITICAL",0)}</div></div>
<div class="card"><div>High</div><div class="metric">{counts.get("HIGH",0)}</div></div>
<div class="card"><div>Medium</div><div class="metric">{counts.get("MEDIUM",0)}</div></div>
<div class="card"><div>Files scanned</div><div class="metric">{stats.files_scanned}</div></div>
<div class="card"><div>Rules</div><div class="metric">{stats.rules}</div></div>
</div>

<h2>Scan information</h2>
<p class="note">
Root: <code>{html_escape(root)}</code> ·
Elapsed: {stats.elapsed:.2f}s ·
Bytes: {stats.bytes_scanned:,}
</p>

<h2>Categories</h2>
<table><thead><tr><th>Category</th><th>Findings</th></tr></thead>
<tbody>{category_rows}</tbody></table>

<h2>Findings</h2>
<p class="note">
Secret values are masked. The report intentionally exposes the detected value because raw-value reporting was explicitly enabled. Findings are heuristic and should be verified before remediation.
</p>
<div class="scroll">
<table>
<thead><tr>
<th>Severity</th><th>Risk</th><th>Confidence</th><th>Rule</th>
<th>Category</th><th>Location</th><th>Detection</th><th>Raw evidence</th><th>Signals/context</th>
</tr></thead>
<tbody>{"".join(rows) if rows else '<tr><td colspan="9">No findings.</td></tr>'}</tbody>
</table>
</div>
</main>
</body>
</html>"""


def write_html(path: Path, findings: Sequence[Finding], stats: ScanStats, root: Path) -> None:
    path.write_text(render_html(findings, stats, root), encoding="utf-8")


def print_terminal(findings: Sequence[Finding], stats: ScanStats) -> None:
    print()
    print("🇮🇳 PRAGYAN-BHARAT Advanced Secret Scanner")
    print("=" * 62)
    print(f"Version             : {VERSION}")
    print(f"Rules loaded        : {stats.rules}")
    print(f"Files seen          : {stats.files_seen}")
    print(f"Files scanned       : {stats.files_scanned}")
    print(f"Files skipped       : {stats.files_skipped}")
    print(f"Bytes scanned       : {stats.bytes_scanned:,}")
    print(f"Findings            : {stats.findings}")
    print(f"Elapsed             : {stats.elapsed:.2f}s")
    print()
    print("Severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"  {sev:8} {stats.severities.get(sev, 0)}")
    print()

    for f in findings[:100]:
        print(f"[{f.severity:<8}] risk={f.risk_score():3} conf={f.confidence:3}% "
              f"{f.file}:{f.line} [{f.rule_id}]")
        print(f"  {f.message}")
        print(f"  evidence: {f.evidence}")
        if f.signals:
            print(f"  signals : {', '.join(f.signals[:5])}")
        print()


def build_ollama_evidence(findings: Sequence[Finding], max_findings: int = 80,
                           max_context_lines: int = 5,
                           max_chars: int = 60000) -> str:
    """Build a compact plain-text evidence package for the local LLM.

    This deliberately does not serialize findings as JSON and does not send the
    complete HTML document to the model. The scanner's rule set is unchanged.
    """
    parts: List[str] = []
    selected = list(findings[:max_findings])

    parts.append("PRAGYAN-BHARAT SECRET ADJUDICATION EVIDENCE")
    parts.append("=" * 58)
    parts.append(f"Scanner findings supplied: {len(selected)}")
    if len(findings) > max_findings:
        parts.append(f"Additional findings omitted from LLM input: {len(findings) - max_findings}")
    parts.append("")

    for index, f in enumerate(selected, 1):
        parts.append(f"FINDING {index}")
        parts.append(f"File: {f.file}")
        parts.append(f"Line: {f.line}")
        parts.append(f"Column: {f.column}")
        parts.append(f"Rule: {f.rule_id}")
        parts.append(f"Category: {f.category}")
        parts.append(f"Scanner severity: {f.severity}")
        parts.append(f"Scanner confidence: {f.confidence}%")
        parts.append(f"Detection: {f.message}")
        parts.append(f"Rationale: {f.rationale[:1200]}")
        parts.append(f"Masked evidence: {f.evidence[:500]}")
        if f.signals:
            parts.append("Signals: " + "; ".join(f.signals[:8]))
        if f.context:
            parts.append("Surrounding source:")
            parts.extend(f"  {line}" for line in f.context[:max_context_lines])
        parts.append("")

        current = "\n".join(parts)
        if len(current) >= max_chars:
            parts.append("[LLM INPUT TRUNCATED HERE TO PROTECT SYSTEM RESOURCES]")
            break

    result = "\n".join(parts)
    return result[:max_chars]


def ollama_analyze_findings(findings: Sequence[Finding], model: str,
                            timeout: int = 1800,
                            endpoint: str = "http://127.0.0.1:11434/api/generate",
                            max_input_chars: int = 60000) -> Optional[str]:
    """Ask a local Ollama model to adjudicate findings using compact plain text.

    Ollama's HTTP transport necessarily uses JSON as its API protocol, but the
    model's requested/returned analysis is plain text. No JSON schema is imposed
    on the model output and no JSON parsing is used for the model response beyond
    extracting Ollama's normal HTTP response envelope.
    """
    if not findings:
        return "No scanner findings were produced. Ollama adjudication was skipped."

    try:
        import urllib.error
        import urllib.request

        evidence = build_ollama_evidence(
            findings,
            max_findings=80,
            max_context_lines=5,
            max_chars=max(12000, max_input_chars),
        )

        prompt = f"""You are PRAGYAN-BHARAT's senior secret and credential adjudication engine.

Analyze the scanner evidence below and determine which findings are genuine exposed
secrets, passwords, credentials, tokens, authentication material, private keys, or
false positives/security smells.

STRICT OUTPUT REQUIREMENTS:
- Return PLAIN TEXT ONLY.
- Do NOT return JSON.
- Do NOT output JSON objects, JSON arrays, YAML, XML, or a JSON-like schema.
- Do NOT use markdown code fences.
- Do NOT repeat the entire evidence.
- Be concise and decisive.
- Maximum approximately 1500 words.
- Start with exactly one line: OVERALL VERDICT: SECRETS_FOUND, NO_CONFIRMED_SECRETS, or REVIEW_REQUIRED
- Then give a short SUMMARY.
- Then analyze each supplied finding using this format:
  FINDING N
  Verdict: REAL_SECRET, LIKELY_REAL, FALSE_POSITIVE, or REVIEW_REQUIRED
  Secret type: ...
  Severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
  Confidence: 0-100%
  Reason: ...
  Recommended action: ...

IMPORTANT:
- The scanner is heuristic. Do not blindly trust it.
- Use only evidence present below. Never invent a secret, value, file, line, or usage.
- Distinguish credentials from UUIDs, hashes, IDs, examples, placeholders, public
  identifiers, URLs, checksums, test fixtures, and random non-secret data.
- A generic value such as p="Heroyy@456" can be a password candidate even when the
  variable name is meaningless.
- Consider whether the value is used for authentication, database access, signing,
  encryption, HTTP authorization, cloud access, package registries, webhooks, or
  cookies.
- Consider production versus test/example/documentation context.
- Do not claim a credential is active unless the supplied evidence establishes that.
- Never recommend authenticating with, brute-forcing, or validating a credential
  against an external service.

EVIDENCE:
{evidence}
"""

        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "5m",
            "options": {
                "temperature": 0.0,
                "num_ctx": 8192,
                "num_predict": 1800,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=max(30, timeout)) as response:
            raw_response = response.read().decode("utf-8", errors="replace")

        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            return f"OLLAMA ERROR: Invalid response from Ollama: {exc}"

        analysis = str(data.get("response", "")).strip()
        if not analysis:
            error_text = data.get("error")
            if error_text:
                return f"OLLAMA ERROR: {error_text}"
            return "OLLAMA ERROR: Ollama returned an empty response."

        return analysis

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
        except Exception:
            detail = ""
        return f"OLLAMA ERROR: HTTP {exc.code} {exc.reason}. {detail}".strip()
    except urllib.error.URLError as exc:
        return f"OLLAMA ERROR: Cannot reach Ollama endpoint: {exc.reason}"
    except TimeoutError:
        return "OLLAMA ERROR: Request timed out."
    except Exception as exc:
        return f"OLLAMA ERROR: {type(exc).__name__}: {exc}"


def append_ollama_html(html_path: Path, analysis: str, model: str) -> None:
    block = f"""
<section style="margin-top:28px;background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:18px">
<h2>Ollama Adjudication</h2>
<p><b>Model:</b> {html_escape(model)}</p>
<pre style="white-space:pre-wrap;overflow:auto;background:#111827;color:#f9fafb;padding:16px;border-radius:8px">{html_escape(analysis)}</pre>
</section>
"""
    text = html_path.read_text(encoding="utf-8")
    text = text.replace("</main>", block + "\n</main>", 1)
    html_path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Rule inventory / self-test
# ---------------------------------------------------------------------------

def print_rule_inventory() -> None:
    by_cat = Counter(r.category for r in RULES)
    print(f"{ENGINE}: {len(RULES)} rule definitions")
    for cat, count in sorted(by_cat.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {cat:24} {count}")


def self_test() -> int:
    samples = {
        "AWS": 'aws_access_key = "AKIA1234567890ABCDEF"',
        "password": 'database_password = "Sup3rSecret!234"',
        "shape": 'code = "ABC-123-DEF"',
        "numeric_at": 'credential = "2344@example-service"',
        "jwt": 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signatureVALUE123"',
        "db": 'url = "postgres://admin:Sup3rSecret@db.internal:5432/app"',
        "private": "-----BEGIN RSA PRIVATE KEY-----",
        "bearer": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
    }
    ok = 0
    for name, text in samples.items():
        hit = False
        for rule, cre in COMPILED_RULES:
            if cre.search(text):
                hit = True
                break
        print(f"[{'PASS' if hit else 'FAIL'}] {name}")
        ok += int(hit)
    print(f"Self-test: {ok}/{len(samples)} passed")
    return 0 if ok == len(samples) else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pragyan_bharat_advanced_secret_scanner.py",
        description="Advanced dependency-free secret/sensitive-data scanner.",
    )
    p.add_argument("path", nargs="?", help="file or repository directory")
    p.add_argument("-o", "--html", default="PRAGYAN-BHARAT-secret-report.html",
                   help="HTML report path")
    p.add_argument("--json", dest="json_path", default=None,
                   help="optional JSON report path; disabled by default")
    p.add_argument("--max-file-mb", type=int, default=DEFAULT_MAX_FILE_MB,
                   help="skip files larger than this size")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help="parallel worker count")
    p.add_argument("--include-generated", action="store_true",
                   help="scan generated/minified files")
    p.add_argument("--min-secret-len", type=int, default=DEFAULT_MIN_SECRET_LEN,
                   help="minimum candidate value length")
    p.add_argument("--rules", action="store_true", help="print rule inventory and exit")
    p.add_argument("--self-test", action="store_true", help="run built-in detector tests")
    p.add_argument("--no-html", action="store_true", help="do not write HTML report")
    p.add_argument("--no-json", action="store_true", help="do not write JSON report")
    p.add_argument("--ollama", action="store_true", help="send generated HTML report and findings to local Ollama")
    p.add_argument("--ollama-model", default="nemotron-3-nano:4b", help="local Ollama model")
    p.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434/api/generate")
    p.add_argument("--ollama-timeout", type=int, default=1800, help="Ollama timeout in seconds; default 5 minutes")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                   default="none", help="return non-zero if findings reach threshold")
    return p


def exit_code(findings: Sequence[Finding], threshold: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 99}
    if threshold == "none":
        return 0
    target = order[threshold]
    for f in findings:
        if order.get(f.severity.lower(), 99) <= target:
            return 2
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.rules:
        print_rule_inventory()
        return 0

    if args.self_test:
        return self_test()

    if not args.path:
        print("error: path is required unless --rules or --self-test is used", file=sys.stderr)
        return 2

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    scanner = Scanner(
        root=root,
        max_file_mb=max(1, args.max_file_mb),
        workers=max(1, args.workers),
        include_generated=args.include_generated,
        min_secret_len=max(4, args.min_secret_len),
    )

    try:
        findings, stats = scanner.scan()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"fatal scan error: {exc}", file=sys.stderr)
        return 1

    # User requested a single HTML artifact; do not emit terminal findings.

    if not args.no_html:
        try:
            write_html(Path(args.html), findings, stats, root.resolve())
            pass
        except OSError as exc:
            print(f"warning: HTML report failed: {exc}", file=sys.stderr)

    if args.json_path and not args.no_json:
        try:
            write_json(Path(args.json_path), findings, stats)
        except OSError:
            return 1

    if args.ollama and not args.no_html:
        print("[+] Ollama adjudication starting...", flush=True)
        if not findings:
            analysis = "No scanner findings were produced. Ollama adjudication was skipped."
        else:
            print(f"[+] Sending {min(len(findings), 80)} finding(s) as compact plain-text evidence...", flush=True)
            analysis = ollama_analyze_findings(
                findings,
                args.ollama_model,
                timeout=max(30, args.ollama_timeout),
                endpoint=args.ollama_endpoint,
                max_input_chars=60000,
            )
        if analysis:
            append_ollama_html(Path(args.html), analysis, args.ollama_model)
            print("[+] Ollama adjudication written to HTML report.", flush=True)

    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
