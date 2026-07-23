"""
Nexus AI — Log Parser & PII Sanitizer
"""
import re
from typing import Dict, List


class LogSanitizer:
    """Sanitizes security logs by removing PII and sensitive data."""

    PII_PATTERNS = [
        (r'password[=:]\s*\S+', 'password=***REDACTED***'),
        (r'passwd[=:]\s*\S+', 'passwd=***REDACTED***'),
        (r'api[_-]?key[=:]\s*\S+', 'api_key=***REDACTED***'),
        (r'token[=:]\s*\S+', 'token=***REDACTED***'),
        (r'secret[=:]\s*\S+', 'secret=***REDACTED***'),
        (r'credential[=:]\s*\S+', 'credential=***REDACTED***'),
        (r'auth[_-]?token[=:]\s*\S+', 'auth_token=***REDACTED***'),
        (r'Bearer\s+\S+', 'Bearer ***REDACTED***'),
        (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic ***REDACTED***'),
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', '***PRIVATE_KEY_REDACTED***'),
    ]

    @classmethod
    def sanitize(cls, log_text: str) -> str:
        """Remove PII and sensitive data from log text."""
        sanitized = log_text
        for pattern, replacement in cls.PII_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        return sanitized

    @classmethod
    def get_stats(cls, log_text: str) -> Dict:
        lines = log_text.split('\n')
        return {
            "total_lines": len(lines),
            "total_chars": len(log_text),
            "file_size_kb": round(len(log_text.encode('utf-8')) / 1024, 2)
        }


log_sanitizer = LogSanitizer()
