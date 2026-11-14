import hashlib
import hmac
import html
import re
from typing import Any, Dict, Iterable, Optional


class SecurityViolationError(Exception):
    """Raised when a payload violates XR6 Filter Wall security policies."""


def compute_sha256(payload: str) -> str:
    """Compute a lowercase hexadecimal SHA-256 digest for a UTF-8 string."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_sha256(payload: str, expected_hex: str) -> bool:
    """Constant-time verification of a SHA-256 digest."""
    actual = compute_sha256(payload)
    return hmac.compare_digest(actual, expected_hex.strip().lower())


class FilterWall:
    """Zero-Trust input sanitization and cryptographic integrity firewall."""

    DEFAULT_BLOCK_PATTERNS = (
        r"<\s*script\b",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"(\bUNION\b.+\bSELECT\b|\bDROP\b.+\bTABLE\b)",
    )

    def __init__(
        self,
        allowed_fields: Optional[Iterable[str]] = None,
        max_length: int = 10_000,
        strict: bool = True,
    ) -> None:
        self.allowed_fields = set(allowed_fields) if allowed_fields else None
        self.max_length = max_length
        self.strict = strict
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.DEFAULT_BLOCK_PATTERNS]

    def inspect_text(self, text: str) -> str:
        if len(text) > self.max_length:
            raise SecurityViolationError(f"Payload exceeds maximum length ({self.max_length}).")

        for pattern in self._compiled:
            if pattern.search(text):
                if self.strict:
                    raise SecurityViolationError("Malicious pattern detected by XR6 Filter Wall.")
                return html.escape(text, quote=True)

        return text.strip()

    def filter_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}
        for key, value in data.items():
            if self.allowed_fields is not None and key not in self.allowed_fields:
                if self.strict:
                    raise SecurityViolationError(f"Unauthorized field: '{key}'.")
                continue

            if isinstance(value, str):
                cleaned[key] = self.inspect_text(value)
            else:
                cleaned[key] = value
        return cleaned
