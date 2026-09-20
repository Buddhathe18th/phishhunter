"""Security primitives: input validation, SSRF guard, auth, rate limiting, response headers."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9_-]{1,30}[a-z0-9]$")

# scrypt parameters: N=2**14 (CPU/memory cost), r=8, p=1 - OWASP's current baseline recommendation for
# interactive login (not a batch job), using the standard library so no new dependency is needed.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN = 2**14, 8, 1, 32


def clean_username(raw: object) -> str | None:
    """2-32 chars, lowercase letters/digits/hyphen/underscore, must start and end alphanumeric."""
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    return value if _USERNAME.match(value) else None


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Returns (salt_hex, hash_hex). Pass the stored salt back in to verify a login attempt."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    try:
        _, candidate_hex = hash_password(password, bytes.fromhex(salt_hex))
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(candidate_hex, expected_hash_hex)


def hash_token(token: str) -> str:
    """Tokens are bearer credentials, so only their hash is ever stored - identical treatment to a password,
    just SHA-256 instead of scrypt, since a token is already high-entropy random data, not a human-chosen secret.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def clean_domain(raw: object) -> str | None:
    """Return a normalised hostname, or None if it isn't a plausible public DNS name.

    Domains come from certificates anyone can obtain, so they are attacker-controlled input. Everything
    downstream (queries, reports, file names, prompts) only ever sees strings that passed this check.
    """
    if not isinstance(raw, str) or len(raw) > 260:
        return None
    domain = raw.strip().lower()
    while domain.startswith("*."):
        domain = domain[2:]
    domain = domain.rstrip(".")
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():  # bare IPv4
        return None
    return domain


def clean_text(value: object, max_len: int) -> str:
    """Strip control characters and cap length. Used on every untrusted string we store or display."""
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub("", value)[:max_len]


def is_public_ip(address: str) -> bool:
    """True only for globally routable addresses (blocks loopback, RFC1918, link-local, CGNAT, metadata IPs...)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def origin_allowed(origin: str | None, host: str | None, extra: frozenset[str]) -> bool:
    """WebSocket origin check. Browsers always send Origin; non-browser clients have to pass token auth anyway."""
    if origin is None:
        return True
    if origin.lower() in extra:
        return True
    return bool(host) and urlparse(origin).netloc.lower() == host.lower()


def token_matches(supplied: str | None, expected: str) -> bool:
    if not supplied:
        return False
    return secrets.compare_digest(supplied.encode(), expected.encode())


class RateLimiter:
    """Sliding-window limiter keyed by client address (we never trust X-Forwarded-For)."""

    def __init__(self, limit: int, window: float = 60.0, max_keys: int = 10_000) -> None:
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if len(self._hits) > self.max_keys:
            self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window})
        q = self._hits[key]
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
