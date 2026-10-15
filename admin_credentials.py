from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_MAX_LENGTH = 128
ADMIN_PASSWORD_LIFETIME_DAYS = 7


def admin_login_subject_hash(user_id: str) -> str:
    """Return a non-secret linkage key for privacy export and deletion."""
    identifier = user_id.strip().upper().encode("utf-8")
    return hashlib.sha256(b"stoatmod-admin-login-subject\0" + identifier).hexdigest()


def generate_temporary_password() -> str:
    """Generate a copy-safe random password without ambiguous punctuation."""
    return f"SM-{secrets.token_urlsafe(24)}"


def hash_password(password: str) -> str:
    salt = hashlib.sha256(
        b"stoatmod-admin-password-salt\0" + secrets.token_bytes(32)
    ).digest()[:16]
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_HASH_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if not 300_000 <= iterations <= 2_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False
