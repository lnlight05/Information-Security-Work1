"""Password hashing, JWT issuing/verification, and output escaping.

Everything security-related lives here so the rules are in one place.
"""

import hashlib
import hmac
import html
import os
import time

import jwt

# In production this comes from the environment / a secret store, never from source.
# The default is >= 32 bytes because PyJWT warns that a shorter HS256 key weakens the MAC.
SECRET_KEY = os.environ.get("APP_SECRET", "dev-only-secret-change-me-do-not-ship-this")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 3600

# scrypt parameters (N=2^14, r=8, p=1 -> ~16 MiB per hash).
# The manual allows bcrypt, scrypt or Argon2; scrypt ships with the standard library,
# so the project needs no compiler and no native wheel.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
HASH_PREFIX = "scrypt"


def hash_password(password: str) -> str:
    """Return ``scrypt$<salt>$<derived key>`` -- never the plaintext."""
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"{HASH_PREFIX}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time comparison of the derived key."""
    try:
        prefix, salt_hex, expected_hex = stored.split("$")
        if prefix != HASH_PREFIX:
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=32,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived.hex(), expected_hex)


def issue_token(user) -> str:
    """Signed JWT: who the user is (sub), plus issued-at / expiry."""
    now = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Verify signature and expiry. Raises jwt.PyJWTError when invalid."""
    # algorithms=[...] is mandatory: without it PyJWT rejects the token, and pinning
    # the list blocks the "alg: none" and algorithm-confusion attacks.
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


def escape(value) -> str:
    """HTML-escape any value that goes into a response (XSS defence)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)
