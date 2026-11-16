"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


# Replay protection: successfully verified codes mapped to the counter at
# which they were consumed. Entries are purged once they fall outside the
# verification window, so the registry stays bounded.
_used_codes: dict[tuple[bytes, str], int] = {}


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one.

    A code that has already been verified successfully is rejected: each
    TOTP code is single-use within its validity window.
    """
    now = int((at or time.time()) // step)
    # Drop records whose counter can no longer match the (now-1, now) window.
    for key, counter in list(_used_codes.items()):
        if counter < now - 1:
            del _used_codes[key]
    for counter in (now - 1, now):
        if hmac.compare_digest(hotp(secret, counter), code):
            key = (secret, code)
            if key in _used_codes:
                return False
            _used_codes[key] = counter
            return True
    return False
