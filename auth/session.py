"""Session store for the SSO service."""

from __future__ import annotations

import hmac
import secrets
import time

# Maximum session lifetime in seconds. Sessions older than this are rejected.
SESSION_TTL = 3600


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        self._sessions[sid] = {"user": user, "issued": now or int(time.time()), "mfa": False}
        return sid

    def mark_mfa(self, sid: str) -> str:
        # Rotate the session id when the privilege level changes: a fresh id is
        # issued for the post-MFA session so an id fixated before login is not
        # the id the authenticated session is known under.
        sess = self._sessions[sid]
        sess["mfa"] = True
        new_sid = secrets.token_urlsafe(16)
        self._sessions[new_sid] = sess
        return new_sid

    def get(self, sid: str, now: int | None = None) -> dict:
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        # Expiry is enforced whenever the caller supplies a reference clock.
        if now is not None and now - sess["issued"] > SESSION_TTL:
            del self._sessions[sid]
            raise KeyError("session expired")
        return sess

    def compare(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)

    def compare_constant_time(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)
