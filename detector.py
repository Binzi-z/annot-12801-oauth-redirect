"""Attack-surface detector for the SSO service.

Replays each of the four audit findings against the live code and reports
whether the attack still bypasses the validation. Each check maps 1:1 to a
security test in tests/test_auth.py; legitimate flows are exercised alongside
to confirm the fix produces no false positives.

Usage: python detector.py
Exit code 0 = every attack is blocked; 1 = at least one bypass succeeded.
"""

from __future__ import annotations

import inspect
import sys

from auth import totp as totp_mod
from auth.session import SessionStore
from auth.totp import totp, verify

# The used-code registry only exists after the replay fix; fall back to a
# throwaway dict so the detector also runs against the vulnerable baseline.
_used_codes = getattr(totp_mod, "_used_codes", {})

SECRET = b"12345678901234567890"
NOW = 1_700_000_000

failures = 0


def report(case: str, bypassed: bool, detail: str) -> None:
    global failures
    if bypassed:
        failures += 1
    verdict = "BYPASSED (vulnerable)" if bypassed else "blocked"
    print(f"[{case}] {verdict}: {detail}")


def check_totp_replay() -> None:
    """Attacker captures the victim's TOTP code and replays it in-window."""
    _used_codes.clear()
    code = totp(SECRET, at=NOW)
    first = verify(SECRET, code, at=NOW)       # victim logs in
    replay = verify(SECRET, code, at=NOW)      # attacker replays the same code
    report(
        "totp-replay",
        bypassed=not (first and not replay),
        detail=f"first use accepted={first}, replay of same code accepted={replay}",
    )
    # Legitimate use must not be flagged: a fresh code for the next step works.
    _used_codes.clear()
    legit = verify(SECRET, totp(SECRET, at=NOW), at=NOW)
    report(
        "totp-replay/legit",
        bypassed=not legit,
        detail=f"fresh legitimate code accepted={legit} (false positive if False)",
    )


def check_session_fixation() -> None:
    """Attacker fixates a session id before the victim completes MFA."""
    store = SessionStore()
    sid = store.create("alice", now=NOW)
    new_sid = store.mark_mfa(sid)
    rotates = bool(new_sid) and new_sid != sid
    report(
        "session-fixation",
        bypassed=not rotates,
        detail=f"mark_mfa issued new id={new_sid!r}; rotation={'yes' if rotates else 'no'}",
    )


def check_session_expiry() -> None:
    """Attacker reuses a stolen session id long after it was issued."""
    store = SessionStore()
    sid = store.create("alice", now=1000)
    try:
        store.get(sid, now=1000 + 7200)
        expired_accepted = True
    except KeyError:
        expired_accepted = False
    report(
        "session-expiry",
        bypassed=expired_accepted,
        detail=f"session issued at t=1000 still accepted at t=8200: {expired_accepted}",
    )
    # Legitimate use must not be flagged: a fresh session is accepted.
    store2 = SessionStore()
    sid2 = store2.create("bob", now=1000)
    try:
        store2.get(sid2, now=1000 + 60)
        legit = True
    except KeyError:
        legit = False
    report(
        "session-expiry/legit",
        bypassed=not legit,
        detail=f"60-second-old session accepted={legit} (false positive if False)",
    )


def check_constant_time_compare() -> None:
    """Attacker measures comparison timing to recover a secret byte-by-byte."""
    store = SessionStore()
    has_ct = hasattr(store, "compare_constant_time")
    src = inspect.getsource(SessionStore.compare)
    ct_impl = "compare_digest" in src
    correct = (
        has_ct
        and store.compare("abc", "abd") is False
        and store.compare("abc", "abc") is True
        and store.compare_constant_time("abc", "abd") is False
    )
    report(
        "timing-compare",
        bypassed=not (has_ct and ct_impl and correct),
        detail=(
            f"compare_constant_time present={has_ct}, "
            f"compare uses hmac.compare_digest={ct_impl}, results correct={correct}"
        ),
    )


def main() -> int:
    _used_codes.clear()
    check_totp_replay()
    check_session_fixation()
    check_session_expiry()
    check_constant_time_compare()
    print()
    if failures:
        print(f"{failures} check(s) show a bypass or false positive")
        return 1
    print("all attacks blocked, no false positives on legitimate flows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
