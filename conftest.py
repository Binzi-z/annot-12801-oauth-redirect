"""Shared pytest fixtures."""

import pytest

from auth import totp


@pytest.fixture(autouse=True)
def reset_totp_replay_cache():
    """Give every test a fresh used-code registry.

    The replay registry in auth.totp is process-global (as it would be in
    production, where it backs a real single-use guarantee). Tests exercise
    the same secret/code at the same timestamp in different cases, so each
    test needs its own empty registry to stay isolated.
    """
    totp._used_codes.clear()
    yield
    totp._used_codes.clear()
