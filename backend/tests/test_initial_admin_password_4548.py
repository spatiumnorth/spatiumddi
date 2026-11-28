"""The first ``admin`` user can start on a password handed in at install (#4548).

The appliance installer collects the web UI password and firstboot hands its
bcrypt hash to the api (INITIAL_ADMIN_PASSWORD_HASH). Without it the account is
the built-in admin / admin with a forced change, which is unchanged.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.config import settings
from app.core.security import hash_password, verify_password
from app.main import _seed_default_admin
from app.models.auth import User
from app.services.support_bundle.scrub import render_env


class _Session:
    """Stands in for ``AsyncSessionLocal()``: yields the test session."""

    def __init__(self, session) -> None:
        self._s = session

    def __call__(self):
        return self

    async def __aenter__(self):
        return self._s

    async def __aexit__(self, *exc) -> bool:
        return False


async def _seed(db_session, monkeypatch, hash_value: str) -> User:
    monkeypatch.setattr("app.db.AsyncSessionLocal", _Session(db_session))
    monkeypatch.setattr(settings, "demo_mode", False)
    monkeypatch.setattr(settings, "initial_admin_password_hash", hash_value)
    await _seed_default_admin()
    return (await db_session.execute(select(User).where(User.username == "admin"))).scalar_one()


async def test_seed_uses_the_handed_over_hash_without_a_forced_change(
    db_session, monkeypatch
) -> None:
    chosen = hash_password("installer-chosen-pw")
    admin = await _seed(db_session, monkeypatch, chosen)
    assert admin.hashed_password == chosen
    assert verify_password("installer-chosen-pw", admin.hashed_password)
    assert not verify_password("admin", admin.hashed_password)
    assert admin.force_password_change is False
    assert admin.is_superadmin is True


async def test_seed_without_a_hash_is_still_admin_admin_with_forced_change(
    db_session, monkeypatch
) -> None:
    admin = await _seed(db_session, monkeypatch, "")
    assert verify_password("admin", admin.hashed_password)
    assert admin.force_password_change is True


@pytest.mark.parametrize("bad", ["not-a-hash", "$6$salt$sha512crypt", "$2b$12$short"])
async def test_seed_ignores_a_value_that_is_not_a_bcrypt_hash(
    db_session, monkeypatch, bad: str
) -> None:
    """A malformed value must not create an account nobody can log into."""
    admin = await _seed(db_session, monkeypatch, bad)
    assert verify_password("admin", admin.hashed_password)
    assert admin.force_password_change is True


async def test_seed_does_not_touch_an_existing_user_table(db_session, monkeypatch) -> None:
    first = await _seed(db_session, monkeypatch, hash_password("one"))
    await _seed_default_admin()  # a second boot: users exist, so nothing changes
    again = (await db_session.execute(select(User))).scalars().all()
    assert len(again) == 1 and again[0].hashed_password == first.hashed_password


def test_the_hash_env_var_is_redacted_in_a_support_bundle() -> None:
    value = hash_password("whatever-pw")
    out = render_env({"INITIAL_ADMIN_PASSWORD_HASH": value}, lambda v: v)
    assert value not in out


async def test_a_malformed_hash_is_warned_about_without_the_value(db_session, monkeypatch) -> None:
    import app.main as main_mod

    events: list[tuple[str, dict]] = []

    class _Log:
        def __getattr__(self, _name):
            return lambda event, **kw: events.append((event, kw))

    monkeypatch.setattr(main_mod, "logger", _Log())
    await _seed(db_session, monkeypatch, "$6$salt$sha512crypt")
    ignored = [kw for ev, kw in events if ev == "initial_admin_password_hash_ignored"]
    assert ignored and "sha512crypt" not in str(ignored)
