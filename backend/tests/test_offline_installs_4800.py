"""#4800 — offline installs: the MAC vendor refresh and the release check.

* A failed OUI fetch is a FAILED task (it used to return ``status: error`` as a
  SUCCESS), is recorded for the Settings card, and backs the hourly beat tick
  off for a day so an offline install logs once a day.
* The release check run at beat start finds no settings row on a fresh
  install; it retries until the row exists instead of waiting for the 24 h tick.
* The supervisor heartbeat accepts the ``update-stale`` APT state.
"""

from __future__ import annotations

import contextlib
from datetime import timedelta

import httpx
import pytest
from celery.exceptions import Retry
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance.supervisor import SupervisorHeartbeatRequest
from app.api.v1.settings.router import get_oui_status
from app.models.settings import PlatformSettings
from app.tasks import oui_update, update_check


class _NullEngine:
    async def dispose(self) -> None:
        return None


def _wire_oui(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, fetches: list[int]
) -> None:
    class _Client:
        def __init__(self, *a: object, **kw: object) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def get(self, _url: str) -> None:
            fetches.append(1)
            raise httpx.ConnectError("Temporary failure in name resolution")

    monkeypatch.setattr(oui_update.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(oui_update, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(oui_update, "async_sessionmaker", lambda *a, **kw: _factory_cm)


async def test_oui_fetch_failure_fails_the_task_and_backs_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_session.add(PlatformSettings(id=1, oui_lookup_enabled=True))
    await db_session.commit()
    fetches: list[int] = []
    _wire_oui(monkeypatch, db_session, fetches)

    with pytest.raises(oui_update.OUIUpdateError):
        await oui_update._run_update(force=False)
    assert fetches == [1]

    status = await get_oui_status(None, db_session)  # type: ignore[arg-type]
    assert status.last_error_at is not None
    assert "name resolution" in (status.last_error or "")

    # The next hourly tick leaves the source alone.
    again = await oui_update._run_update(force=False)
    assert again["status"] == "skipped"
    assert fetches == [1]

    # A manual refresh ignores the backoff and fails loudly again.
    with pytest.raises(oui_update.OUIUpdateError):
        await oui_update._run_update(force=True)
    assert fetches == [1, 1]

    # Once the backoff has passed the tick tries again.
    monkeypatch.setattr(oui_update, "FAILURE_BACKOFF", timedelta(0))
    with pytest.raises(oui_update.OUIUpdateError):
        await oui_update._run_update(force=False)
    assert len(fetches) == 3


def test_release_check_retries_until_the_settings_row_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _no_row() -> dict[str, str]:
        return {"status": "no_settings_row"}

    class _Retry(Retry):
        pass

    seen: dict[str, object] = {}

    def _retry(**kw: object) -> Exception:
        seen.update(kw)
        return _Retry()

    monkeypatch.setattr(update_check, "_run_check", _no_row)
    monkeypatch.setattr(update_check.check_github_release, "retry", _retry)
    with pytest.raises(_Retry):
        update_check.check_github_release.run()
    assert seen["countdown"] == update_check._NO_ROW_RETRY_SECONDS


def test_release_check_does_not_retry_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _off() -> dict[str, str]:
        return {"status": "disabled"}

    def _boom(**kw: object) -> Exception:
        raise AssertionError("a switched-off check must not retry")

    monkeypatch.setattr(update_check, "_run_check", _off)
    monkeypatch.setattr(update_check.check_github_release, "retry", _boom)
    assert update_check.check_github_release.run() == {"status": "disabled"}


def test_heartbeat_accepts_the_stale_apt_state() -> None:
    annotation = SupervisorHeartbeatRequest.model_fields["apt_state"].annotation
    assert "update-stale" in str(annotation)
