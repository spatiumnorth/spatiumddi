"""#2325 — Domains own a feature module, and it is the off switch for RDAP.

A Domain row triggers off-prem RDAP lookups, so ``network.domains`` must
stop them all: the API answers 404 and neither the hourly beat sweep nor
the one-shot refresh queued at create time makes a lookup. Disabled is
stated with a row, not inherited from the shipped default (#1069).
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.domain import Domain
from app.models.feature_module import FeatureModule
from app.services import feature_modules


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _set_module(db: AsyncSession, enabled: bool) -> None:
    db.add(FeatureModule(id="network.domains", enabled=enabled))
    await db.flush()
    feature_modules.invalidate_cache()


def _patch_task_session(monkeypatch: pytest.MonkeyPatch, db: AsyncSession) -> None:
    import app.tasks.domain_whois_refresh as task_mod

    @asynccontextmanager
    async def _fake():  # type: ignore[no-untyped-def]
        yield db

    monkeypatch.setattr(task_mod, "task_session", _fake)


def _count_lookups(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    import app.tasks.domain_whois_refresh as task_mod

    calls: list[str] = []

    async def _fake_refresh(d: Domain, **kw: Any) -> Any:
        calls.append(d.name)
        raise RuntimeError("stop after counting")  # per-row failure is isolated

    monkeypatch.setattr(task_mod, "refresh_one_domain", _fake_refresh)

    async def _tlds(db: Any) -> Any:
        class _R:
            tlds: frozenset[str] = frozenset()

        return _R()

    monkeypatch.setattr(task_mod, "effective_registry", _tlds)
    return calls


@pytest.mark.asyncio
async def test_api_404_when_module_off_and_200_when_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    await _set_module(db_session, False)
    await db_session.commit()
    assert (await client.get("/api/v1/domains", headers=h)).status_code == 404
    assert (
        await client.post("/api/v1/domains", json={"name": "example.com"}, headers=h)
    ).status_code == 404

    row = await db_session.get(FeatureModule, "network.domains")
    row.enabled = True
    await db_session.commit()
    feature_modules.invalidate_cache()
    assert (await client.get("/api/v1/domains", headers=h)).status_code == 200


@pytest.mark.asyncio
async def test_beat_sweep_makes_no_lookup_when_module_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.domain_whois_refresh as task_mod

    db_session.add(Domain(name="due.example.com"))
    await _set_module(db_session, False)
    _patch_task_session(monkeypatch, db_session)
    calls = _count_lookups(monkeypatch)

    result = await task_mod._refresh_due_async()
    assert calls == []
    assert result["status"] == "skipped"


@pytest.mark.asyncio
async def test_beat_sweep_looks_up_due_domains_when_module_on(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.domain_whois_refresh as task_mod

    db_session.add(Domain(name="due.example.com"))
    await _set_module(db_session, True)
    _patch_task_session(monkeypatch, db_session)
    calls = _count_lookups(monkeypatch)

    await task_mod._refresh_due_async()
    assert calls == ["due.example.com"]


@pytest.mark.asyncio
async def test_queued_one_shot_refresh_makes_no_lookup_when_module_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.domain_whois_refresh as task_mod

    d = Domain(name="queued.example.com")
    db_session.add(d)
    await _set_module(db_session, False)
    await db_session.flush()
    _patch_task_session(monkeypatch, db_session)
    calls = _count_lookups(monkeypatch)

    result = await task_mod._refresh_one_by_id_async(str(d.id))
    assert calls == []
    assert result["status"] == "skipped"


# ── Shipped-default resolution (default_on_if_rows_in="domain") ──────


@pytest.fixture
def _domains_shipped_default() -> Iterator[None]:
    """Restore ``network.domains``'s shipped default-off (conftest patches all on)."""
    before_modules, before_by_id = feature_modules.MODULES, feature_modules.MODULES_BY_ID
    patched = tuple(
        dataclasses.replace(m, default_enabled=False) if m.id == "network.domains" else m
        for m in before_modules
    )
    feature_modules.MODULES = patched
    feature_modules.MODULES_BY_ID = {m.id: m for m in patched}
    feature_modules.invalidate_cache()
    try:
        yield
    finally:
        feature_modules.MODULES, feature_modules.MODULES_BY_ID = before_modules, before_by_id
        feature_modules.invalidate_cache()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_domains_shipped_default")
async def test_fresh_install_is_off_404_and_no_lookups(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.domain_whois_refresh as task_mod

    h = await _admin(db_session)
    await db_session.commit()
    feature_modules.invalidate_cache()

    assert "network.domains" not in await feature_modules.get_enabled_modules(db_session)
    assert (await client.get("/api/v1/domains", headers=h)).status_code == 404
    _patch_task_session(monkeypatch, db_session)
    calls = _count_lookups(monkeypatch)
    assert (await task_mod._refresh_due_async())["status"] == "skipped"
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_domains_shipped_default")
async def test_existing_domain_rows_turn_it_on_without_seeding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    db_session.add(Domain(name="tracked.example.com"))
    await db_session.commit()
    feature_modules.invalidate_cache()

    assert "network.domains" in await feature_modules.get_enabled_modules(db_session)
    assert (await client.get("/api/v1/domains", headers=h)).status_code == 200
    assert (await db_session.get(FeatureModule, "network.domains")) is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("_domains_shipped_default")
async def test_operator_row_wins_over_existing_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    db_session.add(Domain(name="tracked.example.com"))
    await _set_module(db_session, False)
    await db_session.commit()

    assert "network.domains" not in await feature_modules.get_enabled_modules(db_session)
    assert (await client.get("/api/v1/domains", headers=h)).status_code == 404
