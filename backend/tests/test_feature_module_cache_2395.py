"""#2395 — a poisoned feature-module cache must not outlive the catalog it
was computed against.

``test_sweep_gated_off_writes_skip_run_and_restamps`` flaked on a CI shard
because ``get_enabled_modules`` was primed (by a stray task running after the
per-test fixtures had been torn down) while the catalog still carried the
SHIPPED defaults — ``tools.wake_scheduler`` default-off — and that verdict then
answered for the next test inside the 5 s TTL, even though the suite patches
every default to on. The cache now remembers which catalog it resolved
against, so a different one forces a re-resolve.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import feature_modules as fm

pytestmark = pytest.mark.asyncio

MODULE = "tools.wake_scheduler"


@pytest.fixture
def _shipped_defaults() -> Iterator[None]:
    """Temporarily restore the catalog the suite's autouse fixture patched."""
    patched, patched_by_id = fm.MODULES, fm.MODULES_BY_ID
    shipped = tuple(dataclasses.replace(m, default_enabled=m.default_enabled) for m in patched)
    # Rebuild the real defaults: the patched copy has everything on, so read
    # them from the catalog source of truth via a fresh spec for our module.
    shipped = tuple(
        dataclasses.replace(m, default_enabled=False) if m.id == MODULE else m for m in shipped
    )
    fm.MODULES = shipped
    fm.MODULES_BY_ID = {m.id: m for m in shipped}
    try:
        yield
    finally:
        fm.MODULES, fm.MODULES_BY_ID = patched, patched_by_id


async def test_cache_resolved_against_another_catalog_is_not_reused(
    db_session: AsyncSession, _shipped_defaults: None
) -> None:
    # Prime the cache while the module is default-off (the leaked state).
    assert MODULE not in await fm.get_enabled_modules(db_session)
    # Back to the suite's catalog (module default-on), cache NOT invalidated.
    fm.MODULES = tuple(dataclasses.replace(m, default_enabled=True) for m in fm.MODULES)
    fm.MODULES_BY_ID = {m.id: m for m in fm.MODULES}
    assert MODULE in await fm.get_enabled_modules(db_session)


async def test_sweep_ignores_cache_primed_under_another_catalog(db_session: AsyncSession) -> None:
    import app.tasks.wol_scheduler as task

    suite_modules, suite_by_id = fm.MODULES, fm.MODULES_BY_ID
    off = tuple(
        dataclasses.replace(m, default_enabled=False) if m.id == MODULE else m
        for m in suite_modules
    )
    fm.MODULES, fm.MODULES_BY_ID = off, {m.id: m for m in off}
    try:
        assert MODULE not in await fm.get_enabled_modules(db_session)
    finally:
        fm.MODULES, fm.MODULES_BY_ID = suite_modules, suite_by_id

    with patch("app.services.wol.wake_from_server", AsyncMock()):
        result = await task._sweep()
    assert "module_disabled" not in result
