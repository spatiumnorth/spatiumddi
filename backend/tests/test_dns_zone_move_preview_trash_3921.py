"""Zone move preview: records in the Trash (#3921)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dns_zone_group_move import _group, _preview, _record, _superadmin, _view, _zone


@pytest.mark.asyncio
async def test_preview_view_figures_count_live_records_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root3921")
    g1 = await _group(db_session, "g1")
    g2 = await _group(db_session, "g2")
    g3 = await _group(db_session, "g3")
    v1 = await _view(db_session, g1, "T")
    await _view(db_session, g2, "T")
    await _view(db_session, g3, "U")
    zone = await _zone(db_session, g1)
    await _record(db_session, zone, "www", view=v1)
    for n in ("old1", "old2"):
        r = await _record(db_session, zone, n, view=v1)
        r.deleted_at = datetime.now(UTC)
    await db_session.flush()

    body = (await _preview(client, token, zone, g2)).json()
    assert body["records_total"] == 1
    assert body["records_remapped"] == 1
    assert body["records_trashed"] == 2

    body = (await _preview(client, token, zone, g3)).json()
    assert body["records_total"] == 1
    assert body["records_widened"] == 1
    assert body["records_widened_by_view"] == {"T": 1}
    assert body["records_trashed"] == 2


@pytest.mark.asyncio
async def test_trash_only_widened_records_still_ask_acknowledgement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A trashed record whose view is cleared comes back shared on restore."""
    token = await _superadmin(db_session, "root3921b")
    g1 = await _group(db_session, "g1")
    g3 = await _group(db_session, "g3")
    v1 = await _view(db_session, g1, "T")
    await _view(db_session, g3, "U")
    zone = await _zone(db_session, g1)
    r = await _record(db_session, zone, "old", view=v1)
    r.deleted_at = datetime.now(UTC)
    await db_session.flush()

    body = (await _preview(client, token, zone, g3)).json()
    assert body["records_widened"] == 0
    assert body["records_trashed_widened"] == 1
    assert "view_widening" in body["required_acknowledgements"]
    assert any("in the Trash" in w for w in body["warnings"])
