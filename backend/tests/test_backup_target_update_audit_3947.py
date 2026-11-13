"""An Edit that re-sends a number as its text records no change (#3947)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_backup_target_update_audit import _rows
from tests.test_backup_target_update_bounds import _enc, _headers, _target

_FTP = {"host": "h", "username": "u", "remote_path": "/b", "password": _enc("p")}


@pytest.mark.asyncio
async def test_number_resent_as_text_is_not_a_change(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    t = await _target(db_session, "ftp", {**_FTP, "port": 21, "mode": "ftp"})
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json={"config": {"port": "21", "mode": "ftp", "password": ""}},
        headers=headers,
    )
    assert res.status_code == 200, res.text
    assert await _rows(db_session) == []


@pytest.mark.asyncio
async def test_changed_number_is_recorded(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    t = await _target(db_session, "ftp", {**_FTP, "port": 21})
    # A moved port brings the stored password along only if it is sent again.
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json={"config": {"port": 2121, "password": "p2"}},
        headers=headers,
    )
    assert res.status_code == 200, res.text
    (row,) = await _rows(db_session)
    assert row.new_value == {"config_keys_changed": ["password", "port"]}
