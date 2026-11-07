"""An Edit's audit row names only what changed (#3697)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from tests.test_backup_target_update_bounds import _enc, _headers, _target


async def _rows(db: AsyncSession) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "backup_target", AuditLog.action == "update"
        )
    )
    return list(res.scalars())


def _form(name: str = "dest", container: str = "c") -> dict:
    # What the console sends: everything, each stored secret as "".
    return {
        "name": name,
        "description": "d",
        "enabled": True,
        "config": {"container": container, "connection_string": "", "account_key": ""},
        "passphrase_hint": "",
        "schedule_cron": None,
        "retention_keep_days": None,
        "retention_keep_last_n": None,
        "write_only": False,
    }


@pytest.mark.asyncio
async def test_untouched_save_writes_no_update_row(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    t = await _target(
        db_session, "azure_blob", {"container": "c", "connection_string": _enc("CS-SECRET")}
    )
    res = await client.patch(f"/api/v1/backup/targets/{t.id}", json=_form(), headers=headers)
    assert res.status_code == 200, res.text
    assert await _rows(db_session) == []


@pytest.mark.asyncio
async def test_save_records_only_what_changed(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    t = await _target(
        db_session, "azure_blob", {"container": "c", "connection_string": _enc("CS-SECRET")}
    )
    res = await client.patch(
        f"/api/v1/backup/targets/{t.id}",
        json=_form(name="renamed", container="c2"),
        headers=headers,
    )
    assert res.status_code == 200, res.text
    (row,) = await _rows(db_session)
    assert row.changed_fields == ["config", "name"]
    assert row.old_value == {"name": "dest"}
    assert row.new_value == {"name": "renamed", "config_keys_changed": ["container"]}
    assert "CS-SECRET" not in str(row.new_value) + str(row.old_value)


@pytest.mark.asyncio
async def test_rotating_a_secret_records_the_key_not_the_value(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _headers(db_session)
    t = await _target(
        db_session, "azure_blob", {"container": "c", "connection_string": _enc("CS-OLD")}
    )
    body = _form()
    body["config"]["connection_string"] = "CS-NEW"
    res = await client.patch(f"/api/v1/backup/targets/{t.id}", json=body, headers=headers)
    assert res.status_code == 200, res.text
    (row,) = await _rows(db_session)
    assert row.new_value == {"config_keys_changed": ["connection_string"]}
    assert "CS-NEW" not in str(row.new_value)
