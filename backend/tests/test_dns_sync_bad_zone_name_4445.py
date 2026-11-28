"""A provider zone name the validator refuses does not abort Sync (#4445)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import zone_name_storage_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone

_BAD = "bad\\057name.example.com"


class _Driver:
    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zones_from_server(self, server: Any) -> list[dict[str, Any]]:
        return [{"name": "good.example.com."}, {"name": _BAD + "."}]

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return []

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        return []


async def test_sync_skips_a_zone_name_the_validator_refuses(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DNSServer(
            group_id=group.id,
            name="ns1",
            driver="technitium_api",
            host="10.0.0.1",
            port=53,
            is_enabled=True,
            is_primary=True,
            credentials_encrypted=b"x",
        )
    )
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    group_id = group.id
    token = create_access_token(str(user.id))

    import app.drivers.dns as drivers
    from app.services.dns import pull_from_server as pfs

    fake = _Driver()
    monkeypatch.setattr(drivers, "get_driver", lambda name: fake)
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    resp = await client.post(
        f"/api/v1/dns/groups/{group_id}/sync-with-servers",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200, resp.text
    (srv,) = resp.json()["items"]
    assert srv["result"]["zones_imported"] == ["good.example.com"]
    assert srv["result"]["zones_skipped_system"] == [_BAD]
    names = (
        (await db_session.execute(select(DNSZone.name).where(DNSZone.group_id == group_id)))
        .scalars()
        .all()
    )
    assert names == ["good.example.com."]


def test_storage_rule_refuses_a_trailing_newline() -> None:
    assert zone_name_storage_error("example.com.\n") is not None
    assert zone_name_storage_error("example.com\n") is not None
    assert zone_name_storage_error("example.com.") is None
