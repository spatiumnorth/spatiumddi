"""#1456 — a cloud import must not push the records back to where it read them.

Importing a Cloudflare account into the group that holds that account's
server used to enqueue one ``create`` op per imported record, which the
agentless path applies straight away: a ``POST dns_records`` per record to
the provider the records had just been read from. Cloudflare refuses the
duplicates; a provider that doesn't would store them twice.

The import still pushes where the records are NOT yet: another provider's
server, or a zone renamed on the way in. A record created after the import
reaches the provider as before.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns_import import cloud as cloud_import

from .test_dns_import_cloud import _FakeCloudDriver

_PREVIEW = "/api/v1/dns/import/cloud/preview"
_COMMIT = "/api/v1/dns/import/cloud/commit"


class _RecordingDriver:
    """Agentless driver stand-in: records every change it is asked to apply."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str, str, str]] = []

    async def apply_record_change(self, server: Any, change: Any) -> None:
        self.changes.append((server.name, change.op, change.record.name, change.record.record_type))

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult

        for c in changes:
            await self.apply_record_change(server, c)
        return [RecordChangeResult(change=c, ok=True) for c in changes]


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _RecordingDriver:
    monkeypatch.setattr(cloud_import, "get_driver", lambda _name: _FakeCloudDriver())
    rec = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: rec)
    return rec


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"imp1456-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="imp1456",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _cloud_group(
    db: AsyncSession, *, group: str, server: str, driver: str = "cloudflare"
) -> tuple[DNSServerGroup, DNSServer]:
    grp = DNSServerGroup(name=f"{group}-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    srv = DNSServer(
        group_id=grp.id,
        name=server,
        driver=driver,
        host="api.example.test",
        port=443,
        is_primary=True,
        is_enabled=True,
        credentials_encrypted=b"placeholder-encrypted-blob",
    )
    db.add(srv)
    await db.flush()
    return grp, srv


async def _import(
    client: AsyncClient,
    headers: dict[str, str],
    *,
    source: DNSServer,
    target: DNSServerGroup,
    conflict_actions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    preview = await client.post(
        _PREVIEW,
        headers=headers,
        json={"server_id": str(source.id), "target_group_id": str(target.id)},
    )
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    commit = await client.post(
        _COMMIT,
        headers=headers,
        json={
            "target_group_id": str(target.id),
            "plan": plan,
            "conflict_actions": conflict_actions or {},
        },
    )
    assert commit.status_code == 200, commit.text
    return commit.json()


async def _op_count(db: AsyncSession, server: DNSServer) -> int:
    return (
        await db.execute(
            select(func.count(DNSRecordOp.id)).where(DNSRecordOp.server_id == server.id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_preview_names_the_source_server(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    headers = await _headers(db_session)
    grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    await db_session.commit()

    r = await client.post(
        _PREVIEW,
        headers=headers,
        json={"server_id": str(cf.id), "target_group_id": str(grp.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["source_server_id"] == str(cf.id)


@pytest.mark.asyncio
async def test_import_into_the_source_servers_group_pushes_nothing_back(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    headers = await _headers(db_session)
    grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    await db_session.commit()

    result = await _import(client, headers, source=cf, target=grp)

    assert result["total_records_created"] == 4
    assert recorder.changes == [], "imported records were pushed back to the provider"
    assert await _op_count(db_session, cf) == 0


@pytest.mark.asyncio
async def test_a_record_created_after_the_import_still_reaches_the_provider(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    headers = await _headers(db_session)
    grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    await db_session.commit()
    await _import(client, headers, source=cf, target=grp)

    zone = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.group_id == grp.id, DNSZone.name == "example.com.")
        )
    ).scalar_one()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=headers,
        json={"name": "api", "record_type": "A", "value": "203.0.113.20"},
    )
    assert r.status_code == 201, r.text
    assert recorder.changes == [("cf01", "create", "api", "A")]


@pytest.mark.asyncio
async def test_import_into_another_providers_group_still_pushes(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    """Moving records from one account to another is a real push."""
    headers = await _headers(db_session)
    _src_grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    dst_grp, other = await _cloud_group(db_session, group="r53", server="r5301", driver="route53")
    await db_session.commit()

    await _import(client, headers, source=cf, target=dst_grp)

    assert len(recorder.changes) == 4
    assert {c[0] for c in recorder.changes} == {"r5301"}
    assert {c[1] for c in recorder.changes} == {"create"}
    assert await _op_count(db_session, other) == 4


@pytest.mark.asyncio
async def test_a_renamed_zone_still_pushes(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    """The provider holds the records under the old name, not the new one."""
    headers = await _headers(db_session)
    grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    await db_session.commit()

    await _import(
        client,
        headers,
        source=cf,
        target=grp,
        conflict_actions={"example.com.": {"action": "rename", "rename_to": "example.org."}},
    )

    renamed = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.group_id == grp.id, DNSZone.name == "example.org.")
        )
    ).scalar_one()
    n_records = (
        await db_session.execute(
            select(func.count(DNSRecord.id)).where(DNSRecord.zone_id == renamed.id)
        )
    ).scalar_one()
    assert n_records == 3
    # Only the renamed zone's three records go out; the reverse zone kept its
    # name and is already on the provider.
    assert len(recorder.changes) == 3
    assert {c[3] for c in recorder.changes} == {"A", "MX"}


@pytest.mark.asyncio
async def test_commit_refuses_a_source_server_of_another_driver(
    client: AsyncClient, db_session: AsyncSession, recorder: _RecordingDriver
) -> None:
    """The id comes back from the client; it must name a server of the plan's
    own source, or it could switch off the ops to any server."""
    headers = await _headers(db_session)
    grp, cf = await _cloud_group(db_session, group="cf", server="cf01")
    bind_grp = DNSServerGroup(name=f"b-{uuid.uuid4().hex[:6]}")
    db_session.add(bind_grp)
    await db_session.flush()
    bind = DNSServer(
        group_id=bind_grp.id,
        name="ns1",
        driver="bind9",
        host="192.0.2.53",
        port=53,
        is_primary=True,
        is_enabled=True,
    )
    db_session.add(bind)
    await db_session.commit()

    preview = await client.post(
        _PREVIEW,
        headers=headers,
        json={"server_id": str(cf.id), "target_group_id": str(grp.id)},
    )
    plan = preview.json()
    plan["source_server_id"] = str(bind.id)
    r = await client.post(
        _COMMIT,
        headers=headers,
        json={"target_group_id": str(grp.id), "plan": plan, "conflict_actions": {}},
    )
    assert r.status_code == 400, r.text
