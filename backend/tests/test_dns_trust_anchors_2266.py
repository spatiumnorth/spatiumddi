"""DNSSEC trust anchors reach the BIND9 agent bundle (#2266).

Stored and listed since the options API shipped, never shipped: with
``dnssec_validation = yes`` BIND validated nothing.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle

KEY = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4Rg=="


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str | None) -> tuple[DNSServerGroup, DNSServer | None]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = None
    if driver:
        server = DNSServer(
            group_id=group.id,
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver=driver,
            host=f"h-{uuid.uuid4().hex[:6]}",
            port=53,
            is_primary=True,
            agent_id=uuid.uuid4(),
        )
        db.add(server)
        await db.flush()
    return group, server


def _anchor(**over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "zone_name": ".",
        "algorithm": 8,
        "key_tag": 20326,
        "public_key": KEY,
        "is_initial_key": False,
    }
    body.update(over)
    return body


@pytest.mark.asyncio
async def test_anchor_is_shipped_and_shifts_the_etag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    await db_session.commit()
    assert server is not None

    server_id = server.id
    before = await build_config_bundle(db_session, server)
    assert "trust_anchors" not in before["options"]

    url = f"/api/v1/dns/groups/{group.id}/options/trust-anchors"
    r = await client.post(url, json=_anchor(), headers=headers)
    assert r.status_code == 201, r.text

    db_session.expire_all()
    server = await db_session.get(DNSServer, server_id)
    assert server is not None
    after = await build_config_bundle(db_session, server)
    assert after["options"]["trust_anchors"] == [
        {
            "zone_name": ".",
            "algorithm": 8,
            "key_tag": 20326,
            "public_key": KEY,
            "is_initial_key": False,
        }
    ]
    assert after["etag"] != before["etag"]
    assert after["structural_etag"] != before["structural_etag"]


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "powerdns"])
async def test_driver_that_cannot_apply_anchors_is_refused(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, driver)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/options/trust-anchors", json=_anchor(), headers=headers
    )
    assert r.status_code == 422
    assert driver in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        {"zone_name": 'x"; }; evil {'},
        {"public_key": 'AAAA"; };'},
        {"algorithm": 0},
        {"key_tag": 70000},
    ],
)
async def test_values_that_would_break_named_conf_are_refused(
    client: AsyncClient, db_session: AsyncSession, bad: dict[str, object]
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/options/trust-anchors", json=_anchor(**bad), headers=headers
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_yes_without_anchors_warns_and_anchor_clears_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"

    r = await client.put(url, json={"dnssec_validation": "auto"}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_warnings"] == []

    r = await client.put(url, json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 200, r.text
    assert any("no trust anchor" in w for w in r.json()["dnssec_warnings"])

    r = await client.post(f"{url}/trust-anchors", json=_anchor(), headers=headers)
    assert r.status_code == 201
    r = await client.get(url, headers=headers)
    assert r.json()["dnssec_warnings"] == []


@pytest.mark.asyncio
async def test_non_bind9_server_cannot_join_a_group_holding_anchors(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.dns.server_move import ServerMoveError, ensure_group_single_driver

    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, None)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/options/trust-anchors", json=_anchor(), headers=headers
    )
    assert r.status_code == 201, r.text

    # BIND9 may join; any other driver would silently ignore the anchors.
    await ensure_group_single_driver(db_session, group.id, "bind9", group_name="g", hint="")
    with pytest.raises(ServerMoveError) as exc:
        await ensure_group_single_driver(
            db_session, group.id, "technitium", group_name="g", hint=""
        )
    assert exc.value.status_code == 422
    assert "trust anchors" in str(exc.value)


async def _dirty_seq(db: AsyncSession, server_id: uuid.UUID) -> int:
    db.expire_all()
    return int(
        (
            await db.execute(select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id))
        ).scalar_one()
    )


@pytest.mark.asyncio
async def test_adding_and_deleting_an_anchor_marks_the_groups_bundle_dirty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The anchor row carries no group_id, so the dirty-set listener has to
    resolve it through its options row. Without that, the 201 / 204 changed
    nothing BIND would ever render until an unrelated options save."""
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    _other_group, other = await _group(db_session, "bind9")
    await db_session.commit()
    assert server is not None and other is not None
    server_id, other_id, group_id = server.id, other.id, group.id
    start = await _dirty_seq(db_session, server_id)
    other_start = await _dirty_seq(db_session, other_id)

    url = f"/api/v1/dns/groups/{group_id}/options/trust-anchors"
    r = await client.post(url, json=_anchor(), headers=headers)
    assert r.status_code == 201, r.text
    assert await _dirty_seq(db_session, server_id) > start
    assert await _dirty_seq(db_session, other_id) == other_start, "another group is untouched"

    after_add = await _dirty_seq(db_session, server_id)
    r = await client.delete(f"{url}/{r.json()['id']}", headers=headers)
    assert r.status_code == 204, r.text
    assert await _dirty_seq(db_session, server_id) > after_add
    assert await _dirty_seq(db_session, other_id) == other_start
