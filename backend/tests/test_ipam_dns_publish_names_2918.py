"""Names IPAM and the DHCP import publish are held to the record API's rules.

#2918 an A owner under a zone with an underscore label, #2919 an imported
reservation hostname the static form refuses, #2920 the bulk-allocate preview
promising names the commit refuses, #2921 the address import counting rows
published nowhere.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.core.dns_names import host_in_zone_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

UNDERSCORE_ZONE = "_lab.example.test"
LONG_ZONE = ".".join(["z" * 63, "y" * 63, "x" * 63, "example.test"])  # 204 chars


def test_rule_covers_zone_labels_and_length() -> None:
    assert host_in_zone_error("h1", "example.test") is None
    assert host_in_zone_error("h1", UNDERSCORE_ZONE + ".") is not None
    assert "_lab" in (host_in_zone_error("h1", UNDERSCORE_ZONE) or "")
    assert host_in_zone_error("h" + "x" * 50 + "-1", LONG_ZONE) is not None
    # the default-gateway placeholder never publishes a forward record
    assert host_in_zone_error("gateway", UNDERSCORE_ZONE) is None


class Env:
    def __init__(self, headers: dict[str, str], subnet: Subnet, zone: DNSZone | None) -> None:
        self.headers = headers
        self.subnet = subnet
        self.zone = zone


async def _env(db: AsyncSession, zone_name: str | None, net: str = "10.91.1.0/24") -> Env:
    user = User(
        username=f"u2918-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    zone = None
    if zone_name:
        grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
        db.add(grp)
        await db.flush()
        db.add(
            DNSServer(
                group_id=grp.id,
                driver="bind9",
                host="10.0.0.1",
                name=f"s-{uuid.uuid4().hex[:6]}",
                is_primary=True,
                is_enabled=True,
            )
        )
        zone = DNSZone(
            group_id=grp.id,
            name=zone_name + ".",
            zone_type="primary",
            kind="forward",
            primary_ns=f"ns1.{zone_name}.",
            admin_email=f"admin.{zone_name}.",
        )
        db.add(zone)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.91.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=net,
        name="s",
        dns_zone_id=str(zone.id) if zone else None,
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    await db.commit()
    return Env({"Authorization": f"Bearer {create_access_token(str(user.id))}"}, subnet, zone)


async def _records(db: AsyncSession, zone: DNSZone, rtype: str = "A") -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(DNSRecord)
            .where(DNSRecord.zone_id == zone.id, DNSRecord.record_type == rtype)
        )
    ).scalar_one()


# ── #2918 ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_allocate_into_underscore_zone_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session, UNDERSCORE_ZONE)
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/next",
        json={"hostname": "h1"},
        headers=env.headers,
    )
    assert r.status_code == 422, r.text
    assert "_lab" in r.text
    assert env.zone is not None
    assert await _records(db_session, env.zone) == 0


@pytest.mark.asyncio
async def test_background_sync_skips_underscore_zone(db_session: AsyncSession) -> None:
    env = await _env(db_session, UNDERSCORE_ZONE)
    ip = IPAddress(subnet_id=env.subnet.id, address="10.91.1.20", status="allocated", hostname="h2")
    db_session.add(ip)
    await db_session.flush()
    assert await _sync_dns_record(db_session, ip, env.subnet, action="create") is False
    assert env.zone is not None
    assert await _records(db_session, env.zone) == 0
    with pytest.raises(HTTPException) as exc:
        await _sync_dns_record(db_session, ip, env.subnet, action="create", strict=True)
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_allocate_into_ordinary_zone_still_publishes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session, "example.test")
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/next",
        json={"hostname": "h1"},
        headers=env.headers,
    )
    assert r.status_code == 201, r.text
    assert env.zone is not None
    assert await _records(db_session, env.zone) == 1


# ── #2920 ────────────────────────────────────────────────────────────


def _bulk(zone: DNSZone) -> dict[str, Any]:
    return {
        "range_start": "10.91.1.200",
        "range_end": "10.91.1.201",
        "hostname_template": "h" + "x" * 50 + "-{n}",
        "dns_zone_id": str(zone.id),
        "create_dns_records": True,
    }


@pytest.mark.asyncio
async def test_bulk_preview_names_what_commit_refuses(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session, LONG_ZONE)
    assert env.zone is not None
    base = f"/api/v1/ipam/subnets/{env.subnet.id}/bulk-allocate"
    body = _bulk(env.zone)
    commit = await client.post(base, json=body, headers=env.headers)
    preview = await client.post(f"{base}/preview", json=body, headers=env.headers)
    assert commit.status_code == 422, commit.text
    assert preview.status_code == 422, preview.text
    assert "253" in preview.text


@pytest.mark.asyncio
async def test_bulk_preview_ok_when_names_fit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session, "example.test")
    assert env.zone is not None
    body = _bulk(env.zone)
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/bulk-allocate/preview",
        json=body,
        headers=env.headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["will_create"] == 2


# ── #2921 ────────────────────────────────────────────────────────────


async def _import(client: AsyncClient, env: Env, csv: bytes) -> dict[str, Any]:
    r = await client.post(
        "/api/v1/ipam/import/addresses/commit",
        headers=env.headers,
        files={"file": ("a.csv", csv, "text/csv")},
        data={"subnet_id": str(env.subnet.id), "strategy": "skip"},
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_import_counts_only_published(client: AsyncClient, db_session: AsyncSession) -> None:
    ctrl = await _env(db_session, "example.test", "10.91.2.0/24")
    out = await _import(client, ctrl, b"address,hostname\n10.91.2.30,okhost\n")
    assert out["created"] == 1 and out["dns_synced"] == 1 and out["errors"] == []

    nozone = await _env(db_session, None, "10.91.3.0/24")
    out = await _import(client, nozone, b"address,hostname\n10.91.3.10,okhost3\n")
    assert out["created"] == 1 and out["dns_synced"] == 0

    long_ = await _env(db_session, LONG_ZONE, "10.91.4.0/24")
    out = await _import(client, long_, b"address,hostname\n10.91.4.4," + b"h" * 50 + b"\n")
    assert out["created"] == 1 and out["dns_synced"] == 0
    assert any("253" in e for e in out["errors"]), out

    us = await _env(db_session, UNDERSCORE_ZONE, "10.91.5.0/24")
    out = await _import(client, us, b"address,hostname\n10.91.5.5,h5\n")
    assert out["dns_synced"] == 0 and any("_lab" in e for e in out["errors"]), out


# ── #2919 ────────────────────────────────────────────────────────────

_KEA = json.dumps(
    {
        "Dhcp4": {
            "subnet4": [
                {
                    "subnet": "192.0.2.128/27",
                    "pools": [{"pool": "192.0.2.130 - 192.0.2.135"}],
                    "reservations": [
                        {
                            "ip-address": "192.0.2.140",
                            "hw-address": "02:00:5e:10:00:8c",
                            "hostname": "under_score",
                        },
                        {
                            "ip-address": "192.0.2.141",
                            "hw-address": "02:00:5e:10:00:8d",
                            "hostname": "good-host",
                        },
                    ],
                }
            ]
        }
    }
).encode()


@pytest.mark.asyncio
async def test_kea_import_drops_hostname_static_form_refuses(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"u2919-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add_all([group, space])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="192.0.2.0/24", name="b")
    db_session.add(block)
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    pv = await client.post(
        "/api/v1/dhcp/import/kea/preview",
        headers=h,
        files={"file": ("kea.conf", _KEA, "application/json")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert pv.status_code == 200, pv.text
    plan = pv.json()
    assert any("under_score" in w or "192.0.2.140" in w for w in plan["warnings"])
    # a plan the client hand-edits back to the bad name is held at the commit
    plan["scopes"][0]["reservations"][0]["hostname"] = "under_score"
    r = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers=h,
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["total_reservations_created"] == 2
    assert any("192.0.2.140" in w for w in r.json()["warnings"])
    rows = (await db_session.execute(select(DHCPStaticAssignment))).scalars().all()
    by_ip = {str(x.ip_address): x.hostname for x in rows}
    assert by_ip["192.0.2.140"] == ""
    assert by_ip["192.0.2.141"] == "good-host"
