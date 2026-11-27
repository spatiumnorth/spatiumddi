"""Cutover-rehearsal diff of the commercial-DDI mirror (#4729): what an import
would create, what already exists, what differs, filters and paging, and that
Trashed live rows never count as present."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.ddi_mirror import DDIMirrorTarget
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ddi_mirror import infoblox as ib
from app.services.ddi_mirror.reconcile import reconcile_target
from tests._ddi_mirror_support import FakeWapi

BASE = "/api/v1/migration/ddi-mirror"


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "_PAGE_PAUSE_SECONDS", 0)


async def _setup(db: AsyncSession) -> tuple[dict[str, str], str, dict[str, object]]:
    """A synced mirror plus a live estate that overlaps it in every way."""
    u = await _admin(db)
    t = DDIMirrorTarget(
        name="gm",
        base_url="https://gm.test",
        username="admin",
        password_encrypted=encrypt_str("secret"),
    )
    db.add(t)
    await db.commit()
    assert (await reconcile_target(db, t, transport=FakeWapi().transport())).ok
    tid = str(t.id)

    space = IPSpace(name="live", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="corp")
    db.add(block)
    await db.flush()
    s1 = Subnet(space_id=space.id, block_id=block.id, network="10.1.0.0/24", name="Servers")
    s2 = Subnet(space_id=space.id, block_id=block.id, network="10.2.0.0/24", name="renamed")
    s3 = Subnet(space_id=space.id, block_id=block.id, network="10.3.0.0/24", name="gone")
    db.add_all([s1, s2, s3])
    await db.flush()
    s3.deleted_at = datetime.now(UTC)  # in Trash: must not count as present
    db.add(
        IPAddress(
            subnet_id=s1.id,
            address="10.1.0.10",
            status="allocated",
            hostname="printer1",
            mac_address="00:11:22:33:44:55",
        )
    )
    dhcp_group = DHCPServerGroup(name="dg")
    db.add(dhcp_group)
    await db.flush()
    scope = DHCPScope(group_id=dhcp_group.id, subnet_id=s1.id, name="sc")
    db.add(scope)
    await db.flush()
    db.add(
        DHCPPool(
            scope_id=scope.id,
            name="p",
            start_ip="10.1.0.100",
            end_ip="10.1.0.199",
            pool_type="dynamic",
        )
    )
    grp = DNSServerGroup(name="dnsg")
    db.add(grp)
    await db.flush()
    db.add(DNSView(group_id=grp.id, name="default"))
    zone = DNSZone(group_id=grp.id, name="example.com.", zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    db.add_all(
        [
            DNSRecord(
                zone_id=zone.id,
                name="app",
                fqdn="app.example.com.",
                record_type="A",
                value="10.1.0.30",
            ),
            DNSRecord(
                zone_id=zone.id,
                name="web1",
                fqdn="web1.example.com.",
                record_type="A",
                value="10.1.0.99",
            ),
        ]
    )
    await db.commit()
    return u, tid, {"zone": zone, "s3": s3}


async def _admin(db: AsyncSession) -> dict[str, str]:
    from app.models.auth import User

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="T",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_rehearsal_says_what_an_import_would_create_and_what_differs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, tid, _ = await _setup(db_session)
    r = await client.get(f"{BASE}/targets/{tid}/rehearsal", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    k = {name: (c["create"], c["exists"], c["differs"]) for name, c in body["kinds"].items()}
    assert k["view"] == (1, 1, 0)
    assert k["container"] == (0, 1, 0)
    # 10.1 matches, 10.2 has another name, 10.3 is only in Trash
    assert k["network"] == (1, 1, 1)
    assert k["range"] == (0, 1, 0)
    assert k["reservation"] == (0, 0, 1)
    assert k["zone"] == (1, 1, 0)
    assert k["host"] == (0, 0, 1) and k["a"] == (0, 1, 0) and k["ptr"] == (1, 0, 0)
    assert body["totals"] == {"total": 13, "create": 4, "exists": 6, "differs": 3}

    diff = (
        await client.get(f"{BASE}/targets/{tid}/rehearsal", params={"action": "differs"}, headers=h)
    ).json()
    by = {(i["kind"], i["name"]): i for i in diff["items"]}
    assert "MAC 00:11:22:33:44:55" in by[("reservation", "printer1")]["differences"][0]
    assert "10.1.0.99" in by[("host", "web1.example.com")]["differences"][0]
    assert (
        "renamed" in by[("network", "10.2.0.0/24")]["differences"][0]
        or "Phones" in by[("network", "10.2.0.0/24")]["differences"][0]
    )
    assert diff["total_items"] == body["totals"]["differs"]
    # the summary does not move while filtering
    assert diff["kinds"] == body["kinds"]


@pytest.mark.asyncio
async def test_rehearsal_filters_paging_and_bad_input(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, tid, _ = await _setup(db_session)
    url = f"{BASE}/targets/{tid}/rehearsal"
    only = (await client.get(url, params={"kind": "network", "action": "create"}, headers=h)).json()
    assert [i["name"] for i in only["items"]] == ["10.3.0.0/24"] and only["total_items"] == 1
    p1 = (await client.get(url, params={"limit": 4}, headers=h)).json()
    p2 = (await client.get(url, params={"limit": 4, "offset": 4}, headers=h)).json()
    assert len(p1["items"]) == 4 and p1["total_items"] == 13 and len(p2["items"]) == 4
    assert {(i["kind"], i["name"]) for i in p1["items"]}.isdisjoint(
        {(i["kind"], i["name"]) for i in p2["items"]}
    )
    for params in (
        {"kind": "bogus"},
        {"action": "maybe"},
        {"limit": 0},
        {"limit": 2000},
        {"offset": -1},
    ):
        assert (await client.get(url, params=params, headers=h)).status_code == 422, params


@pytest.mark.asyncio
async def test_a_trashed_live_zone_is_not_counted_as_existing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, tid, live = await _setup(db_session)
    live["zone"].deleted_at = datetime.now(UTC)  # type: ignore[attr-defined]
    await db_session.commit()
    body = (await client.get(f"{BASE}/targets/{tid}/rehearsal", headers=h)).json()
    assert body["kinds"]["zone"]["create"] == 2 and body["kinds"]["zone"]["exists"] == 0


@pytest.mark.asyncio
async def test_rehearsal_changes_nothing(client: AsyncClient, db_session: AsyncSession) -> None:
    from sqlalchemy import func, select

    h, tid, _ = await _setup(db_session)

    async def snapshot() -> tuple[int, ...]:
        out = []
        for m in (Subnet, IPAddress, DNSZone, DNSRecord, IPBlock):
            out.append(int(await db_session.scalar(select(func.count()).select_from(m)) or 0))
        return tuple(out)

    before = await snapshot()
    await client.get(f"{BASE}/targets/{tid}/rehearsal", headers=h)
    assert await snapshot() == before
