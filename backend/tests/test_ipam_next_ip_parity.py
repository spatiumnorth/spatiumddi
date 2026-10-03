"""#523 — next-IP allocation reaches parity with manual create_address.

Three fixes are exercised here:

* ``NextIPRequest`` gained ``extra_zone_ids`` + ``decom_date`` (schema parity
  with ``IPAddressCreate``); both must thread through onto the created row.
* ``allocate_next_ip`` runs the same ``_check_public_facing_warnings`` guard
  ``create_address`` does — publishing a private IP into a public-facing zone
  needs the force-confirm.
* ``preview_next_ip`` computes + passes the same address-set ``allowed_ranges``
  the commit path uses so preview and commit agree.
"""

from __future__ import annotations

import datetime as _dt
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"nx-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="NX",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _seed_subnet(db: AsyncSession, network: str) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


@pytest.mark.asyncio
async def test_next_ip_threads_extra_zone_ids_and_decom_date(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _seed_subnet(db_session, "10.20.0.0/24")
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}

    # A non-existent extra zone UUID is harmless — the DNS fanout skips a zone
    # it can't resolve — but the value must still land on the row (parity).
    extra_zone = str(uuid.uuid4())
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={
            "hostname": "host1",
            "extra_zone_ids": [extra_zone],
            "decom_date": "2030-01-15",
        },
    )
    assert resp.status_code == 201, resp.text
    ip_id = resp.json()["id"]

    row = await db_session.get(IPAddress, uuid.UUID(ip_id))
    assert row is not None
    assert row.extra_zone_ids == [extra_zone]
    assert row.decom_date == _dt.date(2030, 1, 15)


@pytest.mark.asyncio
async def test_next_ip_public_facing_guard(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _seed_subnet(db_session, "10.30.0.0/24")  # private (RFC1918)
    group = DNSServerGroup(name=f"pf-{uuid.uuid4().hex[:6]}", is_public_facing=True)
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(group_id=group.id, name="pub.example.", zone_type="primary")
    db_session.add(zone)
    await db_session.flush()
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}

    # Unforced: publishing a private IP into the public-facing zone must 409
    # with the confirm-required shape.
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"hostname": "host1", "dns_zone_id": str(zone.id)},
    )
    assert resp.status_code == 409, resp.text
    body = resp.json()["detail"]
    assert body.get("requires_confirmation") is True
    assert any(w["type"] == "public_facing_private_ip" for w in body["warnings"])

    # force=True clears the guard and allocates.
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"hostname": "host1", "dns_zone_id": str(zone.id), "force": True},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_preview_and_commit_agree_on_candidate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # Baseline parity: the preview candidate is exactly what commit hands out
    # (both share ``_pick_next_available_ip`` + now the same allowed_ranges).
    _, token = await _make_admin(db_session)
    subnet = await _seed_subnet(db_session, "10.40.0.0/24")
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}

    preview = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview", headers=hdr)
    assert preview.status_code == 200
    predicted = preview.json()["address"]
    assert predicted is not None

    commit = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"hostname": "host1"},
    )
    assert commit.status_code == 201, commit.text
    assert commit.json()["address"] == predicted


# ── #1307 — IPv6: the preview says which strategy drew its candidate ─────────
#
# For IPv6 the pick upgrades "sequential" to the subnet's
# ``ipv6_allocation_policy`` ("random" by default). A random draw does not
# repeat, so the preview's candidate is not the address a commit draws, and
# the preview has to say so by reporting the strategy it used. Where the pick
# does repeat (sequential, or EUI-64 from a MAC), preview and commit agree.


async def _seed_v6_subnet(db: AsyncSession, network: str, policy: str) -> Subnet:
    subnet = await _seed_subnet(db, network)
    subnet.ipv6_allocation_policy = policy
    await db.flush()
    return subnet


@pytest.mark.asyncio
async def test_ipv6_random_preview_reports_a_random_draw(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _seed_v6_subnet(db_session, "fd00:1307::/64", "random")
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}

    preview = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview", headers=hdr)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    # A free candidate, labelled as what it is. Asked for "sequential", the
    # pick used the subnet's policy, and the commit will draw again.
    assert body["address"] is not None
    assert body["strategy"] == "random"


@pytest.mark.asyncio
async def test_ipv6_sequential_preview_and_commit_agree(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _seed_v6_subnet(db_session, "fd00:1307:1::/120", "sequential")
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}

    preview = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview", headers=hdr)
    assert preview.status_code == 200, preview.text
    assert preview.json()["strategy"] == "sequential"
    predicted = preview.json()["address"]
    assert predicted is not None

    commit = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next", headers=hdr, json={"hostname": "host1"}
    )
    assert commit.status_code == 201, commit.text
    assert commit.json()["address"] == predicted


@pytest.mark.asyncio
async def test_ipv6_eui64_preview_and_commit_agree_on_the_mac(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_admin(db_session)
    subnet = await _seed_v6_subnet(db_session, "fd00:1307:2::/64", "eui64")
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {token}"}
    mac = "00:aa:00:3f:2a:1c"

    preview = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview",
        headers=hdr,
        params={"mac_address": mac},
    )
    assert preview.status_code == 200, preview.text
    assert preview.json() == {"address": "fd00:1307:2:0:2aa:ff:fe3f:2a1c", "strategy": "eui64"}

    commit = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"hostname": "host1", "mac_address": mac},
    )
    assert commit.status_code == 201, commit.text
    assert commit.json()["address"] == "fd00:1307:2:0:2aa:ff:fe3f:2a1c"
