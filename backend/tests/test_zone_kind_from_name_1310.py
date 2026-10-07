"""spatiumddi#1310 — a zone named under in-addr.arpa / ip6.arpa is a reverse zone.

Add Zone pre-filled Kind "Forward lookup" whatever the name, and the API
stored the kind it was given: ``ZoneCreate.kind`` defaulted to ``"forward"``
too, as did create-from-template and the Copilot's ``create_dns_zone``. So a
zone named ``81.98.10.in-addr.arpa`` created with Kind left alone was stored
``kind: forward`` while the API's own classifier (#986) answered
``name_scope: reverse`` for the same zone.

The kind is what IPAM keys on. PTRs are published only into kind "reverse"
zones (``_resolve_reverse_zone``), and the reverse-zone auto-create finds the
existing zone by name and creates nothing beside it
(``ensure_reverse_zone_for_subnet``). A subnet under such a zone got no PTR,
not for its gateway and not for any host, and its DNS-sync summary read
``missing: 0``. Reproduced on nightly-20260928, a single-node appliance driven
through the console with every pre-fill left alone.

The kind now follows the name on every path that takes one from a request:
an omitted kind is taken from the name, and a kind the name contradicts is
refused.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace
from app.services.ai.operations import CreateDNSZoneArgs, get_operation


async def _admin(db: AsyncSession) -> User:
    user = User(
        username=f"u1310-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return user


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = await _admin(db)
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    """A group served by one agent-based (BIND9) primary."""
    grp = DNSServerGroup(name=f"g1310-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    await db.flush()
    return grp


async def _add_zone(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, name: str, **extra: object
):
    """POST a zone the way Add Zone does: the name as typed, no trailing dot."""
    return await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        headers=headers,
        json={
            "name": name,
            "zone_type": "primary",
            "primary_ns": "ns1.example.",
            "admin_email": "admin.example.",
            **extra,
        },
    )


async def _stored_kind(db: AsyncSession, zone_id: str) -> str:
    row = (
        await db.execute(
            select(DNSZone.kind)
            .where(DNSZone.id == uuid.UUID(zone_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return str(row)


# ── The rule ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("81.98.10.in-addr.arpa", "reverse"),
        ("81.98.10.in-addr.arpa.", "reverse"),
        ("8.b.d.0.1.0.0.2.ip6.arpa", "reverse"),
        ("10.IN-ADDR.ARPA", "reverse"),
        # The apex of each reverse tree is reverse too — the same label-wise
        # suffix test ``classify_zone_name`` scopes names with.
        ("in-addr.arpa", "reverse"),
        ("ip6.arpa.", "reverse"),
        ("corp.example.com", "forward"),
        ("home.arpa", "forward"),
        # Label-wise, not a string ``endswith``.
        ("notin-addr.arpa", "forward"),
        ("in-addr.arpa.example.com", "forward"),
    ],
)
def test_zone_kind_for_name(name: str, kind: str) -> None:
    from app.services.dns.name_scope import zone_kind_for_name

    assert zone_kind_for_name(name) == kind


# ── REST create (Add Zone) ────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("81.98.10.in-addr.arpa", "reverse"),
        ("8.b.d.0.1.0.0.2.ip6.arpa", "reverse"),
        ("corp.example.com", "forward"),
    ],
)
async def test_a_zone_created_with_no_kind_takes_it_from_its_name(
    client: AsyncClient, db_session: AsyncSession, name: str, kind: str
) -> None:
    """The issue's first observation: Kind left alone. The kind stored must
    be the one the product's own classifier gives the name."""
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()

    resp = await _add_zone(client, headers, grp, name)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["kind"] == kind
    assert await _stored_kind(db_session, body["id"]) == kind
    if kind == "reverse":
        assert body["name_scope"] == "reverse"


@pytest.mark.asyncio
async def test_a_forward_kind_for_a_reverse_lookup_name_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Refused, not corrected: IPAM would never write into the zone, and the
    operator would not learn why."""
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()

    resp = await _add_zone(client, headers, grp, "81.98.10.in-addr.arpa", kind="forward")

    assert resp.status_code == 422, resp.text
    assert "reverse" in resp.text
    names = (
        (await db_session.execute(select(DNSZone.name).where(DNSZone.group_id == grp.id)))
        .scalars()
        .all()
    )
    assert names == []


@pytest.mark.asyncio
async def test_an_explicit_kind_the_name_allows_is_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()

    resp = await _add_zone(client, headers, grp, "85.98.10.in-addr.arpa", kind="reverse")
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "reverse"

    resp = await _add_zone(client, headers, grp, "shop.example.com", kind="forward")
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "forward"


@pytest.mark.asyncio
async def test_a_zone_that_is_not_primary_keeps_the_kind_it_is_given(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Secondary, stub and forward zones are not SpatiumDDI's to write into,
    and IPAM writes no PTR into them whatever their kind (#1419), so their
    kind is left as it was: ``forward`` when omitted, any kind when given.
    Made primary, a zone takes the rule."""
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()

    resp = await _add_zone(
        client,
        headers,
        grp,
        "93.98.10.in-addr.arpa",
        zone_type="forward",
        forwarders=["192.0.2.53"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "forward"
    fid = resp.json()["id"]

    resp = await _add_zone(
        client,
        headers,
        grp,
        "94.98.10.in-addr.arpa",
        zone_type="secondary",
        masters=["192.0.2.10"],
        kind="reverse",
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "reverse"

    url = f"/api/v1/dns/groups/{grp.id}/zones/{fid}"
    resp = await client.put(url, headers=headers, json={"zone_type": "primary"})
    assert resp.status_code == 422, resp.text
    assert await _stored_kind(db_session, fid) == "forward"
    resp = await client.put(url, headers=headers, json={"zone_type": "primary", "kind": "reverse"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["kind"] == "reverse"


# ── The consequence: IPAM's PTRs ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ipam_publishes_its_ptrs_into_a_reverse_zone_added_with_kind_left_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's second observation, end to end. A subnet whose DNS group
    holds the zone Add Zone created: the gateway (``.1``) and an allocated
    host (``.10``) must get their PTRs in it, and the DNS-sync summary must
    agree. On the broken build the zone was stored forward, so neither PTR
    was ever written and the summary read ``missing: 0`` all the same."""
    headers = await _headers(db_session)
    grp = await _group(db_session)
    fwd = DNSZone(
        group_id=grp.id,
        name=f"z1310-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(fwd)
    space = IPSpace(name=f"sp1310-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.98.0.0/16", name="b")
    db_session.add(block)
    await db_session.commit()

    resp = await _add_zone(client, headers, grp, "82.98.10.in-addr.arpa")
    assert resp.status_code == 201, resp.text
    reverse_id = uuid.UUID(resp.json()["id"])

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.98.82.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(fwd.id),
        },
    )
    assert resp.status_code == 201, resp.text
    sid = resp.json()["id"]
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.98.82.10", "hostname": "host"},
    )
    assert resp.status_code == 201, resp.text

    ptrs = (
        await db_session.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
            .where(DNSRecord.zone_id == reverse_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    assert sorted(tuple(r) for r in ptrs) == [
        ("1", "PTR", f"gateway.{fwd.name}"),
        ("10", "PTR", f"host.{fwd.name}"),
    ]
    # Still the one reverse zone: nothing was auto-created beside it.
    names = (
        (await db_session.execute(select(DNSZone.name).where(DNSZone.group_id == grp.id)))
        .scalars()
        .all()
    )
    assert sorted(names) == sorted(["82.98.10.in-addr.arpa.", fwd.name])

    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    assert {k: resp.json()[k] for k in ("missing", "mismatched", "stale")} == {
        "missing": 0,
        "mismatched": 0,
        "stale": 0,
    }


# ── REST update (Edit Zone) ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_update_cannot_store_a_reverse_lookup_name_as_forward(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    resp = await _add_zone(client, headers, grp, "86.98.10.in-addr.arpa", kind="reverse")
    assert resp.status_code == 201, resp.text
    zid = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zid}", headers=headers, json={"kind": "forward"}
    )
    assert resp.status_code == 422, resp.text
    assert "reverse" in resp.text
    assert await _stored_kind(db_session, zid) == "reverse"

    # A rename into a reverse tree carries the kind with it, or is refused.
    resp = await _add_zone(client, headers, grp, "lab.example.com")
    assert resp.status_code == 201, resp.text
    fid = resp.json()["id"]
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{fid}",
        headers=headers,
        json={"name": "87.98.10.in-addr.arpa"},
    )
    assert resp.status_code == 422, resp.text
    assert await _stored_kind(db_session, fid) == "forward"


@pytest.mark.asyncio
async def test_a_zone_stored_forward_before_the_fix_is_repaired_by_its_next_kind(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A reverse-lookup zone a broken build stored forward. A request that
    touches neither its kind nor its name is left alone; the console's Edit
    dialog sends the kind it shows, so a save there must set Reverse lookup,
    and one that does repairs the zone."""
    headers = await _headers(db_session)
    grp = await _group(db_session)
    legacy = DNSZone(
        group_id=grp.id,
        name="88.98.10.in-addr.arpa.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(legacy)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{legacy.id}"

    resp = await client.put(url, headers=headers, json={"ttl": 600})
    assert resp.status_code == 200, resp.text

    resp = await client.put(url, headers=headers, json={"kind": "forward", "ttl": 900})
    assert resp.status_code == 422, resp.text
    assert "reverse" in resp.text

    resp = await client.put(url, headers=headers, json={"kind": "reverse", "ttl": 900})
    assert resp.status_code == 200, resp.text
    assert resp.json()["kind"] == "reverse"
    assert await _stored_kind(db_session, str(legacy.id)) == "reverse"


# ── Create from template ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_from_template_takes_the_kind_from_the_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/from-template"

    resp = await client.post(
        url,
        headers=headers,
        json={"template_id": "k8s-external-dns", "zone_name": "89.98.10.in-addr.arpa"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "reverse"

    resp = await client.post(
        url,
        headers=headers,
        json={
            "template_id": "k8s-external-dns",
            "zone_name": "90.98.10.in-addr.arpa",
            "kind": "forward",
        },
    )
    assert resp.status_code == 422, resp.text


# ── The Copilot's create_dns_zone ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_copilot_create_takes_the_kind_from_the_name(db_session: AsyncSession) -> None:
    """The Copilot fronts the REST API and the two stay in lockstep (#798)."""
    user = await _admin(db_session)
    grp = await _group(db_session)
    op = get_operation("create_dns_zone")
    assert op is not None

    args = CreateDNSZoneArgs(name="91.98.10.in-addr.arpa", group_id=str(grp.id))
    preview = await op.preview(db_session, user, args)
    assert preview.ok, preview.detail
    assert "/reverse" in (preview.preview_text or "")
    result = await op.apply(db_session, user, args)
    assert result["kind"] == "reverse"
    assert await _stored_kind(db_session, result["id"]) == "reverse"

    refused = await op.preview(
        db_session,
        user,
        CreateDNSZoneArgs(name="92.98.10.in-addr.arpa", group_id=str(grp.id), kind="forward"),
    )
    assert not refused.ok
    assert "reverse" in refused.detail
    with pytest.raises(ValueError, match="reverse"):
        await op.apply(
            db_session,
            user,
            CreateDNSZoneArgs(name="92.98.10.in-addr.arpa", group_id=str(grp.id), kind="forward"),
        )
