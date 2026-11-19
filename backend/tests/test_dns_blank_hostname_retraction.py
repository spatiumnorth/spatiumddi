"""An address whose name turns blank publishes nothing, on every path.

A blank or whitespace-only hostname is refused at input by the request
models, but a row can still end up blank: a reservation whose stored name is
blank, a lease that stamps a client's blank name, an importer, a row from
before the validators. Such an address must retract the A / PTR an earlier
name published, through the record-op queue, rather than be refused, skipped
or offered an update to a blank owner:

* the IPAM → DNS sync on its strict (request / Sync DNS / scheduled) paths;
* the DHCP reservation mirror, which used to skip the sync on an empty name;
* the drift check, which offers the records for deletion;
* the scheduled auto-sync, whatever ``dns_auto_sync_delete_stale`` says;
* the DDNS lease path when the policy names nothing in place of the blank.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync, _sync_dns_record
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.dns.ddns import apply_ddns_for_lease
from app.services.dns.sync_check import compute_subnet_dns_drift


class _Env:
    subnet: Subnet
    zone: DNSZone
    rev: DNSZone
    scope: DHCPScope


async def _env(db: AsyncSession, *, third: int = 7, **subnet_kw: Any) -> _Env:
    env = _Env()
    tag = uuid.uuid4().hex[:6]
    grp = DNSServerGroup(name=f"gbl-{tag}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{tag}",
            is_primary=True,
            is_enabled=True,
        )
    )
    env.zone = DNSZone(
        group_id=grp.id,
        name=f"bl{tag}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(env.zone)
    space = IPSpace(name=f"sp-{tag}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.62.0.0/16", name="b")
    db.add(block)
    await db.flush()
    env.subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=f"10.62.{third}.0/24",
        name="lan",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(env.zone.id),
        dns_inherit_settings=False,
        **subnet_kw,
    )
    db.add(env.subnet)
    await db.flush()
    env.rev = DNSZone(
        group_id=grp.id,
        name=f"{third}.62.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        linked_subnet_id=env.subnet.id,
    )
    db.add(env.rev)
    dgrp = DHCPServerGroup(name=f"dg-{tag}")
    db.add(dgrp)
    await db.flush()
    db.add(DHCPServer(name=f"k-{tag}", driver="kea", host="127.0.0.1", server_group_id=dgrp.id))
    env.scope = DHCPScope(
        group_id=dgrp.id, subnet_id=env.subnet.id, name="scope", address_family="ipv4"
    )
    db.add(env.scope)
    await db.flush()
    await db.commit()
    return env


async def _host_records(db: AsyncSession, ip_id: uuid.UUID) -> set[tuple[str, str]]:
    rows = (
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == ip_id)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return {(r.record_type, r.name) for r in rows}


async def _delete_ops(db: AsyncSession) -> set[tuple[str, str]]:
    rows = (await db.execute(select(DNSRecordOp).where(DNSRecordOp.op == "delete"))).scalars().all()
    return {(o.record["type"], o.record["name"]) for o in rows}


async def _published(db: AsyncSession, env: _Env, address: str, name: str) -> IPAddress:
    """An address named *name* with its A and PTR published."""
    ip = IPAddress(subnet_id=env.subnet.id, address=address, status="allocated", hostname=name)
    db.add(ip)
    await db.flush()
    assert await _sync_dns_record(db, ip, env.subnet, zone_id=env.zone.id) is True
    await db.flush()
    kinds = {t for t, _ in await _host_records(db, ip.id)}
    assert kinds == {"A", "PTR"}, kinds
    return ip


# ── The sync itself ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("blank", ["   ", "", "\t"])
@pytest.mark.asyncio
async def test_strict_sync_of_a_blank_name_retracts_a_and_ptr(
    db_session: AsyncSession, blank: str
) -> None:
    env = await _env(db_session)
    ip = await _published(db_session, env, "10.62.7.10", "h10")
    ip.hostname = blank
    # No 422: the strict paths (Sync DNS, the scheduled sync) retract.
    published = await _sync_dns_record(
        db_session, ip, env.subnet, zone_id=env.zone.id, action="create", strict=True
    )
    await db_session.flush()
    assert published is False
    assert await _host_records(db_session, ip.id) == set()
    ops = await _delete_ops(db_session)
    assert ("A", "h10") in ops
    assert any(t == "PTR" for t, _ in ops)
    assert ip.dns_record_id is None
    assert ip.fqdn is None
    # The zone stays, so a later name lands in the same zone.
    assert ip.forward_zone_id == env.zone.id


@pytest.mark.asyncio
async def test_a_blank_name_never_publishes_an_owner(db_session: AsyncSession) -> None:
    env = await _env(db_session)
    ip = IPAddress(subnet_id=env.subnet.id, address="10.62.7.11", status="allocated", hostname=" ")
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, env.subnet, zone_id=env.zone.id, strict=True)
    await db_session.flush()
    assert await _host_records(db_session, ip.id) == set()
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert all(o.record["name"].strip() for o in ops)


# ── DHCP reservation mirror ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reservation_update_with_a_blank_stored_name_retracts(
    db_session: AsyncSession,
) -> None:
    env = await _env(db_session)
    st = DHCPStaticAssignment(
        scope_id=env.scope.id,
        ip_address="10.62.7.20",
        mac_address="aa:bb:cc:dd:ee:20",
        hostname="h20",
    )
    db_session.add(st)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, env.scope, st)
    await db_session.flush()
    row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.62.7.20"))
    ).scalar_one()
    assert {t for t, _ in await _host_records(db_session, row.id)} == {"A", "PTR"}

    st.hostname = "   "  # a stored blank (importer / pre-validator row)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, env.scope, st, action="update")
    await db_session.flush()
    assert row.hostname == ""
    assert await _host_records(db_session, row.id) == set()
    assert ("A", "h20") in await _delete_ops(db_session)


@pytest.mark.asyncio
async def test_reservation_cleared_over_rest_retracts_a_and_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"adm-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    env = await _env(db_session)
    created = await client.post(
        f"/api/v1/dhcp/scopes/{env.scope.id}/statics",
        headers=headers,
        json={"ip_address": "10.62.7.21", "mac_address": "aa:bb:cc:dd:ee:21", "hostname": "h21"},
    )
    assert created.status_code == 201, created.text
    ip_id = uuid.UUID(created.json()["ip_address_id"])
    assert {t for t, _ in await _host_records(db_session, ip_id)} == {"A", "PTR"}
    resp = await client.put(
        f"/api/v1/dhcp/statics/{created.json()['id']}", headers=headers, json={"hostname": "  "}
    )
    assert resp.status_code == 200, resp.text
    assert await _host_records(db_session, ip_id) == set()


# ── Drift check + Sync DNS commit ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_drift_offers_deletion_not_an_update_to_a_blank_owner(
    db_session: AsyncSession,
) -> None:
    env = await _env(db_session)
    ip = await _published(db_session, env, "10.62.7.30", "h30")
    ip.hostname = "   "
    await db_session.commit()

    report = await compute_subnet_dns_drift(db_session, env.subnet.id)
    assert [m for m in report.mismatched if m.ip_id == ip.id] == []
    assert [m for m in report.missing if m.ip_id == ip.id] == []
    stale = [s for s in report.stale if s.ip_id == ip.id]
    assert {s.record_type for s in stale} == {"A", "PTR"}
    assert all(s.reason == "no-hostname" and s.blank_name_host_record for s in stale)

    # Committing the offered deletion retracts both.
    _c, _u, deleted, errors = await _apply_dns_sync(
        db_session,
        DnsSyncCommitRequest(delete_stale_record_ids=[s.record_id for s in stale]),
        allowed_stale_ids=[s.record_id for s in stale],
        restrict_subnet_id=env.subnet.id,
    )
    assert errors == []
    assert deleted == 2
    assert await _host_records(db_session, ip.id) == set()


@pytest.mark.asyncio
async def test_sync_dns_update_of_a_blank_named_address_retracts_instead_of_erroring(
    db_session: AsyncSession,
) -> None:
    """A drift result taken while the name was still set, committed after."""
    env = await _env(db_session)
    ip = await _published(db_session, env, "10.62.7.31", "h31")
    a_id = ip.dns_record_id
    ip.hostname = "   "
    await db_session.commit()
    _c, _u, _d, errors = await _apply_dns_sync(
        db_session,
        DnsSyncCommitRequest(update_record_ids=[a_id]),
        restrict_subnet_id=env.subnet.id,
    )
    assert errors == []
    assert await _host_records(db_session, ip.id) == set()


# ── Scheduled auto-sync ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_auto_sync_retracts_a_blank_named_address_with_delete_stale_off(
    db_session: AsyncSession,
) -> None:
    from app.tasks.ipam_dns_sync import _run_auto_sync  # noqa: PLC0415

    env = await _env(db_session)
    ip = await _published(db_session, env, "10.62.7.40", "h40")
    keep = await _published(db_session, env, "10.62.7.41", "h41")
    ip.hostname = "   "
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_delete_stale = False
    ps.dns_auto_sync_last_run_at = None
    await db_session.commit()

    result = await _run_auto_sync()
    assert result.get("status") not in ("disabled", "skipped"), result
    assert result["errors"] == 0, result

    assert await _host_records(db_session, ip.id) == set()
    # The named neighbour is untouched.
    assert await _host_records(db_session, keep.id) == {
        ("A", "h41"),
        ("PTR", "41"),
    }


# ── DDNS lease path ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ddns_with_a_blank_lease_name_retracts(db_session: AsyncSession) -> None:
    env = await _env(
        db_session,
        third=8,
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_provided",
    )
    row = IPAddress(
        subnet_id=env.subnet.id,
        address="10.62.8.50",
        status="dhcp",
        mac_address="aa:bb:cc:dd:ee:50",
        auto_from_lease=True,
    )
    db_session.add(row)
    await db_session.flush()
    assert await apply_ddns_for_lease(
        db_session, subnet=env.subnet, ipam_row=row, client_hostname="d50"
    )
    await db_session.flush()
    assert {t for t, _ in await _host_records(db_session, row.id)} == {"A", "PTR"}

    # The lease ingest stamps the client's blank name onto the row; the
    # policy offers nothing in its place.
    row.hostname = "   "
    assert not await apply_ddns_for_lease(
        db_session, subnet=env.subnet, ipam_row=row, client_hostname="   "
    )
    await db_session.flush()
    assert await _host_records(db_session, row.id) == set()
    assert ("A", "d50") in await _delete_ops(db_session)
