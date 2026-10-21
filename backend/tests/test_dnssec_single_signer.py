"""#1762 — DNSSEC on a multi-server group: each server signs with its own
keys, so signing is refused there, a signed group refuses a second server on
every operator path, and the agent DS report is group-scoped and not
last-writer-wins.

A *disabled* agent server counts as a signer: ``is_enabled`` only pauses the
record-op fan-out, the agent still receives the bundle, and a BIND9 bundle
renders ``inline-signing`` for every ``dnssec_enabled`` zone.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import DNSSECStateBatch, DNSSECStateReport, agent_dnssec_state
from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone

# Drivers SpatiumDDI signs on. Technitium signing is refused outright (#1783,
# covered by test_technitium_dnssec_withdrawn.py), so its 422 is not this one.
DRIVERS = ["bind9", "powerdns"]


async def _user(db: AsyncSession) -> User:
    u = User(
        username=f"ss-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return u


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = await _user(db)
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db, driver="bind9", servers=1, enabled=True, name=None):
    g = DNSServerGroup(name=name or f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    out = []
    # Explicit created_at: the column defaults to now(), which is the
    # transaction start, so every server flushed in one test would tie and
    # the "oldest" rule would fall through to random UUID order.
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(servers):
        s = DNSServer(
            created_at=base + timedelta(seconds=i),
            group_id=g.id,
            driver=driver,
            host=f"10.0.0.{i + 1}",
            name=f"s{i}-{uuid.uuid4().hex[:4]}",
            is_primary=(i == 0),
            is_enabled=enabled,
        )
        db.add(s)
        await db.flush()
        out.append(s)
    return g, out


def _zone(group_id, name="z.example.", signed=False):
    return DNSZone(
        group_id=group_id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="a.example.",
        dnssec_enabled=signed,
    )


def _body(**kw):
    b = {
        "name": f"z{uuid.uuid4().hex[:6]}.example.",
        "zone_type": "primary",
        "kind": "forward",
        "primary_ns": "ns1.example.",
        "admin_email": "admin.example.",
    }
    b.update(kw)
    return b


def _batch(ds: str, zone: str = "same.example.") -> DNSSECStateBatch:
    return DNSSECStateBatch(zones=[DNSSECStateReport(zone_name=zone, ds_records=[ds])])


# ── Signing refused on a multi-server group ──────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", DRIVERS)
async def test_create_update_sign_refused_on_multi_server_group(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, driver, servers=2)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422 and "shared DNSSEC keys" in r.text

    z = _zone(g.id)
    db_session.add(z)
    await db_session.flush()
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/zones/{z.id}", json={"dnssec_enabled": True}, headers=h
    )
    assert r.status_code == 422
    r = await client.post(f"/api/v1/dns/groups/{g.id}/zones/{z.id}/dnssec/sign", headers=h)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_a_disabled_peer_still_counts_as_a_signer(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A disabled BIND9 agent still receives the bundle and renders
    inline-signing with its own keys, so it is a second signer."""
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    db_session.add(
        DNSServer(group_id=g.id, driver="bind9", host="10.9.9.9", name="off", is_enabled=False)
    )
    await db_session.flush()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422, r.text
    assert "disabling a server does not stop it" in r.text


@pytest.mark.asyncio
async def test_single_server_group_may_sign(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["dnssec_multi_signer"] is False


# ── A second server refused into a signed group ──────────────────────────


@pytest.mark.asyncio
async def test_second_server_create_and_move_refused_on_signed_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    db_session.add(_zone(g.id, signed=True))
    other, (mover,) = await _group(db_session, "bind9", servers=1)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "second", "driver": "bind9", "host": "10.0.0.50"},
        headers=h,
    )
    assert r.status_code == 422 and "DNSSEC-signed" in r.text
    # adding it disabled is no way round it: it would still serve the zone
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "spare", "driver": "bind9", "host": "10.0.0.51", "is_enabled": False},
        headers=h,
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/dns/groups/{other.id}/servers/{mover.id}",
        json={"group_id": str(g.id)},
        headers=h,
    )
    assert r.status_code == 422 and "DNSSEC-signed" in r.text
    mover.is_enabled = False
    await db_session.flush()
    r = await client.put(
        f"/api/v1/dns/groups/{other.id}/servers/{mover.id}",
        json={"group_id": str(g.id)},
        headers=h,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_unsigned_group_takes_a_second_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    db_session.add(_zone(g.id, signed=False))
    await db_session.flush()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "second", "driver": "bind9", "host": "10.0.0.50"},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_signed_zone_move_into_multi_server_group_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    src, _ = await _group(db_session, "bind9", servers=1)
    dst, _ = await _group(db_session, "bind9", servers=2)
    z = _zone(src.id, f"mv{uuid.uuid4().hex[:6]}.example.", signed=True)
    db_session.add(z)
    await db_session.flush()
    r = await client.post(
        f"/api/v1/dns/groups/{src.id}/zones/{z.id}/move/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": z.name,
            "acknowledgements": ["dnssec_rollover"],
        },
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "#1762" in r.text
    await db_session.refresh(z)
    assert z.group_id == src.id


# ── Fleet + Copilot paths ────────────────────────────────────────────────


async def _appliance(db: AsyncSession, roles: list[str]) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=roles,
        capabilities={"can_run_dns_bind9": True},
    )
    db.add(a)
    await db.flush()
    return a


@pytest.mark.asyncio
async def test_fleet_assign_new_dns_appliance_to_signed_group_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1, name=f"signed{uuid.uuid4().hex[:4]}")
    db_session.add(_zone(g.id, signed=True))
    a = await _appliance(db_session, ["dns-bind9"])
    await db_session.commit()
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"roles": ["dns-bind9"], "dns_group_id": str(g.id)},
    )
    assert r.status_code == 422, r.text
    assert "DNSSEC-signed" in r.text


@pytest.mark.asyncio
async def test_copilot_assign_appliance_role_refused_into_signed_group(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import AssignApplianceRoleArgs, get_operation

    user = await _user(db_session)
    g, _ = await _group(db_session, "bind9", servers=1, name=f"signed{uuid.uuid4().hex[:4]}")
    db_session.add(_zone(g.id, signed=True))
    a = await _appliance(db_session, [])
    await db_session.flush()
    op = get_operation("assign_appliance_role")
    assert op is not None
    args = AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(a.id), "roles": ["dns-bind9"], "dns_group_id": str(g.id)}
    )
    preview = await op.preview(db_session, user, args)
    assert not preview.ok and "DNSSEC-signed" in preview.detail
    with pytest.raises(ValueError, match="DNSSEC-signed"):
        await op.apply(db_session, user, args)
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is None

    # an unsigned group is fine
    g2, _ = await _group(db_session, "bind9", servers=1, name=f"plain{uuid.uuid4().hex[:4]}")
    args2 = AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(a.id), "roles": ["dns-bind9"], "dns_group_id": str(g2.id)}
    )
    assert (await op.preview(db_session, user, args2)).ok


@pytest.mark.asyncio
async def test_copilot_create_signed_zone_refused_on_multi_server_group(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import CreateDNSZoneArgs, get_operation

    user = await _user(db_session)
    g, _ = await _group(db_session, "powerdns", servers=2)
    op = get_operation("create_dns_zone")
    assert op is not None
    args = CreateDNSZoneArgs(
        name=f"z{uuid.uuid4().hex[:6]}.example.com", group_id=str(g.id), dnssec_enabled=True
    )
    preview = await op.preview(db_session, user, args)
    assert not preview.ok and "shared DNSSEC keys" in preview.detail
    with pytest.raises(ValueError, match="shared DNSSEC keys"):
        await op.apply(db_session, user, args)


# ── Agent auto-registration: not refused, but flagged + alerted ──────────


@pytest.mark.asyncio
async def test_agent_register_into_signed_group_is_flagged_audited_and_alerted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.alerts import _matching_dnssec_multi_signer_subjects

    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1762")
    h = await _headers(db_session)
    gname = f"signed{uuid.uuid4().hex[:4]}"
    g, _ = await _group(db_session, "bind9", servers=1, name=gname)
    z = _zone(g.id, f"r{uuid.uuid4().hex[:6]}.example.", signed=True)
    db_session.add(z)
    await db_session.commit()
    assert await _matching_dnssec_multi_signer_subjects(db_session, None) == []  # type: ignore[arg-type]

    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-1762"},
        json={
            "hostname": "late-joiner",
            "fingerprint": "fp-1762",
            "driver": "bind9",
            "roles": ["authoritative"],
            "agent_id": str(uuid.uuid4()),
            "group_name": gname,
        },
    )
    assert reg.status_code == 200, reg.text  # never refused

    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "dns.agent.register.dnssec_multi_signer")
        )
    ).scalar_one()
    assert audit.resource_id == reg.json()["server_id"]

    r = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=h)
    assert r.json()["dnssec_multi_signer"] is True
    info = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}/dnssec/info", headers=h)
    assert info.json()["dnssec_multi_signer"] is True
    assert info.json()["signing_servers"] == 2

    hits = await _matching_dnssec_multi_signer_subjects(db_session, None)  # type: ignore[arg-type]
    assert [(sid, sev) for sid, _d, _m, sev in hits] == [(str(z.id), "critical")]


@pytest.mark.asyncio
async def test_agentless_groups_are_outside_the_rule(db_session: AsyncSession) -> None:
    """Cloud providers hold one key set per zone however many server rows
    point at them, so a signed (imported) cloud zone is not multi-signer."""
    from app.services.dns import dnssec_signers

    g, _ = await _group(db_session, "cloudflare", servers=2)
    z = _zone(g.id, signed=True)
    db_session.add(z)
    await db_session.flush()
    assert await dnssec_signers.multi_signer_group_ids(db_session, {g.id}) == set()
    assert await dnssec_signers.second_signer_refusal(db_session, g, driver="cloudflare") is None


def test_signing_drivers_match_the_router_gate() -> None:
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS
    from app.services.dns.dnssec_signers import SIGNING_DRIVERS
    from app.services.dns.zone_move import DNSSEC_SIGN_DRIVERS

    # One list, not copies kept in step (#1783 removed Technitium from it).
    assert _DRIVER_GATED_OPERATIONS["dnssec_sign"] is SIGNING_DRIVERS
    assert DNSSEC_SIGN_DRIVERS is SIGNING_DRIVERS
    assert "technitium" not in SIGNING_DRIVERS


# ── Existing multi-signer zones: flagged, not unsigned ───────────────────


@pytest.mark.asyncio
async def test_already_signed_multi_server_zone_is_flagged_not_unsigned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=2)
    z = _zone(g.id, signed=True)
    db_session.add(z)
    await db_session.flush()
    r = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=h)
    assert r.status_code == 200
    assert r.json()["dnssec_enabled"] is True
    assert r.json()["dnssec_multi_signer"] is True


# ── The DS report ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dnssec_state_report_is_group_scoped_and_primary_only(
    db_session: AsyncSession,
) -> None:
    g1, (p1, s1) = await _group(db_session, "bind9", servers=2)
    g2, (p2,) = await _group(db_session, "bind9", servers=1)
    z1 = _zone(g1.id, "same.example.", signed=True)
    z2 = _zone(g2.id, "same.example.", signed=True)
    db_session.add_all([z1, z2])
    await db_session.flush()

    # group 1's primary must not touch group 2's same-named zone
    await agent_dnssec_state(_batch("1 DS-G1"), db_session, (p1, {}))
    await db_session.refresh(z1)
    await db_session.refresh(z2)
    assert z1.dnssec_ds_records == ["1 DS-G1"]
    assert z2.dnssec_ds_records is None

    # a non-primary server of the multi-server group does not overwrite
    out = await agent_dnssec_state(_batch("2 DS-OTHER"), db_session, (s1, {}))
    await db_session.refresh(z1)
    assert out == {"updated": 0}
    assert z1.dnssec_ds_records == ["1 DS-G1"]

    # single-server group's own report still lands
    await agent_dnssec_state(_batch("3 DS-G2"), db_session, (p2, {}))
    await db_session.refresh(z2)
    assert z2.dnssec_ds_records == ["3 DS-G2"]


@pytest.mark.asyncio
async def test_dnssec_state_report_survives_losing_the_primary(
    db_session: AsyncSession,
) -> None:
    """An ORM-level delete re-elects nothing (the API delete does, #2276, and
    the beat self-heal catches up within a minute). With no primary among the
    signers the oldest one reports; back down to one server, whoever is
    left reports."""
    g, (p, s1, s2) = await _group(db_session, "bind9", servers=3)
    z = _zone(g.id, "same.example.", signed=True)
    db_session.add(z)
    await db_session.flush()
    await db_session.delete(p)
    await db_session.flush()

    assert (await agent_dnssec_state(_batch("late"), db_session, (s2, {}))) == {"updated": 0}
    assert (await agent_dnssec_state(_batch("oldest"), db_session, (s1, {}))) == {"updated": 1}
    await db_session.refresh(z)
    assert z.dnssec_ds_records == ["oldest"]

    await db_session.delete(s1)
    await db_session.flush()
    assert (await agent_dnssec_state(_batch("sole"), db_session, (s2, {}))) == {"updated": 1}
    await db_session.refresh(z)
    assert z.dnssec_ds_records == ["sole"]
