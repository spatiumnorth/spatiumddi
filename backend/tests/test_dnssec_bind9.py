"""BIND9 DNSSEC — render + policy CRUD + driver gate (issue #49)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import ConfigBundle, DNSSECPolicyData, ServerOptions, ZoneData
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import DNSSECPolicy, DNSServer, DNSServerGroup, DNSZone


def _zone(*, dnssec_enabled: bool = False, policy: str | None = None) -> ZoneData:
    return ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=3600,
        refresh=3600,
        retry=600,
        expire=604800,
        minimum=300,
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
        serial=1,
        dnssec_enabled=dnssec_enabled,
        dnssec_policy_name=policy,
    )


def _bundle(zone: ZoneData, policies: tuple[DNSSECPolicyData, ...] = ()) -> ConfigBundle:
    return ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 5, 29, 12, 0, tzinfo=UTC),
        dnssec_policies=policies,
    )


# ── Control-plane render ────────────────────────────────────────────────


def test_unsigned_zone_has_no_dnssec_policy() -> None:
    out = BIND9Driver().render_server_config(None, ServerOptions(), bundle=_bundle(_zone()))
    assert "dnssec-policy" not in out
    assert "inline-signing" not in out


def test_signed_zone_default_policy() -> None:
    out = BIND9Driver().render_server_config(
        None, ServerOptions(), bundle=_bundle(_zone(dnssec_enabled=True))
    )
    assert 'dnssec-policy "default";' in out
    assert "inline-signing yes;" in out
    # No custom policy block — "default" is BIND's built-in.
    assert 'dnssec-policy "default" {' not in out


def test_signed_zone_custom_policy_renders_block() -> None:
    pol = DNSSECPolicyData(
        name="strong",
        algorithm="ed25519",
        ksk_lifetime_days=0,
        zsk_lifetime_days=30,
        nsec3=True,
        nsec3_iterations=0,
        nsec3_salt_length=0,
        nsec3_optout=False,
    )
    out = BIND9Driver().render_server_config(
        None,
        ServerOptions(),
        bundle=_bundle(_zone(dnssec_enabled=True, policy="strong"), policies=(pol,)),
    )
    # Top-level policy block + zone reference.
    assert 'dnssec-policy "strong" {' in out
    assert "ksk lifetime unlimited algorithm ed25519;" in out
    assert "zsk lifetime 30d algorithm ed25519;" in out
    assert "nsec3param iterations 0 optout no salt-length 0;" in out
    assert 'dnssec-policy "strong";' in out
    assert "inline-signing yes;" in out


def test_dnssec_enable_shifts_bundle_etag() -> None:
    a = _bundle(_zone(dnssec_enabled=False)).compute_etag()
    b = _bundle(_zone(dnssec_enabled=True)).compute_etag()
    assert a != b


# ── Policy CRUD + driver gate ───────────────────────────────────────────


async def _admin(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def test_default_policy_seeded_and_crud(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin(db_session)
    # The real DB gets the built-in "default" from the migration seed; the
    # test DB is create_all (no seed), so insert it directly to exercise the
    # built-in-protection logic.
    db_session.add(DNSSECPolicy(name="default", is_builtin=True))
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.get("/api/v1/dns/dnssec-policies", headers=h)
    assert r.status_code == 200, r.text
    names = {p["name"]: p for p in r.json()}
    assert "default" in names and names["default"]["is_builtin"] is True

    # Create a custom policy.
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": "nsec3-ec", "algorithm": "ecdsap256sha256", "nsec3": True},
    )
    assert r.status_code == 201, r.text
    pid = r.json()["id"]

    # Bad algorithm → 422.
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": "bad", "algorithm": "md5"},
    )
    assert r.status_code == 422

    # Built-in can't be deleted.
    r = await client.delete(f"/api/v1/dns/dnssec-policies/{names['default']['id']}", headers=h)
    assert r.status_code == 422

    # Custom delete works.
    r = await client.delete(f"/api/v1/dns/dnssec-policies/{pid}", headers=h)
    assert r.status_code == 204


async def _group_with_driver(db: AsyncSession, driver: str) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(group_id=grp.id, name=f"s-{uuid.uuid4().hex[:6]}", driver=driver, host="1.2.3.4")
    )
    await db.flush()
    return grp


async def _zone_row(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
    z = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.flush()
    return z


async def test_sign_allowed_on_bind9_group(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _admin(db_session)
    grp = await _group_with_driver(db_session, "bind9")
    zone = await _zone_row(db_session, grp)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/sign",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_enabled"] is True


async def test_sign_rejected_on_windows_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin(db_session)
    grp = await _group_with_driver(db_session, "windows_dns")
    zone = await _zone_row(db_session, grp)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/sign",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert r.status_code == 422


async def test_rollover_requires_signed_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _admin(db_session)
    grp = await _group_with_driver(db_session, "bind9")
    zone = await _zone_row(db_session, grp)  # unsigned
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/rollover",
        headers={"Authorization": f"Bearer {token}"},
        json={"key_tag": 12345},
    )
    assert r.status_code == 409


async def test_nsec3_iterations_above_zero_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """BIND 9.20 refuses ``nsec3param iterations`` > 0 and rejects the whole
    named.conf over it (#3153), so the API must not store one."""
    token = await _admin(db_session)
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": "it151", "nsec3": True, "nsec3_iterations": 151},
    )
    assert r.status_code == 422, r.text
    assert "BIND 9.20" in r.text
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": "salty", "nsec3": True, "nsec3_salt_length": 256},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": "ok3", "nsec3": True, "nsec3_iterations": 0, "nsec3_salt_length": 8},
    )
    assert r.status_code == 201, r.text
    r = await client.put(
        f"/api/v1/dns/dnssec-policies/{r.json()['id']}",
        headers=h,
        json={"nsec3_iterations": 5},
    )
    assert r.status_code == 422, r.text


async def test_stored_nonzero_iterations_ship_as_zero(db_session: AsyncSession) -> None:
    """A row saved before the API refused it must not reach named (#3153).

    The agent bundle ships 0, and its ETag is the one a policy stored with 0
    gives, so the hash is taken over the clamped value and an agent that
    applied it does not see a change that is not there.
    """
    from app.services.dns.agent_config import render_bundle_body

    grp = await _group_with_driver(db_session, "bind9")
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == grp.id))
    ).scalar_one()
    pol = DNSSECPolicy(name="old151", nsec3=True, nsec3_iterations=151, nsec3_salt_length=8)
    db_session.add(pol)
    await db_session.flush()
    zone = await _zone_row(db_session, grp)
    zone.dnssec_enabled = True
    zone.dnssec_policy_id = pol.id
    await db_session.commit()

    stored = await render_bundle_body(db_session, server)
    shipped = [p for p in stored.body["dnssec_policies"] if p["name"] == "old151"]
    assert [p["nsec3_iterations"] for p in shipped] == [0]

    pol.nsec3_iterations = 0
    await db_session.commit()
    zero = await render_bundle_body(db_session, server)
    assert zero.etag == stored.etag
    assert zero.body["structural_etag"] == stored.body["structural_etag"]


# ── Key lifetimes BIND refuses (#3411) ──────────────────────────────────
#
# named-checkconf 9.20 refuses a ``dnssec-policy`` key lifetime that is
# negative ("expected ISO 8601 duration or TTL value near '-1d'"), past 49710
# days ("duration or TTL out of range"), or shorter than a rollover of that key
# takes with the default timings a policy renders with ("key lifetime is
# shorter than the time it takes to do a rollover": a KSK under 2 days, a ZSK
# under 11). Any of them fails the whole named.conf, so once a zone is signed
# with the policy every later apply on its group is quarantined.


@pytest.mark.parametrize(
    ("field", "days", "allowed"),
    [
        ("ksk_lifetime_days", -1, "0 (unlimited) or 2 to 49710 days"),
        ("zsk_lifetime_days", -1, "0 (unlimited) or 11 to 49710 days"),
        ("ksk_lifetime_days", 1000000, "0 (unlimited) or 2 to 49710 days"),
        ("zsk_lifetime_days", 49711, "0 (unlimited) or 11 to 49710 days"),
        ("ksk_lifetime_days", 1, "0 (unlimited) or 2 to 49710 days"),
        ("zsk_lifetime_days", 7, "0 (unlimited) or 11 to 49710 days"),
        ("zsk_lifetime_days", 10, "0 (unlimited) or 11 to 49710 days"),
        ("ksk_lifetime_days", 2147483648, "0 (unlimited) or 2 to 49710 days"),
    ],
)
async def test_key_lifetime_bind_refuses_is_422_on_create(
    client: AsyncClient, db_session: AsyncSession, field: str, days: int, allowed: str
) -> None:
    """A lifetime BIND refuses is a 422 naming the field and what it may be."""
    token = await _admin(db_session)
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": f"lt-{uuid.uuid4().hex[:8]}", field: days},
    )
    assert r.status_code == 422, r.text
    assert field in r.text, r.text
    assert allowed in r.text, r.text
    assert "BIND 9.20" in r.text, r.text


@pytest.mark.parametrize(("ksk", "zsk"), [(0, 0), (0, 90), (2, 11), (49710, 49710)])
async def test_key_lifetime_bind_takes_is_stored(
    client: AsyncClient, db_session: AsyncSession, ksk: int, zsk: int
) -> None:
    """Unlimited (0), each key's floor and the ceiling all load in named-checkconf 9.20."""
    token = await _admin(db_session)
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": f"lt-{uuid.uuid4().hex[:8]}",
            "ksk_lifetime_days": ksk,
            "zsk_lifetime_days": zsk,
        },
    )
    assert r.status_code == 201, r.text
    assert (r.json()["ksk_lifetime_days"], r.json()["zsk_lifetime_days"]) == (ksk, zsk)


async def test_key_lifetime_bind_refuses_is_422_on_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An edit to a lifetime BIND refuses is a 422 and leaves the policy as it was."""
    token = await _admin(db_session)
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        "/api/v1/dns/dnssec-policies",
        headers=h,
        json={"name": f"lt-{uuid.uuid4().hex[:8]}", "zsk_lifetime_days": 30},
    )
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    for body in (
        {"ksk_lifetime_days": -1},
        {"ksk_lifetime_days": 1},
        {"zsk_lifetime_days": 10},
        {"zsk_lifetime_days": 1000000},
    ):
        r = await client.put(f"/api/v1/dns/dnssec-policies/{pid}", headers=h, json=body)
        assert r.status_code == 422, (body, r.text)
    r = await client.get("/api/v1/dns/dnssec-policies", headers=h)
    (row,) = [p for p in r.json() if p["id"] == pid]
    assert (row["ksk_lifetime_days"], row["zsk_lifetime_days"]) == (0, 30)
    r = await client.put(
        f"/api/v1/dns/dnssec-policies/{pid}", headers=h, json={"zsk_lifetime_days": 11}
    )
    assert r.status_code == 200, r.text
    assert r.json()["zsk_lifetime_days"] == 11


async def _signed_with(db: AsyncSession, ksk: int, zsk: int) -> tuple[DNSServer, DNSSECPolicy]:
    """A BIND9 server whose group has a zone signed with a policy stored with
    these lifetimes, as the API accepted them before #3411."""
    grp = await _group_with_driver(db, "bind9")
    server = (await db.execute(select(DNSServer).where(DNSServer.group_id == grp.id))).scalar_one()
    pol = DNSSECPolicy(
        name=f"old-{uuid.uuid4().hex[:8]}", ksk_lifetime_days=ksk, zsk_lifetime_days=zsk
    )
    db.add(pol)
    await db.flush()
    zone = await _zone_row(db, grp)
    zone.dnssec_enabled = True
    zone.dnssec_policy_id = pol.id
    await db.commit()
    return server, pol


@pytest.mark.parametrize(
    ("stored", "shipped"),
    [
        ((-1, -1), (0, 0)),
        ((1, 7), (2, 11)),
        ((1000000, 49711), (49710, 49710)),
    ],
)
async def test_stored_key_lifetimes_bind_refuses_ship_in_range(
    db_session: AsyncSession, stored: tuple[int, int], shipped: tuple[int, int]
) -> None:
    """A row saved before the API refused it must not reach named (#3411).

    The agent bundle carries the nearest lifetime BIND takes: a negative one
    as 0 (unlimited), a short one at the key's floor, a long one at the
    ceiling. Its ETag is the one a policy stored with those values gives, so
    an agent that applied it does not see a change that is not there.
    """
    from app.services.dns.agent_config import render_bundle_body

    server, pol = await _signed_with(db_session, *stored)
    before = await render_bundle_body(db_session, server)
    (p,) = [p for p in before.body["dnssec_policies"] if p["name"] == pol.name]
    assert (p["ksk_lifetime_days"], p["zsk_lifetime_days"]) == shipped

    pol.ksk_lifetime_days, pol.zsk_lifetime_days = shipped
    await db_session.commit()
    held = await render_bundle_body(db_session, server)
    assert held.etag == before.etag
    assert held.body["structural_etag"] == before.body["structural_etag"]


async def test_stored_key_lifetimes_bind_refuses_render_in_range(
    db_session: AsyncSession,
) -> None:
    """The control plane's own BIND9 render holds a stored row to BIND's range too."""
    from app.services.dns.config_bundle import build_config_bundle as build_dataclass_bundle

    server, _ = await _signed_with(db_session, -1, 1000000)
    bundle = await build_dataclass_bundle(db_session, server)
    out = BIND9Driver().render_server_config(server, ServerOptions(), bundle=bundle)
    assert "ksk lifetime unlimited algorithm ecdsap256sha256;" in out
    assert "zsk lifetime 49710d algorithm ecdsap256sha256;" in out
    # Anchor on the lifetime clause: the rendered file also carries random
    # UUIDs and a timestamp, which can contain "-1d" by chance (#3629).
    assert not re.search(r"lifetime\s+-1d", out)
    assert not re.search(r"lifetime\s+1000000d", out)
