"""BIND9 DNSSEC — render + policy CRUD + driver gate (issue #49)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
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


def test_stored_nonzero_iterations_render_as_zero() -> None:
    """A row saved before the API refused it must not reach named."""
    from app.services.dns.named_conf_validation import effective_nsec3_iterations

    assert effective_nsec3_iterations("p", 151) == 0
    assert effective_nsec3_iterations("p", 0) == 0
