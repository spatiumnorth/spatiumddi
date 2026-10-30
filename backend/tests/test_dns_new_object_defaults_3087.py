"""#3087 — Settings' four DNS defaults were stored and read by nothing.

``dns_default_ttl``, ``dns_default_zone_type``, ``dns_default_dnssec_validation``
and ``dns_recursive_by_default`` now seed NEW zones and server groups when the
caller sent no value of its own.  An explicit value always wins, and an
importer's source value is never overridden.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSServerOptions, DNSZone
from app.models.settings import PlatformSettings
from tests.test_dns_import import _build_tar, _make_group


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _set_defaults(db: AsyncSession, **values: object) -> None:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    for k, v in values.items():
        setattr(ps, k, v)
    await db.commit()


async def _group_options(db: AsyncSession, group_id: str) -> DNSServerOptions:
    db.expire_all()
    return (
        await db.execute(select(DNSServerOptions).where(DNSServerOptions.group_id == group_id))
    ).scalar_one()


# ── zone TTL ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zone_create_without_ttl_takes_the_stored_default(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    await _set_defaults(db_session, dns_default_ttl=5400)

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones", json={"name": "d.test."}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["ttl"] == 5400


@pytest.mark.asyncio
async def test_zone_create_with_explicit_ttl_keeps_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    await _set_defaults(db_session, dns_default_ttl=5400)

    for name, ttl in (("e.test.", 300), ("z.test.", 0)):
        r = await client.post(
            f"/api/v1/dns/groups/{group.id}/zones",
            json={"name": name, "ttl": ttl},
            headers=headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["ttl"] == ttl


@pytest.mark.asyncio
async def test_zone_create_default_is_unchanged_on_a_stock_install(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    await _set_defaults(db_session)  # column defaults only

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones", json={"name": "s.test."}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["ttl"] == 3600
    assert r.json()["zone_type"] == "primary"


@pytest.mark.asyncio
async def test_zone_type_stays_primary_when_omitted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Default Zone Type is a form pre-selection: a forward / secondary zone needs
    fields a bare API create never carries, so the API's type does not follow it."""
    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    await _set_defaults(db_session, dns_default_zone_type="forward")

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones", json={"name": "t.test."}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["zone_type"] == "primary"


@pytest.mark.asyncio
async def test_zone_from_template_takes_the_stored_ttl(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.dns.zone_templates import list_templates

    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    await _set_defaults(db_session, dns_default_ttl=5400)
    tpl = next(t for t in list_templates() if not t.parameters)

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/from-template",
        json={"template_id": tpl.id, "zone_name": "tpl.test.", "params": {}},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["ttl"] == 5400


# ── server groups ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_group_create_without_values_takes_the_stored_defaults(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _set_defaults(
        db_session, dns_recursive_by_default=False, dns_default_dnssec_validation="no"
    )

    r = await client.post("/api/v1/dns/groups", json={"name": "g-defaults"}, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["is_recursive"] is False
    assert (await _group_options(db_session, r.json()["id"])).dnssec_validation == "no"


@pytest.mark.asyncio
async def test_group_create_with_explicit_recursion_keeps_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _set_defaults(db_session, dns_recursive_by_default=False)

    r = await client.post(
        "/api/v1/dns/groups", json={"name": "g-explicit", "is_recursive": True}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["is_recursive"] is True


@pytest.mark.asyncio
async def test_group_create_default_is_unchanged_on_a_stock_install(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _set_defaults(db_session)

    r = await client.post("/api/v1/dns/groups", json={"name": "g-stock"}, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["is_recursive"] is True
    assert (await _group_options(db_session, r.json()["id"])).dnssec_validation == "auto"


@pytest.mark.asyncio
async def test_auto_registered_group_takes_the_stored_defaults(db_session: AsyncSession) -> None:
    from app.services.dns.new_object_defaults import add_group_with_defaults

    await _set_defaults(
        db_session, dns_recursive_by_default=False, dns_default_dnssec_validation="yes"
    )
    group = DNSServerGroup(name="auto-registered")
    await add_group_with_defaults(db_session, group)
    await db_session.commit()

    assert group.is_recursive is False
    assert (await _group_options(db_session, str(group.id))).dnssec_validation == "yes"


# ── importers keep the source's values ───────────────────────────────────

_NAMED = """
options { directory "/var/named"; };
zone "example.com" { type master; file "example.com.zone"; };
zone "fwd.example" { type forward; forwarders { 192.0.2.1; }; };
"""
_ZONE = """\
$TTL 7200
@   IN  SOA ns1.example.com. admin.example.com. (
        2026050901 3600 1800 1209600 3600 )
    IN  NS  ns1.example.com.
www IN  A   192.0.2.10
"""


@pytest.mark.asyncio
async def test_importer_keeps_the_source_ttl_and_defaults_only_where_it_has_none(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _make_group(db_session)
    group_id = group.id
    await _set_defaults(db_session, dns_default_ttl=5400)
    archive = _build_tar([("etc/named.conf", _NAMED), ("var/named/example.com.zone", _ZONE)])

    plan = (
        await client.post(
            "/api/v1/dns/import/bind9/preview",
            headers=headers,
            files={"file": ("bind.tar.gz", archive, "application/gzip")},
            data={"target_group_id": str(group.id)},
        )
    ).json()
    r = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers=headers,
        json={"target_group_id": str(group.id), "plan": plan, "conflict_actions": {}},
    )
    assert r.status_code == 200, r.text

    db_session.expire_all()
    zones = {
        z.name: z
        for z in (await db_session.execute(select(DNSZone).where(DNSZone.group_id == group_id)))
        .scalars()
        .all()
    }
    assert zones["example.com."].ttl == 7200  # the source's, not 5400
    assert zones["fwd.example."].ttl == 5400  # no SOA: the stored default
