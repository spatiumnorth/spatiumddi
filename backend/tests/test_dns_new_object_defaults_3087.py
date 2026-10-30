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
async def test_auto_registered_group_takes_the_stored_defaults(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A group an agent's registration creates is seeded like a REST create."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-3087")
    await _set_defaults(
        db_session, dns_recursive_by_default=False, dns_default_dnssec_validation="yes"
    )
    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-3087"},
        json={
            "hostname": "ns-auto",
            "fingerprint": "fp-3087",
            "driver": "bind9",
            "roles": ["authoritative"],
            "agent_id": str(uuid.uuid4()),
            "group_name": "auto-registered",
        },
    )
    assert reg.status_code == 200, reg.text

    db_session.expire_all()
    group = (
        await db_session.execute(
            select(DNSServerGroup).where(DNSServerGroup.name == "auto-registered")
        )
    ).scalar_one()
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


# ── validation review follow-ups ─────────────────────────────────────────


async def _technitium_api_group(db: AsyncSession) -> DNSServerGroup:
    from app.models.dns import DNSServer

    grp = DNSServerGroup(name=f"tapi-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            name="tapi",
            driver="technitium_api",
            host="tapi.example.com",
            port=53,
            is_enabled=True,
            is_primary=True,
        )
    )
    await db.flush()
    return grp


@pytest.mark.asyncio
async def test_technitium_api_zone_create_without_ttl_keeps_the_stock_ttl(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agentless Technitium driver never writes a zone TTL and its scope
    gate refuses anything but the stock value (#1784): an omitted TTL there
    must not become the stored default and turn the create into a 422."""
    from app.api.v1.dns import router as dns_router

    async def _no_push(*_a: object, **_k: object) -> list[str]:
        return []

    monkeypatch.setattr(dns_router, "_push_zone_to_agentless_servers", _no_push)
    headers = await _superadmin(db_session)
    group = await _technitium_api_group(db_session)
    await _set_defaults(db_session, dns_default_ttl=5400)

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones", json={"name": "t.test."}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["ttl"] == 3600


@pytest.mark.asyncio
async def test_copilot_zone_ttl_on_technitium_api_is_the_stock_ttl(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import CreateDNSZoneArgs, _effective_zone_ttl

    group = await _technitium_api_group(db_session)
    other = DNSServerGroup(name=f"plain-{uuid.uuid4().hex[:6]}")
    db_session.add(other)
    await db_session.flush()
    await _set_defaults(db_session, dns_default_ttl=5400)

    args = CreateDNSZoneArgs(name="c.test.")
    assert await _effective_zone_ttl(db_session, args, group.id) == 3600
    assert await _effective_zone_ttl(db_session, args, other.id) == 5400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("dns_default_ttl", -1),
        ("dns_default_ttl", 2**31),
        ("dns_default_zone_type", "master"),
        ("dns_default_dnssec_validation", "bogus"),
    ],
)
async def test_settings_refuse_a_dns_default_the_seeded_object_would_refuse(
    client: AsyncClient, db_session: AsyncSession, field: str, value: object
) -> None:
    """``dns_default_dnssec_validation`` is rendered into named.conf, and a
    value BIND rejects stops the whole group converging."""
    headers = await _superadmin(db_session)
    await _set_defaults(db_session)
    r = await client.put("/api/v1/settings", json={field: value}, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_a_bad_stored_default_falls_back_to_the_builtin(db_session: AsyncSession) -> None:
    """A row stored while the settings were inert (no validation then) must
    not reach a zone or named.conf."""
    from app.services.dns.new_object_defaults import load_dns_defaults

    await _set_defaults(
        db_session,
        dns_default_ttl=-5,
        dns_default_zone_type="master",
        dns_default_dnssec_validation="bogus",
        dns_recursive_by_default=False,
    )
    d = await load_dns_defaults(db_session)
    assert (d.ttl, d.zone_type, d.dnssec_validation, d.recursive) == (
        3600,
        "primary",
        "auto",
        False,
    )


@pytest.mark.asyncio
async def test_options_row_at_stock_defaults_renders_like_no_row(
    db_session: AsyncSession,
) -> None:
    """Agent auto-registration now writes an options row. At the stock
    defaults it must ship the options block a row-less group always did, or
    a fresh agent's named.conf would differ from before."""
    from app.models.dns import DNSServer
    from app.services.dns.agent_config import render_bundle_body

    await _set_defaults(db_session)
    rendered = []
    for with_row in (False, True):
        grp = DNSServerGroup(name=f"g-{with_row}")
        db_session.add(grp)
        await db_session.flush()
        srv = DNSServer(
            group_id=grp.id,
            name=f"s-{with_row}",
            driver="bind9",
            host="127.0.0.1",
            port=53,
            is_enabled=True,
            is_primary=True,
        )
        db_session.add(srv)
        if with_row:
            from app.services.dns.new_object_defaults import load_dns_defaults

            db_session.add(
                DNSServerOptions(
                    group=grp,
                    dnssec_validation=(await load_dns_defaults(db_session)).dnssec_validation,
                )
            )
        await db_session.flush()
        rendered.append((await render_bundle_body(db_session, srv)).body["options"])
    assert rendered[0] == rendered[1]
