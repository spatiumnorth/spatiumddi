"""A forward zone's upstream transport is its own setting (#2121).

Before #2121 a forward zone inherited the server group's ``forward_transport``
(#50), so a group forwarding to Cloudflare over DoT also sent a Tailscale
tailnet zone's queries to 100.100.100.100:853 over TLS, checked against
``cloudflare-dns.com``. Nothing answers there, and every name SERVFAILed.

Covered here: the shared renderer helper (byte-identical with the agent's
copy, pinned by the same vectors as ``agent/dns/tests/
test_zone_forward_transport_render.py``), the control-plane template's
rendered output, the config bundle + etag, the API's 422s, the zone move,
and the migration's backfill default. The agent's rendered named.conf is
covered agent-side.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns._forwarders import bind_zone_forwarder, zone_tls_statement_name
from app.drivers.dns.base import ConfigBundle, ServerOptions, ZoneData
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSZone
from app.services.dns.agent_config import build_config_bundle

_BACKEND_HELPER = Path(__file__).parents[1] / "app/drivers/dns/_forwarders.py"
_AGENT_HELPER = Path(__file__).parents[2] / "agent/dns/spatium_dns_agent/drivers/_forwarders.py"
_MIGRATION = (
    Path(__file__).parents[1] / "alembic/versions/c4f8a2e61d37_dns_zone_forward_transport.py"
)

TAILNET = "example-tailnet.ts.net."

# Same table as the agent's test (#878: two renderers, one behaviour).
FORWARDER_VECTORS = [
    ("100.100.100.100", None, "100.100.100.100"),
    ("100.100.100.100@53", None, "100.100.100.100 port 53"),
    ("10.0.0.1@5353", None, "10.0.0.1 port 5353"),
    ("9.9.9.9", "T", "9.9.9.9 port 853 tls T"),
    ("9.9.9.9@8853", "T", "9.9.9.9 port 8853 tls T"),
    ("100.100.100.100@53", "T", "100.100.100.100 port 53"),
    ("2620:fe::fe", "T", "2620:fe::fe port 853 tls T"),
]


# ── Shared helper ───────────────────────────────────────────────────────────


@pytest.mark.skipif(not _AGENT_HELPER.exists(), reason="agent package not in this checkout")
def test_the_forwarder_helper_matches_the_agent_copy() -> None:
    assert _BACKEND_HELPER.read_bytes() == _AGENT_HELPER.read_bytes()


@pytest.mark.parametrize("entry,tls_name,expected", FORWARDER_VECTORS)
def test_forwarder_vectors(entry: str, tls_name: str | None, expected: str) -> None:
    assert bind_zone_forwarder(entry, tls_name) == expected


# ── Control-plane template (the config preview) ─────────────────────────────


def _zone(name: str, forwarders: tuple[str, ...], **kw: object) -> ZoneData:
    return ZoneData(
        name=name,
        zone_type="forward",
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="",
        admin_email="",
        serial=1,
        forwarders=forwarders,
        **kw,  # type: ignore[arg-type]
    )


def _render(zones: tuple[ZoneData, ...], opts: ServerOptions) -> str:
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=opts,
        acls=(),
        views=(),
        zones=zones,
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 10, 18, 12, 0, tzinfo=UTC),
    )
    return BIND9Driver().render_server_config(
        SimpleNamespace(id=bundle.server_id, name="ns1"), opts, bundle=bundle
    )


DOT_GROUP = ServerOptions(
    forwarders=("1.1.1.1", "1.0.0.1"),
    forward_transport="tls",
    forward_tls_hostname="cloudflare-dns.com",
)


def _stanza(conf: str, name: str) -> str:
    start = conf.index(f'zone "{name}"')
    return conf[start : conf.index("};\n", conf.index("forwarders", start)) + 3]


def test_template_do53_zone_in_a_dot_group_has_no_tls() -> None:
    conf = _render((_zone(TAILNET, ("100.100.100.100",)),), DOT_GROUP)
    stanza = _stanza(conf, TAILNET)
    assert "forwarders { 100.100.100.100; };" in stanza
    assert "tls" not in stanza
    assert "spatium-zone-tls-" not in conf


def test_template_renders_ip_at_port_loadably() -> None:
    """The template used to emit the wire shape verbatim: ``1.1.1.1@53;``."""
    conf = _render((_zone("lab.example.", ("10.0.0.1@53", "10.0.0.2@5353")),), ServerOptions())
    stanza = _stanza(conf, "lab.example.")
    assert "forwarders { 10.0.0.1 port 53; 10.0.0.2 port 5353; };" in stanza
    assert "@" not in stanza


def test_template_tls_zone_has_its_own_statement() -> None:
    zone = _zone(
        "corp.example.",
        ("9.9.9.9", "10.9.9.9@53"),
        forward_transport="tls",
        forward_tls_hostname="dns.quad9.net",
    )
    conf = _render((zone,), ServerOptions(forwarders=("10.0.0.1",)))
    name = zone_tls_statement_name("dns.quad9.net")
    assert f"tls {name} {{" in conf
    assert 'remote-hostname "dns.quad9.net";' in conf
    assert conf.index(f"tls {name} {{") < conf.index("options {")
    stanza = _stanza(conf, "corp.example.")
    assert f"9.9.9.9 port 853 tls {name};" in stanza
    assert "10.9.9.9 port 53;" in stanza
    assert "spatium-upstream-tls" not in conf


def test_template_skips_a_zone_bind_cannot_render() -> None:
    zone = _zone(
        "corp.example.", ("9.9.9.9",), forward_transport="https", forward_tls_hostname="x.test"
    )
    assert 'zone "corp.example."' not in _render((zone,), ServerOptions())


# ── API ─────────────────────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str = "bind9") -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DNSServer(
            group_id=group.id,
            name=f"ns-{uuid.uuid4().hex[:4]}",
            driver=driver,
            host="10.0.0.53",
            port=53,
            is_primary=True,
        )
    )
    await db.flush()
    return group


def _fwd(name: str, forwarders: list[str], **extra: object) -> dict[str, object]:
    return {"name": name, "zone_type": "forward", "forwarders": forwarders, **extra}


async def test_create_defaults_to_plain_dns_in_a_dot_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session)
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            forwarders=["1.1.1.1"],
            forward_transport="tls",
            forward_tls_hostname="cloudflare-dns.com",
        )
    )
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd(TAILNET, ["100.100.100.100"]),
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["forward_transport"] == "do53"
    assert r.json()["forward_tls_hostname"] is None


async def test_create_tls_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd(
            "corp.example.",
            ["9.9.9.9"],
            forward_transport="tls",
            forward_tls_hostname="DNS.Quad9.net.",
        ),
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["forward_transport"] == "tls"
    assert r.json()["forward_tls_hostname"] == "dns.quad9.net"


@pytest.mark.parametrize(
    "extra,needle",
    [
        ({"forward_transport": "tls"}, "forward_tls_hostname is required"),
        ({"forward_transport": "tls", "forward_tls_hostname": 'x"; };'}, "forward_tls_hostname"),
        ({"forward_transport": "dot"}, "forward_transport must be one of"),
        (
            {"forward_transport": "https", "forward_tls_hostname": "dns.quad9.net"},
            "not supported for a forward zone by bind9",
        ),
        (
            {"forward_transport": "quic", "forward_tls_hostname": "dns.quad9.net"},
            "not supported for a forward zone by bind9",
        ),
    ],
)
async def test_create_refusals(
    client: AsyncClient, db_session: AsyncSession, extra: dict[str, object], needle: str
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd("corp.example.", ["9.9.9.9"], **extra),
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert needle in r.text


async def test_tls_zone_spanning_two_certificate_names_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The #877 rule, per zone: one hostname cannot validate both."""
    headers = await _headers(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd(
            "corp.example.",
            ["1.1.1.1", "8.8.8.8"],
            forward_transport="tls",
            forward_tls_hostname="cloudflare-dns.com",
        ),
        headers=headers,
    )
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    # Per-zone wording: the zone, its forwarders and its hostname, not the
    # group-level "one hostname applies to the whole group".
    assert "Forward zone 'corp.example.'" in detail
    assert "1.1.1.1" in detail and "8.8.8.8" in detail
    assert "forward_tls_hostname 'cloudflare-dns.com'" in detail
    assert "whole group" not in detail


async def test_do53_zone_to_an_encrypted_only_upstream_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd("corp.example.", ["194.242.2.4"]),
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "encrypted transport" in r.text


async def test_doh_zone_is_accepted_on_a_technitium_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session, driver="technitium")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json=_fwd(
            "corp.example.",
            ["9.9.9.9"],
            forward_transport="https",
            forward_tls_hostname="dns.quad9.net",
        ),
        headers=headers,
    )
    assert r.status_code == 201, r.text


async def test_update_sets_and_clears_the_transport(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session)
    zone = DNSZone(
        group_id=group.id, name=TAILNET, zone_type="forward", forwarders=["100.100.100.100"]
    )
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"

    r = await client.put(url, json={"forward_transport": "tls"}, headers=headers)
    assert r.status_code == 422, r.text
    assert "forward_tls_hostname is required" in r.text

    r = await client.put(
        url,
        json={"forward_transport": "tls", "forward_tls_hostname": "dns.quad9.net"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["forward_transport"] == "tls"

    r = await client.put(
        url, json={"forward_transport": "do53", "forward_tls_hostname": None}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["forward_transport"] == "do53"
    assert r.json()["forward_tls_hostname"] is None


async def test_an_unrelated_edit_to_a_stored_zone_is_not_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only a change is held to the gate: a zone stored before it (here a DoH
    zone a later BIND9 server now shares the group with) stays editable."""
    headers = await _headers(db_session)
    group = await _group(db_session)
    zone = DNSZone(
        group_id=group.id,
        name="corp.example.",
        zone_type="forward",
        forwarders=["9.9.9.9"],
        forward_transport="https",
        forward_tls_hostname="dns.quad9.net",
    )
    db_session.add(zone)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}",
        json={"forward_only": False},
        headers=headers,
    )
    assert r.status_code == 200, r.text


async def test_move_refuses_a_doh_zone_into_a_bind9_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    source = await _group(db_session, driver="technitium")
    target = await _group(db_session)
    zone = DNSZone(
        group_id=source.id,
        name="corp.example.",
        zone_type="forward",
        forwarders=["9.9.9.9"],
        forward_transport="https",
        forward_tls_hostname="dns.quad9.net",
    )
    db_session.add(zone)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{source.id}/zones/{zone.id}/move/commit",
        json={
            "target_group_id": str(target.id),
            "confirmation_zone_name": zone.name,
            "acknowledgements": [],
        },
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "not supported for a forward zone by bind9" in r.text


async def _stored_forward_zone(
    db: AsyncSession, group: DNSServerGroup, transport: str, forwarders: list[str]
) -> DNSZone:
    zone = DNSZone(
        group_id=group.id,
        name="corp.example.",
        zone_type="forward",
        forwarders=forwarders,
        forward_transport=transport,
        forward_tls_hostname=None if transport == "do53" else "dns.quad9.net",
    )
    db.add(zone)
    await db.commit()
    return zone


async def test_move_preview_reports_the_refusal_the_commit_raises(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The preview shows a transport the target cannot serve; before this
    follow-up only the commit 422'd, after the operator had filled the
    move in."""
    headers = await _headers(db_session)
    source = await _group(db_session, driver="technitium")
    target = await _group(db_session)
    zone = await _stored_forward_zone(db_session, source, "https", ["9.9.9.9"])
    r = await client.post(
        f"/api/v1/dns/groups/{source.id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(target.id)},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    refusal = r.json().get("forward_transport_refusal")
    assert refusal, r.text
    assert "not supported for a forward zone by bind9" in refusal
    assert target.name in refusal


@pytest.mark.parametrize(
    "source_driver,target_driver,transport,forwarders,refused",
    [
        ("technitium", "bind9", "https", ["9.9.9.9"], True),
        ("technitium", "bind9", "quic", ["9.9.9.9"], True),
        ("bind9", "windows_dns", "tls", ["9.9.9.9"], True),
        # A stored plain-DNS zone to an encrypted-only upstream (the #2121
        # backfill can produce one): refused on arrival, in both.
        ("technitium", "bind9", "do53", ["194.242.2.4"], True),
        ("technitium", "bind9", "tls", ["9.9.9.9"], False),
        ("bind9", "technitium", "do53", ["100.100.100.100"], False),
    ],
)
async def test_move_preview_and_commit_agree_on_the_forward_transport(
    client: AsyncClient,
    db_session: AsyncSession,
    source_driver: str,
    target_driver: str,
    transport: str,
    forwarders: list[str],
    refused: bool,
) -> None:
    headers = await _headers(db_session)
    source = await _group(db_session, driver=source_driver)
    target = await _group(db_session, driver=target_driver)
    zone = await _stored_forward_zone(db_session, source, transport, forwarders)
    base = f"/api/v1/dns/groups/{source.id}/zones/{zone.id}/move"
    preview = await client.post(
        f"{base}/preview", json={"target_group_id": str(target.id)}, headers=headers
    )
    assert preview.status_code == 200, preview.text
    refusal = preview.json().get("forward_transport_refusal")
    assert bool(refusal) is refused, preview.text

    commit = await client.post(
        f"{base}/commit",
        json={
            "target_group_id": str(target.id),
            "confirmation_zone_name": zone.name,
            "acknowledgements": preview.json()["required_acknowledgements"],
        },
        headers=headers,
    )
    if refused:
        assert commit.status_code == 422, commit.text
        assert commit.json()["detail"] == refusal
    else:
        assert commit.status_code == 200, commit.text


# ── Config bundle ───────────────────────────────────────────────────────────


async def test_bundle_carries_the_zone_transport_and_the_etag_moves(
    db_session: AsyncSession,
) -> None:
    group = await _group(db_session)
    zone = DNSZone(
        group_id=group.id, name=TAILNET, zone_type="forward", forwarders=["100.100.100.100"]
    )
    db_session.add(zone)
    await db_session.flush()
    server = (
        await db_session.execute(DNSServer.__table__.select().where(DNSServer.group_id == group.id))
    ).first()
    assert server is not None
    srv = await db_session.get(DNSServer, server.id)
    assert srv is not None

    before = await build_config_bundle(db_session, srv)
    shipped = {z["name"]: z for z in before["zones"]}[TAILNET]
    # A plain-DNS zone ships neither key: the agent reads their absence as
    # do53, and a group not using the feature keeps the bundle (and the etag)
    # it had before #2121, so an upgrade does not reload every agent.
    assert "forward_transport" not in shipped
    assert "forward_tls_hostname" not in shipped

    zone.forward_transport = "tls"
    zone.forward_tls_hostname = "dns.quad9.net"
    await db_session.flush()
    after = await build_config_bundle(db_session, srv)
    shipped = {z["name"]: z for z in after["zones"]}[TAILNET]
    assert shipped["forward_transport"] == "tls"
    assert shipped["forward_tls_hostname"] == "dns.quad9.net"
    assert before["etag"] != after["etag"]
    assert before["structural_etag"] != after["structural_etag"]

    # Back to plain DNS: the keys go again, and the bundle is the one a
    # zone that never had a transport ships.
    zone.forward_transport = "do53"
    zone.forward_tls_hostname = None
    await db_session.flush()
    reset = await build_config_bundle(db_session, srv)
    assert "forward_transport" not in {z["name"]: z for z in reset["zones"]}[TAILNET]
    assert reset["structural_etag"] == before["structural_etag"]


# ── Migration ───────────────────────────────────────────────────────────────


async def test_a_row_written_without_the_column_reads_do53(db_session: AsyncSession) -> None:
    """The column's server default IS the backfill: a forward zone stored
    before #2121 — in any group, DoT or not — reads plain DNS afterwards."""
    group = await _group(db_session)
    zid = uuid.uuid4()
    await db_session.execute(
        text(
            "INSERT INTO dns_zone (id, group_id, name, zone_type, kind, ttl, refresh, retry, "
            "expire, minimum, primary_ns, admin_email, last_serial, is_auto_generated, "
            "dnssec_enabled, forwarders) "
            "VALUES (:id, :g, 'legacy.example.', 'forward', 'forward', 3600, 86400, 7200, "
            "3600000, 3600, '', '', 0, false, false, '[\"100.100.100.100\"]'::jsonb)"
        ),
        {"id": zid, "g": group.id},
    )
    row = (
        await db_session.execute(
            text("SELECT forward_transport, forward_tls_hostname FROM dns_zone WHERE id = :id"),
            {"id": zid},
        )
    ).one()
    assert row.forward_transport == "do53"
    assert row.forward_tls_hostname is None


def test_the_migration_backfills_do53_not_null() -> None:
    src = _MIGRATION.read_text()
    assert 'down_revision = "b3d7f1a82c54"' in src
    assert "server_default=sa.text(\"'do53'\")" in src
    assert "nullable=False" in src
