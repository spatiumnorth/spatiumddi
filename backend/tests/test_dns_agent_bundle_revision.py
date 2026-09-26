"""A renderer change without a ``RENDERER_REVISION`` bump fails here (#1185).

A process serves a stored DNS bundle only when it came from its own renderer
revision or a newer one. So a change that alters what the renderer emits for
the same database state, without a bump, keeps serving the old renderer's
bytes after an upgrade until something unrelated marks each server: the
defect ``bundle_app_version`` was added to fix, and that #1185 replaced with
the revision.

This renders two fixed groups (one plain, one split-horizon) and compares the
stored bytes with a digest pinned to the current revision. When the renderer
changes on purpose, bump ``RENDERER_REVISION`` in
``app/services/dns/agent_bundle_store.py`` and add the new digests here under
the new revision.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import (
    DNSAcl,
    DNSAclEntry,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSView,
    DNSZone,
)
from app.models.settings import PlatformSettings
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_config import render_bundle_body

# Every stored-body digest per revision. Add a new entry when you bump; never
# edit an old one, so a bump without a real change still has to be explained.
PINNED_DIGESTS: dict[int, dict[str, str]] = {
    1: {
        "plain": "c69af6546ce6118fe11c4abfeb4abc230e7d4c8b33c679444fa6e06cfba33748",
        "views": "1e70781c25f21f3563a0800205adfaef09b615eb0990e0f4ab8569f9d02bb7a0",
    },
}


def _id(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


def _record(n: int, zone: DNSZone, name: str, rtype: str, value: str, **kw: Any) -> DNSRecord:
    fqdn = zone.name if name == "@" else f"{name}.{zone.name}"
    return DNSRecord(
        id=_id(n), zone_id=zone.id, name=name, fqdn=fqdn, record_type=rtype, value=value, **kw
    )


async def _server(db: AsyncSession, n: int, name: str) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(id=_id(n), name=name, description="revision guard")
    db.add(group)
    await db.flush()
    server = DNSServer(
        id=_id(n + 1),
        agent_id=_id(n + 2),
        group_id=group.id,
        name=f"{name}-ns1",
        host="192.0.2.53",
        port=53,
        driver="bind9",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return group, server


def _zone(n: int, group: DNSServerGroup, name: str, *, kind: str = "forward", **kw: Any) -> DNSZone:
    return DNSZone(
        id=_id(n),
        group_id=group.id,
        name=name,
        zone_type="primary",
        kind=kind,
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
        last_serial=2026092501,
        **kw,
    )


async def _plain(db: AsyncSession) -> DNSServer:
    group, server = await _server(db, 0x1000, "guard-plain")
    db.add(
        DNSServerOptions(
            group_id=group.id,
            forwarders=["192.0.2.1", "192.0.2.2"],
            allow_query=["any"],
        )
    )
    acl = DNSAcl(id=_id(0x1010), group_id=group.id, name="trusted", description="")
    db.add(acl)
    await db.flush()
    db.add_all(
        [
            DNSAclEntry(id=_id(0x1011), acl_id=acl.id, value="192.0.2.0/24", order=0),
            DNSAclEntry(id=_id(0x1012), acl_id=acl.id, value="2001:db8::/32", order=1),
        ]
    )
    forward = _zone(0x1020, group, "example.test.")
    reverse = _zone(0x1021, group, "2.0.192.in-addr.arpa.", kind="reverse")
    db.add_all([forward, reverse])
    await db.flush()
    db.add_all(
        [
            _record(0x1100, forward, "www", "A", "192.0.2.10"),
            _record(0x1101, forward, "www", "AAAA", "2001:db8::10"),
            _record(0x1102, forward, "alias", "CNAME", "www.example.test."),
            _record(0x1103, forward, "@", "MX", "mail.example.test.", priority=10),
            _record(0x1104, forward, "@", "TXT", "v=spf1 -all", ttl=300),
            _record(
                0x1105,
                forward,
                "_sip._tcp",
                "SRV",
                "sip.example.test.",
                priority=10,
                weight=5,
                port=5060,
            ),
            _record(0x1106, forward, "@", "CAA", '0 issue "letsencrypt.org"'),
            _record(0x1107, reverse, "10", "PTR", "www.example.test."),
        ]
    )
    await db.flush()
    return server


async def _views(db: AsyncSession) -> DNSServer:
    group, server = await _server(db, 0x2000, "guard-views")
    internal = DNSView(
        id=_id(0x2010),
        group_id=group.id,
        name="internal",
        match_clients=["192.0.2.0/24"],
        order=0,
    )
    external = DNSView(
        id=_id(0x2011), group_id=group.id, name="external", match_clients=["any"], order=1
    )
    db.add_all([internal, external])
    await db.flush()
    zone = _zone(0x2020, group, "split.test.")
    db.add(zone)
    await db.flush()
    db.add_all(
        [
            _record(0x2100, zone, "www", "A", "192.0.2.20", view_id=internal.id),
            _record(0x2101, zone, "www", "A", "198.51.100.20", view_id=external.id),
            _record(0x2102, zone, "shared", "A", "198.51.100.21"),
        ]
    )
    await db.flush()
    return server


async def _digest(db: AsyncSession, server: DNSServer) -> str:
    rendered = await render_bundle_body(db, server)
    return hashlib.sha256(store.encode_body(rendered.body)).hexdigest()


@pytest.mark.asyncio
async def test_the_renderer_output_matches_its_revision(db_session: AsyncSession) -> None:
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    digests = {
        "plain": await _digest(db_session, await _plain(db_session)),
        "views": await _digest(db_session, await _views(db_session)),
    }
    revision = store.RENDERER_REVISION
    assert (
        revision in PINNED_DIGESTS
    ), f"RENDERER_REVISION is {revision}; add PINNED_DIGESTS[{revision}] = {digests!r}"
    assert digests == PINNED_DIGESTS[revision], (
        "The DNS agent bundle renderer's output changed. If that is intended, "
        "bump RENDERER_REVISION in app/services/dns/agent_bundle_store.py and add "
        f"PINNED_DIGESTS[{revision + 1}] = {digests!r} here. Without the bump, "
        "servers keep serving bundles from the old renderer after an upgrade."
    )
