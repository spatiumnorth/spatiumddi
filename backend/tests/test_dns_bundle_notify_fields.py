"""The bundle ships the NOTIFY fields + zone overrides (#1523).

``DNSServerOptions.notify_enabled`` / ``also_notify`` / ``allow_notify``
and ``DNSZone.allow_query`` / ``also_notify`` / ``notify_enabled`` were
accepted, validated (#1316) and persisted, but absent from the agent
config bundle, so neither agent could render them: a stealth primary
still sent NOTIFY, also-notify targets were never notified, and a
zone-level allow_query was never enforced — while the API and UI
reported the settings as saved.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSZone
from app.models.settings import PlatformSettings
from app.services.dns.agent_config import render_bundle_body


def _id(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


async def _server_with(
    db: AsyncSession, *, options: dict[str, Any], zone: dict[str, Any]
) -> tuple[DNSServer, DNSServerOptions]:
    group = DNSServerGroup(id=_id(0x3000), name="notify-guard", description="")
    db.add(group)
    await db.flush()
    server = DNSServer(
        id=_id(0x3001),
        agent_id=_id(0x3002),
        group_id=group.id,
        name="notify-ns1",
        host="192.0.2.53",
        port=53,
        driver="bind9",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    opts = DNSServerOptions(group_id=group.id, **options)
    db.add(opts)
    db.add(
        DNSZone(
            id=_id(0x3010),
            group_id=group.id,
            name="example.test.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.test.",
            admin_email="hostmaster.example.test.",
            last_serial=2026100401,
            **zone,
        )
    )
    await db.flush()
    return server, opts


@pytest.mark.asyncio
async def test_bundle_ships_server_notify_options(db_session: AsyncSession) -> None:
    db_session.add(PlatformSettings(id=1))
    server, _opts = await _server_with(
        db_session,
        options={
            "notify_enabled": "no",
            "also_notify": ["192.0.2.53", "192.0.2.54 port 5300"],
            "allow_notify": ["192.0.2.0/24"],
        },
        zone={},
    )
    body = (await render_bundle_body(db_session, server)).body
    assert body["options"]["notify_enabled"] == "no"
    assert body["options"]["also_notify"] == ["192.0.2.53", "192.0.2.54 port 5300"]
    assert body["options"]["allow_notify"] == ["192.0.2.0/24"]


@pytest.mark.asyncio
async def test_bundle_ships_zone_notify_and_query_overrides(
    db_session: AsyncSession,
) -> None:
    db_session.add(PlatformSettings(id=1))
    server, _opts = await _server_with(
        db_session,
        options={},
        zone={
            "allow_query": ["192.0.2.0/24"],
            "also_notify": ["192.0.2.99"],
            "notify_enabled": "explicit",
        },
    )
    body = (await render_bundle_body(db_session, server)).body
    (zone,) = body["zones"]
    assert zone["allow_query"] == ["192.0.2.0/24"]
    assert zone["also_notify"] == ["192.0.2.99"]
    assert zone["notify_enabled"] == "explicit"


@pytest.mark.asyncio
async def test_bundle_zone_overrides_default_to_none_and_options_to_yes(
    db_session: AsyncSession,
) -> None:
    """None = inherit. The agents key zone-clause rendering off it, so the
    bundle must carry a real None, not a copied server value."""
    db_session.add(PlatformSettings(id=1))
    server, _opts = await _server_with(db_session, options={}, zone={})
    body = (await render_bundle_body(db_session, server)).body
    (zone,) = body["zones"]
    assert zone["allow_query"] is None
    assert zone["also_notify"] is None
    assert zone["notify_enabled"] is None
    assert body["options"]["notify_enabled"] == "yes"
    assert body["options"]["also_notify"] == []
    assert body["options"]["allow_notify"] == []


@pytest.mark.asyncio
async def test_notify_change_moves_the_structural_etag(
    db_session: AsyncSession,
) -> None:
    """The fields live inside the structural fingerprint (options_block +
    zones_structural), so toggling one must re-render the agent config —
    the #899 failure mode is a saved setting that never wakes the agent."""
    db_session.add(PlatformSettings(id=1))
    server, opts = await _server_with(
        db_session, options={"notify_enabled": "yes"}, zone={}
    )
    before = (await render_bundle_body(db_session, server)).body["structural_etag"]
    opts.notify_enabled = "no"
    await db_session.flush()
    after = (await render_bundle_body(db_session, server)).body["structural_etag"]
    assert before != after
