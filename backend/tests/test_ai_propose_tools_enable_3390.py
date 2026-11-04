"""An operator can switch on every ``propose_*`` tool, and the Copilot then offers it (#3390).

``propose_set_zone_update_acl`` (#641) and ``propose_allowlist_bgp_origin`` (#527)
ship ``default_enabled=False`` so the operator opts in from Settings → AI → Tool
Catalog, like the other ``propose_*`` tools. Both were registered ``writes=True``,
and the Tool Catalog's save, the effective tool set and the chat's tool list keep
only tools that do not write: the save dropped them, so neither could ever be
enabled. A propose tool only previews the change and stores a proposal row; the
operator's Apply is the write. MCP never dispatches a ``propose_*`` tool, enabled
or not.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.ai import mcp as mcp_mod
from app.core.security import create_access_token, hash_password
from app.db import _json_serializer
from app.models.ai import AIOperationProposal
from app.models.asn import ASN
from app.models.auth import User
from app.models.bgp_monitor import BGPHijackDetection, BGPTrackedPrefix
from app.models.dns import DNSServerGroup, DNSZone, DNSZoneUpdateAcl
from app.services.ai.chat import ChatOrchestrator
from app.services.ai.tools import REGISTRY

ZONE_ACL = "propose_set_zone_update_acl"
BGP_ORIGIN = "propose_allowlist_bgp_origin"


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Root",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _defaults() -> set[str]:
    return {t.name for t in REGISTRY.all() if t.default_enabled and not t.writes}


async def _enable(client: AsyncClient, headers: dict[str, str], *names: str) -> dict:
    r = await client.put(
        "/api/v1/ai/tools/catalog",
        json={"enabled": sorted(_defaults() | set(names))},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_every_propose_tool_is_registered_read_only() -> None:
    """The propose call only stages a proposal; the operator's Apply is the
    write. MCP's guard and the catalog both rely on it (``mcp.py``)."""
    offenders = sorted(t.name for t in REGISTRY.all() if t.name.startswith("propose_") and t.writes)
    assert offenders == []


@pytest.mark.parametrize("name", [ZONE_ACL, BGP_ORIGIN])
async def test_catalog_save_keeps_an_enabled_propose_tool(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    tool = REGISTRY.get(name)
    assert tool is not None and tool.default_enabled is False
    _, h = await _superadmin(db_session)

    body = await _enable(client, h, name)

    assert name in body["platform_override"]
    (entry,) = [t for t in body["tools"] if t["name"] == name]
    assert entry["enabled"] is True
    # Read back, as the Tool Catalog page does after the save.
    again = (await client.get("/api/v1/ai/tools", headers=h)).json()
    (entry,) = [t for t in again["tools"] if t["name"] == name]
    assert entry["enabled"] is True


@pytest.mark.parametrize("name", [ZONE_ACL, BGP_ORIGIN])
async def test_enabled_propose_tool_reaches_the_chat(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    user, h = await _superadmin(db_session)
    chat = ChatOrchestrator(db_session, user)
    assert name not in {t.name for t in await chat._tools_for_request()}  # default off

    await _enable(client, h, name)

    assert name in {t.name for t in await chat._tools_for_request()}


async def test_mcp_never_offers_an_enabled_propose_tool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    await _enable(client, h, ZONE_ACL, BGP_ORIGIN)

    names = await mcp_mod._mcp_tool_names(db_session, token_scopes=[])
    assert ZONE_ACL not in names
    assert BGP_ORIGIN not in names


@pytest_asyncio.fixture
async def app_session(db_session: AsyncSession) -> AsyncGenerator[AsyncSession, None]:
    """A session on the test database whose engine serializes JSONB as the
    app's engine does (``app.db``): a proposal's stored args carry UUIDs."""
    engine = create_async_engine(
        db_session.bind.url, poolclass=NullPool, json_serializer=_json_serializer
    )
    async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as s:
        yield s
    await engine.dispose()


async def _stage_through_the_chat(
    db: AsyncSession, user_id: uuid.UUID, name: str, args: dict
) -> tuple[dict, list[AIOperationProposal]]:
    """Call ``name`` the way the chat does: gated by the tool list it sends
    the model (``ChatOrchestrator.stream_turn``)."""
    user = await db.get(User, user_id)
    assert user is not None
    effective = {t.name for t in await ChatOrchestrator(db, user)._tools_for_request()}
    result = await REGISTRY.call(name, args, db=db, user=user, effective=effective)
    stmt = select(AIOperationProposal).where(AIOperationProposal.user_id == user_id)
    return result, list((await db.execute(stmt)).scalars().all())


async def test_chat_call_of_propose_set_zone_update_acl_only_stages_a_proposal(
    client: AsyncClient, db_session: AsyncSession, app_session: AsyncSession
) -> None:
    user, h = await _superadmin(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=False,
    )
    db_session.add(zone)
    await db_session.commit()
    await _enable(client, h, ZONE_ACL)

    result, proposals = await _stage_through_the_chat(
        app_session,
        user.id,
        ZONE_ACL,
        {
            "group_id": str(group.id),
            "zone_id": str(zone.id),
            "dynamic_update_enabled": True,
            "entries": [{"match_kind": "ip", "ip_cidr": "192.0.2.10/32"}],
        },
    )

    assert result["kind"] == "proposal", result
    (proposal,) = proposals
    assert proposal.operation == "set_zone_update_acl"
    assert proposal.applied_at is None
    # Nothing written until the operator applies it.
    stored = await app_session.get(DNSZone, zone.id)
    assert stored is not None and stored.dynamic_update_enabled is False
    acl = await app_session.execute(
        select(DNSZoneUpdateAcl).where(DNSZoneUpdateAcl.zone_id == zone.id)
    )
    assert acl.all() == []


async def test_chat_call_of_propose_allowlist_bgp_origin_only_stages_a_proposal(
    client: AsyncClient, db_session: AsyncSession, app_session: AsyncSession
) -> None:
    user, h = await _superadmin(db_session)
    asn = ASN(number=64500, name="AS64500", kind="public", registry="arin")
    db_session.add(asn)
    await db_session.flush()
    tracked = BGPTrackedPrefix(
        asn_id=asn.id,
        prefix="192.0.2.0/24",
        expected_origin_asn=64500,
        source="manual",
        enabled=True,
        allowed_origins=[],
    )
    db_session.add(tracked)
    await db_session.flush()
    now = datetime.now(UTC)
    det = BGPHijackDetection(
        tracked_prefix_id=tracked.id,
        asn_id=asn.id,
        tracked_prefix="192.0.2.0/24",
        observed_prefix="192.0.2.0/24",
        expected_origin_asn=64500,
        observed_origin_asn=64999,
        detection_kind="prefix_hijack",
        rpki_status="invalid",
        severity="critical",
        source="ripestat_poll",
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(det)
    await db_session.commit()
    await _enable(client, h, BGP_ORIGIN)

    result, proposals = await _stage_through_the_chat(
        app_session, user.id, BGP_ORIGIN, {"detection_id": str(det.id)}
    )

    assert result["kind"] == "proposal", result
    (proposal,) = proposals
    assert proposal.operation == "allowlist_bgp_origin"
    assert proposal.applied_at is None
    # Nothing written until the operator applies it.
    stored_prefix = await app_session.get(BGPTrackedPrefix, tracked.id)
    stored_det = await app_session.get(BGPHijackDetection, det.id)
    assert stored_prefix is not None and stored_prefix.allowed_origins == []
    assert stored_det is not None and stored_det.acknowledged is False
