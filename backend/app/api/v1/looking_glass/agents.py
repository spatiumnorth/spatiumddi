"""BGP Looking Glass collector agent endpoints: register, config long-poll,
heartbeat (session-state), RIB push.

Mirrors ``app.api.v1.dhcp.agents`` — the collector reuses the DNS/DHCP agent
protocol (PSK→JWT bootstrap, ConfigBundle ETag long-poll + Redis wake,
telemetry push). It is trimmed to the leaner ``LookingGlassCollector``
identity row (no server-group, no approval flow, no config-op queue, no
fleet/host-config plumbing — those ride the supervisor, not the LG agent).
"""

from __future__ import annotations

import asyncio
import hmac
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jose import JWTError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.deps import DB
from app.api.v1.dhcp._audit import write_audit
from app.core.agent_wake import (
    WAKE_TICK_SECONDS,
    looking_glass_wake_channels,
    wake_subscription,
)
from app.core.http_etag import etag_matches, format_etag
from app.models.bgp_looking_glass import BGPLGPeer, LookingGlassCollector
from app.services.agents.config_apply import apply_reported_status
from app.services.agents.server_gone import refresh_agent_server
from app.services.looking_glass.agent_token import (
    hash_token,
    mint_agent_token,
    needs_rotation,
    verify_agent_token,
)
from app.services.looking_glass.config_bundle import build_lg_config_bundle
from app.services.looking_glass.routes_ingest import ingest_routes

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/agents", tags=["looking-glass-agents"])

LONGPOLL_TIMEOUT_SECONDS = int(os.environ.get("LG_AGENT_LONGPOLL_TIMEOUT", "30"))


# ── Schemas ─────────────────────────────────────────────────────────────────


class AgentRegisterRequest(BaseModel):
    # Bounds mirror the collector columns (name/host 255, fingerprint 128)
    # — an over-length value used to reach asyncpg and surface as 500
    # instead of the 422 it is.
    hostname: str = Field(max_length=255)
    version: str | None = Field(default=None, max_length=64)
    fingerprint: str = Field(max_length=128)
    agent_id: str | None = None


class AgentRegisterResponse(BaseModel):
    collector_id: str
    agent_id: str
    agent_token: str
    token_expires_at: datetime
    config_etag: str | None


class PeerStateReport(BaseModel):
    """One per-peer runtime observation the collector relays each heartbeat.

    Every field except ``peer_id`` is optional so the handler only overwrites
    the columns the agent actually sent (leaving previously-known state intact
    for anything omitted), mirroring the DHCP slot-state discipline.
    """

    model_config = ConfigDict(extra="forbid")

    peer_id: str
    session_state: str | None = None
    uptime_started_at: datetime | None = None
    prefixes_received: int | None = None
    prefixes_accepted: int | None = None
    last_state_change: datetime | None = None
    last_flap_at: datetime | None = None
    rpki_invalid_count: int | None = None


class AgentHeartbeatRequest(BaseModel):
    # extra="forbid": reject a wrong-envelope heartbeat loudly instead of
    # validating into an all-default body that would silently drop the
    # per-peer state reports (mirrors the DHCP #482 hardening).
    model_config = ConfigDict(extra="forbid")

    # Bounded to the column (String(64)); the heartbeat is the OTHER route
    # the same value arrives by, and leaving it unbounded here would let
    # an over-length version in through the side door that register now
    # rejects at the field.
    agent_version: str | None = Field(default=None, max_length=64)
    peers: list[PeerStateReport] = Field(default_factory=list, max_length=5000)
    # #882 — the agent's last config-apply verdict:
    # ``{status, etag, failed_etag, phase, error}``. MUST be declared here:
    # this model is extra="forbid", so an undeclared field would 422 every
    # heartbeat from a current collector. Kept a loose dict for the same
    # reason as the DNS/DHCP agents — see their AgentHeartbeatRequest.
    config: dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeatResponse(BaseModel):
    collector_id: str
    status: str
    acknowledged_at: datetime
    rotated_token: str | None = None
    rotated_expires_at: datetime | None = None


class RouteEntry(BaseModel):
    """One learned path in a peer's Adj-RIB-In pushed by the collector."""

    model_config = ConfigDict(extra="forbid")

    prefix: str
    next_hop: str
    origin_asn: int | None = None
    as_path: list[int] = Field(default_factory=list)
    local_pref: int | None = None
    med: int | None = None
    communities: list[str] = Field(default_factory=list)
    large_communities: list[str] = Field(default_factory=list)
    ext_communities: list[str] = Field(default_factory=list)
    # Route Distinguisher (RFC 4364) — vpnv4/vpnv6 paths only. Optional
    # because the collector-side GoBGP RIB poll doesn't populate this yet
    # (issue #566 Phase 6 lands the API + ingest-side identity/matching;
    # the agent's VPNv4/VPNv6 wire support is a follow-up). ``None``/absent
    # is treated as "" (plain ipv4-unicast/ipv6-unicast path) by
    # ``routes_ingest.ingest_routes``.
    route_distinguisher: str | None = None
    is_best: bool = False


class RoutesPushRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    peer_id: str
    # snapshot=True → the full current RIB for this peer (runs the
    # absence-withdraw sweep); False → a delta batch (upsert-only).
    snapshot: bool = True
    # Generous cap so a full-table-ish snapshot fits one POST while a
    # malformed/hostile client still can't ship an unbounded batch.
    routes: list[RouteEntry] = Field(default_factory=list, max_length=100000)


# ── Auth ────────────────────────────────────────────────────────────────────


def _require_bootstrap_key(
    x_lg_agent_key: str | None = Header(default=None, alias="X-LG-Agent-Key"),
) -> str:
    expected = os.environ.get("LG_AGENT_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LG_AGENT_KEY is not configured on the control plane",
        )
    # Compare BYTES: hmac.compare_digest raises TypeError on a str with
    # non-ASCII characters, so any client that sent one (fuzz: '\x80')
    # got a 500 out of the auth gate instead of the 401 a wrong key is.
    if not x_lg_agent_key or not hmac.compare_digest(
        x_lg_agent_key.encode("utf-8", "surrogateescape"),
        expected.encode("utf-8", "surrogateescape"),
    ):
        raise HTTPException(status_code=401, detail="Invalid bootstrap key")
    return x_lg_agent_key


async def _auth_agent(
    db: DB, authorization: str | None = Header(default=None)
) -> tuple[LookingGlassCollector, dict[str, Any]]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        payload = verify_agent_token(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
    collector_id = payload.get("sub")
    if not collector_id:
        raise HTTPException(status_code=401, detail="Token missing subject")
    collector = await db.get(LookingGlassCollector, uuid.UUID(collector_id))
    if collector is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    if collector.agent_token_hash and collector.agent_token_hash != hash_token(token):
        raise HTTPException(status_code=401, detail="Stale token")
    return collector, payload


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/register", response_model=AgentRegisterResponse)
async def agent_register(
    request: Request,
    body: AgentRegisterRequest,
    db: DB,
    _psk: str = Depends(_require_bootstrap_key),
) -> AgentRegisterResponse:
    """Bootstrap registration — PSK → per-collector JWT. Idempotent on agent_id."""
    collector: LookingGlassCollector | None = None
    if body.agent_id:
        res = await db.execute(
            select(LookingGlassCollector).where(LookingGlassCollector.agent_id == body.agent_id)
        )
        collector = res.scalar_one_or_none()
    if collector is None:
        res = await db.execute(
            select(LookingGlassCollector).where(LookingGlassCollector.name == body.hostname)
        )
        collector = res.scalar_one_or_none()

    now = datetime.now(UTC)
    agent_id = body.agent_id or str(uuid.uuid4())
    if collector is None:
        collector = LookingGlassCollector(
            name=body.hostname,
            host=body.hostname,
            status="active",
            agent_id=agent_id,
            agent_registered=True,
            agent_version=body.version,
            description=(
                f"auto-registered agent v{body.version}" if body.version else "auto-registered"
            ),
            last_seen_at=now,
        )
        if request.client is not None:
            collector.last_seen_ip = request.client.host
        db.add(collector)
        await db.flush()
    else:
        collector.host = body.hostname
        collector.status = "active"
        collector.agent_registered = True
        collector.agent_version = body.version
        collector.last_seen_at = now
        if collector.agent_id is None:
            collector.agent_id = agent_id
        if request.client is not None:
            collector.last_seen_ip = request.client.host

    token, exp = mint_agent_token(
        collector_id=str(collector.id),
        agent_id=str(collector.agent_id),
        fingerprint=body.fingerprint,
    )
    collector.agent_token_hash = hash_token(token)

    # Compute the current bundle ETag so the agent's first /config poll can
    # immediately 304 if nothing has changed since register.
    bundle = await build_lg_config_bundle(db, collector)

    write_audit(
        db,
        user=None,
        action="looking_glass.agent.register",
        resource_type="looking_glass_collector",
        resource_id=str(collector.id),
        resource_display=body.hostname,
        new_value={"version": body.version},
    )
    await db.commit()
    await db.refresh(collector)

    logger.info(
        "lg_agent_registered",
        collector_id=str(collector.id),
        hostname=body.hostname,
    )
    return AgentRegisterResponse(
        collector_id=str(collector.id),
        agent_id=str(collector.agent_id),
        agent_token=token,
        token_expires_at=exp,
        config_etag=bundle.etag,
    )


@router.get("/config")
async def agent_config_longpoll(
    db: DB,
    response: Response,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    auth: tuple[LookingGlassCollector, dict[str, Any]] = Depends(_auth_agent),
) -> Any:
    """Long-poll for peer-config changes. 304 if unchanged, bundle JSON otherwise."""
    collector, _payload = auth

    deadline = asyncio.get_running_loop().time() + LONGPOLL_TIMEOUT_SECONDS
    async with wake_subscription(looking_glass_wake_channels(collector)) as wake:
        # #358 — subscribe before the first bundle build so a committed +
        # published peer change wakes this poll immediately; Redis-down
        # degrades to the WAKE_TICK_SECONDS sleep (the ETag compare stays
        # authoritative either way).
        while True:
            # #2040 — this session lives for the whole wait (expire_on_commit=
            # False, no commit in the loop). A re-query hands back the peer
            # rows already in the identity map without overwriting them, and
            # the collector row was never re-read at all, so a woken pass
            # rebuilt the bundle from the state the poll parked on: a peer
            # edit (address, ASN, MD5 secret, filter) or a collector disable
            # reached the agent only when the long-poll timed out. Expire
            # everything and refresh the collector so each pass reads
            # committed state, as the DHCP long-poll does.
            db.expire_all()
            await refresh_agent_server(db, collector)
            bundle = await build_lg_config_bundle(db, collector)
            etag = bundle.etag
            if not etag_matches(if_none_match, etag):
                logger.info(
                    "lg_agent_config_200",
                    collector_id=str(collector.id),
                    etag=etag,
                    if_none_match=if_none_match,
                )
                response.headers["ETag"] = format_etag(etag)
                return {
                    "collector_id": str(collector.id),
                    "etag": etag,
                    "bundle": {
                        "collector_name": bundle.collector_name,
                        "peers": [
                            {
                                "peer_id": p.peer_id,
                                "name": p.name,
                                "peer_address": p.peer_address,
                                "peer_asn": p.peer_asn,
                                "local_asn": p.local_asn,
                                "address_families": list(p.address_families),
                                "max_prefixes": p.max_prefixes,
                                "import_filter": p.import_filter,
                                # Decrypted MD5 secret — delivered ONLY here,
                                # over TLS, to the JWT-authed collector; never
                                # surfaced on an operator API.
                                "md5_password": p.md5_password,
                                "md5_password_set": p.md5_password_set,
                            }
                            for p in bundle.peers
                        ],
                    },
                }
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return Response(status_code=304, headers={"ETag": format_etag(etag)})
            await wake.wait(min(WAKE_TICK_SECONDS, remaining))


@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
    request: Request,
    body: AgentHeartbeatRequest,
    db: DB,
    auth: tuple[LookingGlassCollector, dict[str, Any]] = Depends(_auth_agent),
) -> AgentHeartbeatResponse:
    collector, payload = auth
    now = datetime.now(UTC)
    collector.last_seen_at = now
    collector.last_health_check_at = now
    collector.status = "active"
    if request.client is not None:
        collector.last_seen_ip = request.client.host
    if body.agent_version:
        collector.agent_version = body.agent_version

    # #882 — the config-apply verdict. The collector's own SyncLoop has set a
    # ``daemon_status`` since it was written and the heartbeat never carried
    # it, so a peer set that failed to render was invisible from here.
    apply_reported_status(
        collector, body.config, agent_kind="looking_glass", server_id=str(collector.id)
    )

    # Per-peer runtime state — only overwrite the columns the agent sent.
    for rep in body.peers:
        try:
            pid = uuid.UUID(rep.peer_id)
        except ValueError:
            continue
        peer = await db.get(BGPLGPeer, pid)
        if peer is None or peer.collector_id != collector.id:
            continue
        if rep.session_state is not None:
            peer.session_state = rep.session_state
        # uptime_started_at is only meaningful while the session is
        # Established. A plain ``is not None`` merge can't tell an
        # agent-sent explicit null (session flapped down) from an omitted
        # field, so on a flap-down the stale established-at timestamp would
        # freeze and consumers would report a bogus multi-hour uptime for a
        # session that is actually down. Clear it whenever the collector
        # reports a non-established state; apply the agent's value otherwise.
        if rep.uptime_started_at is not None:
            peer.uptime_started_at = rep.uptime_started_at
        elif rep.session_state is not None and rep.session_state != "established":
            peer.uptime_started_at = None
        if rep.prefixes_received is not None:
            peer.prefixes_received = rep.prefixes_received
        if rep.prefixes_accepted is not None:
            peer.prefixes_accepted = rep.prefixes_accepted
        if rep.last_state_change is not None:
            peer.last_state_change = rep.last_state_change
        if rep.last_flap_at is not None:
            peer.last_flap_at = rep.last_flap_at
        if rep.rpki_invalid_count is not None:
            peer.rpki_invalid_count = rep.rpki_invalid_count

    rotated_token = None
    rotated_exp = None
    if needs_rotation(payload):
        rotated_token, rotated_exp = mint_agent_token(
            collector_id=str(collector.id),
            agent_id=str(collector.agent_id),
            fingerprint=payload.get("fingerprint", ""),
        )
        collector.agent_token_hash = hash_token(rotated_token)

    await db.commit()
    return AgentHeartbeatResponse(
        collector_id=str(collector.id),
        status=collector.status,
        acknowledged_at=now,
        rotated_token=rotated_token,
        rotated_expires_at=rotated_exp,
    )


@router.post("/routes")
async def agent_routes(
    body: RoutesPushRequest,
    db: DB,
    auth: tuple[LookingGlassCollector, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest a peer's pushed Adj-RIB-In and reconcile into ``BGPLGRoute``.

    A ``snapshot`` push is the peer's complete current RIB and runs the
    absence-withdraw sweep (with the zero-wire floor guard); a delta push
    is upsert-only. See ``services.looking_glass.routes_ingest``.
    """
    collector, _ = auth
    try:
        pid = uuid.UUID(body.peer_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid peer_id: {e}") from e
    peer = await db.get(BGPLGPeer, pid)
    if peer is None or peer.collector_id != collector.id:
        raise HTTPException(status_code=404, detail="Peer not found")

    result = await ingest_routes(
        db,
        peer,
        [r.model_dump() for r in body.routes],
        snapshot=body.snapshot,
    )
    await db.commit()
    return {
        "wire_routes": result.wire_routes,
        "imported": result.imported,
        "refreshed": result.refreshed,
        "withdrawn": result.withdrawn,
        "errors": result.errors,
    }
