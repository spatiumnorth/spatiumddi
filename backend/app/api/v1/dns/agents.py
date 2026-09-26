"""DNS agent endpoints: register, heartbeat, config long-poll, record-ops, ops/ack.

See docs/deployment/DNS_AGENT.md §§2-5 for the full protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import uuid
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from jose import JWTError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB
from app.config import settings
from app.core.agent_wake import (
    WAKE_TICK_SECONDS,
    dns_wake_channels,
    wake_subscription,
)
from app.core.http_etag import etag_matches, format_etag
from app.core.redis_client import make_async_redis
from app.drivers.dns import get_driver as get_dns_driver
from app.metrics import (
    AGENT_BUNDLE_INLINE_FAILURES,
    AGENT_BUNDLE_INLINE_RENDERS,
    AGENT_BUNDLE_SERVED,
)
from app.models.audit import AuditLog
from app.models.dns import (
    DNSAgentBundle,
    DNSKey,
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSServerRuntimeState,
    DNSServerZoneState,
    DNSZone,
)
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DNSQueryLogEntry
from app.models.metrics import DNSMetricSample
from app.services.agents.config_apply import apply_reported_status
from app.services.agents.daemon_state import apply_reported_daemon_state
from app.services.agents.ingest_receipt import (
    BatchId,
    IngestAck,
    claim_batch,
    duplicate_response,
)
from app.services.agents.spool_status import apply_reported_spool
from app.services.dns import agent_bundle_store as bundle_store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_bundle_store import RENDERED_BY_API, encode_body
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.agent_token import (
    hash_token,
    mint_agent_token,
    needs_rotation,
    verify_agent_token,
)
from app.services.dns.bundle_dirty import enqueue_renders
from app.services.dns.record_ops import ack_op
from app.services.dns.tsig import ensure_group_tsig_key
from app.services.feature_modules import is_module_enabled
from app.tasks.prune_logs import DEFAULT_RETENTION_HOURS as QUERY_LOG_RETENTION_HOURS

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/agents", tags=["dns-agents"])

LONGPOLL_TIMEOUT_SECONDS = int(os.environ.get("DNS_AGENT_LONGPOLL_TIMEOUT", "30"))
LONGPOLL_POLL_INTERVAL = 2.0


# ── Schemas ────────────────────────────────────────────────────────────────────


class AgentRegisterRequestV2(BaseModel):
    # Bounds mirror the columns these land in (DNSServer.name/host 255,
    # .driver 50, .agent_fingerprint 128, DNSServerGroup.name 255) — an
    # over-length value used to reach asyncpg and surface as 500 instead
    # of the 422 it is.
    hostname: str = Field(max_length=255)
    driver: str = Field(default="bind9", max_length=50)
    roles: list[str] = ["authoritative"]
    version: str | None = Field(default=None, max_length=64)
    group_name: str | None = Field(default=None, max_length=255)
    fingerprint: str = Field(max_length=128)
    agent_id: str | None = None  # persisted UUID from previous runs


class AgentRegisterResponseV2(BaseModel):
    server_id: str
    agent_id: str
    agent_token: str
    token_expires_at: datetime
    config_etag: str | None
    pending_approval: bool


class AgentHeartbeatRequest(BaseModel):
    # #430 (D4) — reject a wrong-envelope heartbeat loudly instead of
    # validating into an all-default body (ops_ack=[] → ACK loop runs 0× →
    # 200 → agent clears its ACK buffer). The model is a strict superset of
    # what the DNS agent sends (the slot/deployment fields below are still
    # accepted from pre-Wave-C1 agents), so forbid is backward-compatible.
    model_config = ConfigDict(extra="forbid")

    # Bounded to the column (String(64)); the heartbeat is the OTHER route
    # the same value arrives by, and leaving it unbounded here would let
    # an over-length version in through the side door that register now
    # rejects at the field.
    agent_version: str | None = Field(default=None, max_length=64)
    # #638 — running DNS daemon version, e.g. "5.0.5" / "9.20.26". MUST be
    # declared here: this model is extra="forbid", so an undeclared field would
    # 422 every heartbeat from a current agent.
    daemon_version: str | None = None
    daemon: dict[str, Any] = {}
    # #882 — the agent's last config-apply verdict:
    # ``{status, etag, failed_etag, phase, error}``. Kept as a loose dict
    # rather than a strict model because a pre-#882 agent sends ``{}`` and
    # a NEWER agent may send fields this control plane predates — both must
    # keep heartbeating. ``apply_reported_status`` validates what it reads.
    config: dict[str, Any] = {}
    # #1077 — the agent's durable push spool (``SpoolManager.status()``):
    # bytes / entries queued, oldest entry, cumulative trim counters and a
    # per-stream breakdown. Loose dict at the edge for the same reason as
    # ``config``; ``apply_reported_spool`` validates it against
    # ``SpoolStatus`` and ignores (with a log line) a malformed report rather
    # than 422-ing the heartbeat. Absent (None) on a pre-#1077 agent, which
    # leaves the stored value untouched.
    spool: dict[str, Any] | None = None
    # Bound the ACK list so a malformed/hostile heartbeat can't pin memory.
    ops_ack: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    failed_ops_count: int = 0
    disk_free_bytes: int | None = None
    # #430 (D6) — deprecated: serial convergence is reported via the
    # dedicated /zone-state endpoint. The current agent no longer sends this;
    # retained (default {}) so pre-#430 agents still validate under forbid.
    zone_serials: dict[str, int] = {}
    # Phase 8f-2 — agent reports its slot state + deployment environment.
    # All optional so older agents that haven't been upgraded keep
    # heartbeating without a 422. Server-side fills the matching
    # ``dns_server`` columns when present.
    deployment_kind: str | None = None
    installed_appliance_version: str | None = None
    current_slot: str | None = None
    durable_default: str | None = None
    is_trial_boot: bool | None = None
    last_upgrade_state: str | None = None
    last_upgrade_state_at: datetime | None = None


class AgentHeartbeatResponseV2(BaseModel):
    server_id: str
    status: str
    acknowledged_at: datetime
    rotated_token: str | None = None
    rotated_expires_at: datetime | None = None


# ── Auth dependencies ──────────────────────────────────────────────────────────


def _require_bootstrap_key(
    x_dns_agent_key: str | None = Header(default=None, alias="X-DNS-Agent-Key")
) -> str:
    expected = os.environ.get("DNS_AGENT_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DNS_AGENT_KEY is not configured on the control plane",
        )
    # Compare BYTES: hmac.compare_digest raises TypeError on a str with
    # non-ASCII characters, so any client that sent one (fuzz: '\x80')
    # got a 500 out of the auth gate instead of the 401 a wrong key is.
    if not x_dns_agent_key or not hmac.compare_digest(
        x_dns_agent_key.encode("utf-8", "surrogateescape"),
        expected.encode("utf-8", "surrogateescape"),
    ):
        raise HTTPException(status_code=401, detail="Invalid bootstrap key")
    return x_dns_agent_key


async def _auth_agent(
    db: DB,
    authorization: str | None = Header(default=None),
) -> tuple[DNSServer, dict[str, Any]]:
    """Verify the Bearer agent_token, return (server, jwt_payload)."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        payload = verify_agent_token(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
    server_id = payload.get("sub")
    if not server_id:
        raise HTTPException(status_code=401, detail="Token missing subject")
    server = await db.get(DNSServer, uuid.UUID(server_id))
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    # Defence-in-depth: verify hash match if we have one stored
    if server.agent_jwt_hash and server.agent_jwt_hash != hash_token(token):
        # Token rotated out — reject stale one
        raise HTTPException(status_code=401, detail="Stale token")
    return server, payload


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post("/register", response_model=AgentRegisterResponseV2)
async def agent_register(
    body: AgentRegisterRequestV2,
    db: DB,
    _psk: str = Depends(_require_bootstrap_key),
) -> AgentRegisterResponseV2:
    """Bootstrap registration: PSK-authenticated; returns a per-server JWT."""
    # #1068 — see the matching guard in dhcp/agents.py. Registration is
    # the one agent call that creates a server row, so without this an
    # agent re-registers moments after the operator empties DNS and
    # disables the module, stranding a live server behind a 404 surface.
    # 403, never 404: a 404 is the signal that makes an agent throw its
    # JWT away and re-bootstrap, which would loop forever here.
    if not await is_module_enabled(db, "core.dns"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "The DNS subsystem is disabled on this control plane, so new "
                "agents cannot register. Enable it under Settings → Features."
            ),
        )
    # Resolve or create group
    if body.group_name:
        res = await db.execute(select(DNSServerGroup).where(DNSServerGroup.name == body.group_name))
        group = res.scalar_one_or_none()
        if group is None:
            group = DNSServerGroup(
                name=body.group_name, description="Auto-created by agent registration"
            )
            db.add(group)
            await db.flush()
    else:
        res = await db.execute(select(DNSServerGroup).order_by(DNSServerGroup.created_at).limit(1))
        group = res.scalar_one_or_none()
        if group is None:
            group = DNSServerGroup(name="default", description="Auto-created by agent registration")
            db.add(group)
            await db.flush()

    # Find by agent_id first (stable across restarts) then by hostname
    server: DNSServer | None = None
    if body.agent_id:
        try:
            aid = uuid.UUID(body.agent_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"Invalid agent_id: {e}") from e
        res = await db.execute(select(DNSServer).where(DNSServer.agent_id == aid))
        server = res.scalar_one_or_none()

    if server is None:
        res = await db.execute(
            select(DNSServer).where(DNSServer.group_id == group.id, DNSServer.name == body.hostname)
        )
        server = res.scalar_one_or_none()

    # Auto-generate group TSIG key on first registration if not set.
    # Used by the agent's RFC 2136 dynamic update path over loopback.
    # Shared with the #934 group-move path, which has the same need for a
    # group the operator created in the UI and no agent has registered into.
    ensure_group_tsig_key(group)

    # First server in the group is auto-elected primary so DDNS ops have
    # somewhere to land. Operator can flip later via API.
    primary_res = await db.execute(
        select(DNSServer)
        .where(DNSServer.group_id == group.id, DNSServer.is_primary.is_(True))
        .limit(1)
    )
    has_primary = primary_res.scalar_one_or_none() is not None

    # ``DNS_REQUIRE_AGENT_APPROVAL`` (env / settings) gates whether
    # fingerprint changes lock the agent out pending operator approval.
    # Default: false — wiping an agent's persistent volume + redeploying
    # against the same PSK should "just work" because the agent is
    # already authenticated by the bootstrap key. Operators running
    # high-trust environments flip this to true, which engages the
    # anti-hijack behaviour: any fingerprint mismatch on re-registration
    # forces a manual approval step before the agent can pull config.
    require_approval = os.environ.get("DNS_REQUIRE_AGENT_APPROVAL", "false").lower() == "true"

    pending_approval = False
    if server is None:
        agent_id = uuid.UUID(body.agent_id) if body.agent_id else uuid.uuid4()
        server = DNSServer(
            group_id=group.id,
            name=body.hostname,
            driver=body.driver,
            host=body.hostname,
            port=53,
            roles=body.roles,
            status="active",
            agent_id=agent_id,
            agent_fingerprint=body.fingerprint,
            pending_approval=require_approval,
            is_primary=not has_primary,
            notes=f"agent v{body.version}" if body.version else "auto-registered",
        )
        pending_approval = require_approval
        db.add(server)
        await db.flush()
    else:
        # Anti-hijack: fingerprint change → force approval IFF the
        # operator has opted into the approval gate. Otherwise the
        # agent's PSK authentication is enough — a wiped agent
        # volume legitimately produces a new fingerprint and we
        # don't want to lock the operator out of their own install.
        if (
            require_approval
            and server.agent_fingerprint
            and server.agent_fingerprint != body.fingerprint
        ):
            server.pending_approval = True
            pending_approval = True
            logger.warning("dns_agent_fingerprint_mismatch", server_id=str(server.id))
        server.agent_fingerprint = body.fingerprint
        server.driver = body.driver
        server.roles = body.roles
        server.status = "active"
        if server.agent_id is None:
            server.agent_id = uuid.UUID(body.agent_id) if body.agent_id else uuid.uuid4()

    # Mint token
    token, exp = mint_agent_token(
        server_id=str(server.id),
        agent_id=str(server.agent_id),
        fingerprint=body.fingerprint,
    )
    server.agent_jwt_hash = hash_token(token)
    server.last_seen_at = datetime.now(UTC)

    db.add(
        AuditLog(
            user_display_name="system:dns-agent",
            auth_source="system",
            action="dns.agent.register",
            resource_type="dns_server",
            resource_id=str(server.id),
            resource_display=body.hostname,
            new_value={
                "driver": body.driver,
                "version": body.version,
                "roles": body.roles,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(server)

    logger.info(
        "dns_agent_registered",
        server_id=str(server.id),
        hostname=body.hostname,
        driver=body.driver,
        pending_approval=pending_approval,
    )

    return AgentRegisterResponseV2(
        server_id=str(server.id),
        agent_id=str(server.agent_id),
        agent_token=token,
        token_expires_at=exp,
        config_etag=server.last_config_etag,
        pending_approval=pending_approval,
    )


_BODY_CHUNK = 64 * 1024


def _bundle_prefix(etag: str, ops: list[dict[str, Any]], remaining: int) -> bytes:
    """The per-poll head of the response: ``etag`` and the ops page, in the
    #958 wire shape. This ``json.dumps`` of at most ``dns_agent_ops_batch``
    small dicts is the only serialisation left on the request loop."""
    return (
        b'{"etag":'
        + json.dumps(etag).encode("utf-8")
        + b',"pending_record_ops":'
        + encode_body(ops)
        + b',"pending_ops_remaining":'
        + str(int(remaining)).encode("ascii")
        + b","
    )


def _iter_bundle_bytes(prefix: bytes, body_gz: bytes) -> Iterator[bytes]:
    """Stream ``prefix`` + the stored body minus its opening brace.

    The stored body is a JSON object, so dropping its first byte and
    concatenating yields one object with the per-poll keys first. A sync
    iterator: Starlette runs it in its threadpool, so gunzipping a 26 MB
    body never blocks the event loop and never exists whole in memory.
    """
    yield prefix
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    opened = False
    for offset in range(0, len(body_gz), _BODY_CHUNK):
        out = inflater.decompress(body_gz[offset : offset + _BODY_CHUNK])
        if not opened and out:
            out = out[1:]
            opened = True
        if out:
            yield out
    tail = inflater.flush()
    if not opened and tail:
        tail = tail[1:]
    if tail:
        yield tail


def _bundle_response(
    bundle: DNSAgentBundle, body_gz: bytes, ops: list[dict[str, Any]], remaining: int
) -> StreamingResponse:
    return StreamingResponse(
        _iter_bundle_bytes(_bundle_prefix(bundle.etag, ops, remaining), body_gz),
        media_type="application/json",
        headers={"ETag": format_etag(bundle.etag)},
    )


class _InlineRenderFailed(Exception):
    """The api's inline attempt raised; the poll falls back to the worker."""


async def _render_inline(db: AsyncSession, server: DNSServer) -> DNSAgentBundle | None:
    """Migration-release fallback: build in the request as before, store it.

    Once per (server, version) — the store is idempotent on the watermark
    and a concurrent render (another replica, or the worker) simply wins;
    then this poll serves the row that won.

    A render that raises here is the api's opportunistic attempt, not the
    control plane's verdict on the server's bundle, and is NOT recorded on
    the server row. At a million records the records query outlives the
    api's 30 s ``command_timeout`` on every attempt: recorded, each one
    stamped ``bundle_render_status = failed`` (firing
    ``agent_bundle_render_failed`` while the worker was rendering fine) and
    kept the render-missing sweep backing off the server for its 5-minute
    failed window, re-stamped by every poll — so a lost or crashed worker
    render of that server was never retried. The failure is logged and
    counted instead, and the caller holds the poll on the worker's render.
    """
    server_id = server.id  # a rollback expires the instance
    try:
        outcome = await render_and_store(db, server, rendered_by=RENDERED_BY_API)
    except Exception as exc:
        await db.rollback()
        AGENT_BUNDLE_INLINE_FAILURES.labels(family="dns").inc()
        logger.warning(
            "dns_agent_bundle_inline_render_failed",
            server_id=str(server_id),
            error=f"{type(exc).__name__}: {exc}",
        )
        raise _InlineRenderFailed from exc
    # Commit now: the stored row serves every other poller of this server.
    await db.commit()
    if outcome.bundle is not None:
        AGENT_BUNDLE_INLINE_RENDERS.labels(family="dns").inc()
        return outcome.bundle
    await db.refresh(server)
    return await bundle_store.newest(db, server)


# A bundle read by a poll can be pruned before its body is loaded when two
# newer renders store in between (``bundle_store.load_body``). The poll then
# serves the newest; this bounds how often one poll re-reads before it falls
# back to waiting for the next wake.
_PRUNED_RETRIES = 3

_INLINE_LOCK_PREFIX = "spatium:bundle:inline:"
_INLINE_BACKOFF_PREFIX = "spatium:bundle:inline-backoff:"
# Longer than any inline attempt: the records query alone is capped by the
# api's 30 s command_timeout, the serialisation and store follow it.
_INLINE_LOCK_SECONDS = 180
_RELEASE_IF_OWNER = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


def _inline_eligible(server: DNSServer) -> bool:
    """Whether the api may build this server's bundle itself, now.

    A server that has never had a bundle: yes. Nothing is being raced, and
    it is the case the fallback exists for (the upgrade from a release
    before stored bundles brings every server in with none, and its worker
    may still be that release). A server whose bundle is stale: only once
    it has waited longer than the bound for the worker. The worker renders
    every marked bundle within seconds and every render that lands restarts
    ``bundle_dirty_at``, so while it keeps up no bundle waits past the bound
    and the api builds nothing, however many changes a storm commits
    (without the bound a 250k-record seed had the api build the growing
    bundle 48 times, up to 480k records and 16 s each, beside the worker).
    A bundle that is stale only because an older renderer revision
    rendered it waits for the sweep.
    """
    if server.bundle_watermark is None:
        return True
    if server.bundle_dirty_at is None:
        return False
    waited = (datetime.now(UTC) - server.bundle_dirty_at).total_seconds()
    return waited >= settings.dns_agent_bundle_inline_fallback_after_seconds


async def _bounded_inline(db: AsyncSession, server: DNSServer) -> DNSAgentBundle | None:
    """The inline fallback, bounded: eligible servers only, one attempt per
    server at a time across replicas, none during a failed attempt's backoff.

    Returns the bundle it rendered (or the row a concurrent render won with),
    or ``None`` when it did not try. Raises ``_InlineRenderFailed`` when the
    attempt failed, after starting the backoff. Redis is advisory: without it
    the attempt is made unbounded, as the fallback always did.
    """
    if not _inline_eligible(server):
        return None
    sid = str(server.id)
    lock_key = _INLINE_LOCK_PREFIX + sid
    backoff_key = _INLINE_BACKOFF_PREFIX + sid
    token = uuid.uuid4().hex
    # Any: the redis stubs type eval() as ``Awaitable[str] | str``.
    client: Any = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=2.0)
        if await client.exists(backoff_key) or not await client.set(
            lock_key, token, nx=True, ex=_INLINE_LOCK_SECONDS
        ):
            await client.aclose()
            return None
    except Exception as exc:  # noqa: BLE001 — advisory: render unbounded
        logger.warning("dns_agent_bundle_inline_lock_unavailable", error=str(exc))
        client = None
    try:
        return await _render_inline(db, server)
    except _InlineRenderFailed:
        if client is not None:
            try:
                await client.set(
                    backoff_key,
                    "1",
                    ex=max(1, int(settings.dns_agent_bundle_inline_fallback_backoff_seconds)),
                )
            except Exception:  # noqa: BLE001
                pass
        raise
    finally:
        if client is not None:
            try:
                await client.eval(_RELEASE_IF_OWNER, 1, lock_key, token)
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass


@router.get("/config")
async def agent_config_longpoll(
    db: DB,
    response: Response,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> Any:
    """Long-poll for config changes.

    Returns 304 if the server's current bundle matches If-None-Match.
    Otherwise holds the connection up to LONGPOLL_TIMEOUT_SECONDS waiting for
    any change, then returns the current bundle with a new ETag.

    #1111 — the bundle is no longer assembled here. It is rendered once per
    (server, watermark) by the worker (``app.tasks.agent_bundles``) and
    stored in ``dns_agent_bundle``; this handler reads one small row per
    wake, compares ``If-None-Match`` with the stored ETag, splices the
    per-server ops page in front of the stored bytes and streams them. No
    assembly and no 26 MB string on the request loop whatever the group's
    record count, and one build per change instead of one per agent per
    change (it used to be one per agent per wake, and one per PAGE while
    ops were pending).

    The agents' contract is unchanged: weak ETag / 304 / the body shape /
    the "200 while ops are pending" fast path / ``structural_etag`` / the
    #882 quarantine. One deliberate difference: the ETag is the stored
    body's and no longer folds the ops page in, so a page does not rotate
    it — the fast path answers 200 with the same ETag and the next page,
    and the poll after the last ack answers 304 instead of re-sending the
    whole body. The agent never short-circuits on an unchanged ETag (it
    saves, compares ``structural_etag``, drains the ops), so nothing on its
    side changes.

    The ops page is gated to what the stored bundle's snapshot covers: an
    op whose transaction had not committed when its render read rides with
    the next render, whose dirty mark its own commit made. Every body an
    agent holds is therefore a superset of every op it has applied — the
    invariant the inline build had by construction, and what keeps a later
    structural re-render (or a restart replaying the cached bundle) from
    dropping a record the agent already applied incrementally.

    The newest bundle this release stored is served even when changes have
    been committed since it was rendered (``bundle_store.newest``). Under a
    write storm marks arrive faster than renders finish, so no render is
    current until the writes stop; serving only a current one held every
    agent on its last config for the whole storm. Now each render the
    worker lands reaches the agents, at most one render behind; that is
    safe because of the gate above. A bundle that is not current also has
    its render enqueued (the worker coalesces duplicates), and the poll
    holds on the wake the worker publishes when one lands. With nothing
    stored for this release the poll holds, 304 at the deadline.

    While ``settings.dns_agent_bundle_inline_fallback`` is on (the
    migration release, whose worker may still be one release behind), the
    api renders inline, exactly the old build, but only where the worker
    has not (``_inline_eligible``): a bundle stale for longer than
    ``dns_agent_bundle_inline_fallback_after_seconds``, or a server that
    has never had one. One attempt per server at a time, none during a
    failed attempt's backoff, and a failed attempt leaves the poll on the
    worker's renders like the fallback being off.
    """
    server, _payload = auth
    if server.pending_approval:
        response.headers["X-Spatium-Pending-Approval"] = "1"
        return {"pending_approval": True, "etag": None}

    deadline = asyncio.get_running_loop().time() + LONGPOLL_TIMEOUT_SECONDS
    enqueued = False
    inline_tried = False
    pruned_retries = 0
    # #358 — subscribe to this agent's wake channels BEFORE the first read so
    # a change (or a render) that commits + publishes during this request
    # can't land in the gap. A wake collapses the re-poll latency; with
    # Redis down the subscription degrades to the old poll interval.
    async with wake_subscription(dns_wake_channels(server)) as wake:
        while True:
            # The server row carries the dirty sequence and the watermark of
            # the newest stored bundle; refresh it so a change committed on
            # any replica, or the worker's store, is seen here
            # (expire_on_commit=False, no in-loop commit).
            await db.refresh(server)
            # The newest bundle this release stored, current or not: under a
            # write storm no render is current until the writes stop, and
            # each one that lands is served as it lands (docstring).
            bundle = await bundle_store.newest(db, server)
            if not bundle_store.is_current(server):
                if settings.dns_agent_bundle_inline_fallback and not inline_tried:
                    try:
                        rendered = await _bounded_inline(db, server)
                        inline_tried = rendered is not None
                        if rendered is not None:
                            bundle = rendered
                    except _InlineRenderFailed:
                        # Once per poll: the worker's renders serve it instead.
                        inline_tried = True
                        await db.refresh(server)
                        bundle = await bundle_store.newest(db, server)
                if not enqueued and not bundle_store.is_current(server):
                    await enqueue_renders([server.id])
                    enqueued = True
            if bundle is not None:
                ops: list[dict[str, Any]] = []
                remaining_ops = 0
                if bundle.ships_ops:
                    ops, remaining_ops = await page_pending_ops(
                        db,
                        server,
                        up_to=bundle.snapshot_at,
                        visible_xacts=bundle.visible_xacts,
                    )
                # Early return if there are pending ops (fast-path per §3)
                if not etag_matches(if_none_match, bundle.etag) or ops:
                    # The body before the commit, and never assumed: the
                    # worker keeps dns_agent_bundle_keep_versions rows per
                    # server, and under a write storm (the api's loop
                    # saturated, this request waiting between statements)
                    # two newer renders can store and prune this bundle
                    # after it was read. The row being gone means a newer
                    # render exists: undo this page's in_flight marks (it
                    # was never shipped) and serve the newest instead of
                    # answering 500.
                    body_gz = await bundle_store.load_body(db, bundle)
                    if body_gz is not None:
                        server.last_config_etag = bundle.etag
                        await db.commit()
                        AGENT_BUNDLE_SERVED.labels(family="dns", outcome="full").inc()
                        return _bundle_response(bundle, body_gz, ops, remaining_ops)
                    await db.rollback()
                    bundle = None  # expired by the rollback; never read again
                    # Re-read and re-page from scratch: the page is gated to
                    # the bundle it ships with, never reused. Bounded; past
                    # the bound the poll waits for the next wake as usual.
                    pruned_retries += 1
                    if (
                        pruned_retries <= _PRUNED_RETRIES
                        and deadline - asyncio.get_running_loop().time() > 0
                    ):
                        continue
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                headers = {"ETag": format_etag(bundle.etag)} if bundle is not None else {}
                AGENT_BUNDLE_SERVED.labels(family="dns", outcome="not_modified").inc()
                return Response(status_code=304, headers=headers)
            await wake.wait(min(WAKE_TICK_SECONDS, remaining))


@router.post("/heartbeat", response_model=AgentHeartbeatResponseV2)
async def agent_heartbeat(
    request: Request,
    body: AgentHeartbeatRequest,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> AgentHeartbeatResponseV2:
    """Heartbeat: updates last_seen_at, processes op ACKs, rotates token if near expiry."""
    server, payload = auth
    now = datetime.now(UTC)
    server.last_seen_at = now
    server.last_health_check_at = now
    server.status = "active"
    # Capture the source IP so the operator can identify which host
    # this agent is running on — the operator-set ``host`` column is
    # just a label that may not match the real machine in NAT /
    # distributed deployments.
    if request.client is not None:
        server.last_seen_ip = request.client.host

    # #638 — only overwrite when the agent actually reported a version. A probe
    # that failed answers None, and clobbering a known-good value with NULL
    # would make the PowerDNS LMDB preflight fall back to "unknown" for no
    # reason.
    if body.daemon_version:
        server.daemon_version = body.daemon_version

    # Phase 8f-2 — persist whatever slot state the agent reported. Only
    # overwrite when the agent actually sent a value (older agents
    # leave these as None, in which case we leave the DB columns
    # untouched rather than nulling out previously-known state).
    if body.deployment_kind is not None:
        server.deployment_kind = body.deployment_kind
    if body.installed_appliance_version is not None:
        server.installed_appliance_version = body.installed_appliance_version
    if body.current_slot is not None:
        server.current_slot = body.current_slot
    if body.durable_default is not None:
        server.durable_default = body.durable_default
    if body.is_trial_boot is not None:
        server.is_trial_boot = body.is_trial_boot
    if body.last_upgrade_state is not None:
        server.last_upgrade_state = body.last_upgrade_state
    if body.last_upgrade_state_at is not None:
        server.last_upgrade_state_at = body.last_upgrade_state_at

    # Phase 8f-7 — auto-clear the operator-intent stamp once the agent
    # confirms it landed. The Fleet view's "pending" indicator drops
    # to None as soon as installed_appliance_version matches the
    # desired one + the slot upgrade reported done. Cancellation flow
    # (operator cleared desired_ manually before the agent picked it
    # up) is handled by the Fleet endpoint's clear handler — that
    # already nulls both fields directly.
    if (
        server.desired_appliance_version is not None
        and server.installed_appliance_version
        and server.installed_appliance_version == server.desired_appliance_version
        and (server.last_upgrade_state in ("done", None))
    ):
        server.desired_appliance_version = None
        server.desired_slot_image_url = None

    # Phase 8f-8 — clear reboot_requested once the agent reconnects
    # after the reboot landed. We don't have a discrete "I rebooted"
    # signal from the agent, but: agents heartbeat every ~30 s, the
    # host reboot takes ~30-60 s, so any heartbeat that arrives more
    # than 15 s after the request was stamped AND finds the request
    # still set is post-reboot by construction (a pre-reboot agent
    # wouldn't be heartbeating — the container's down). 15 s is a
    # safety margin to avoid races where the heartbeat arrives mid-
    # ConfigBundle-pickup but the box hasn't actually rebooted yet.
    if server.reboot_requested and server.reboot_requested_at is not None:
        elapsed = (datetime.now(UTC) - server.reboot_requested_at).total_seconds()
        if elapsed > 15:
            server.reboot_requested = False
            server.reboot_requested_at = None

    # #882 — the config-apply verdict. ``body.config`` has been declared on
    # this model since it was written and read by nothing; a server could be
    # reachable, healthy and serving a config the operator never approved.
    apply_reported_status(server, body.config, agent_kind="dns", server_id=str(server.id))
    # #1077 — spool state. Only written when the heartbeat carries it.
    apply_reported_spool(server, body.spool, agent_kind="dns", server_id=str(server.id))
    # #1067 — the daemon state. ``body.daemon`` has been declared on this model
    # since it was written and read by nothing: an agent whose ``named`` never
    # started (no bundle yet — #1061 says ``degraded`` on every heartbeat) was
    # indistinguishable from a healthy one.
    apply_reported_daemon_state(server, body.daemon, agent_kind="dns", server_id=str(server.id))

    # Process op ACKs
    for ack in body.ops_ack:
        op_id = ack.get("op_id")
        result = ack.get("result", "error")
        message = ack.get("message")
        if op_id:
            await ack_op(db, op_id, result, message)

    rotated_token = None
    rotated_exp = None
    if needs_rotation(payload):
        rotated_token, rotated_exp = mint_agent_token(
            server_id=str(server.id),
            agent_id=str(server.agent_id),
            fingerprint=server.agent_fingerprint or "",
        )
        server.agent_jwt_hash = hash_token(rotated_token)

    await db.commit()
    return AgentHeartbeatResponseV2(
        server_id=str(server.id),
        status=server.status,
        acknowledged_at=now,
        rotated_token=rotated_token,
        rotated_expires_at=rotated_exp,
    )


@router.get("/record-ops")
async def agent_record_ops(
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Return the queue of pending record ops targeting this server.

    Agents typically pick ops up from the long-poll bundle, but this endpoint
    lets an agent drain ops out-of-band (e.g. after a restart).
    """
    server, _ = auth
    res = await db.execute(
        select(DNSRecordOp)
        .where(DNSRecordOp.server_id == server.id, DNSRecordOp.state == "pending")
        .order_by(DNSRecordOp.created_at)
    )
    ops = res.scalars().all()
    return {
        "server_id": str(server.id),
        "ops": [
            {
                "op_id": str(o.id),
                "zone_name": o.zone_name,
                "op": o.op,
                "record": o.record,
                "target_serial": o.target_serial,
            }
            for o in ops
        ],
    }


@router.post("/ops/{op_id}/ack")
async def agent_ops_ack(
    op_id: uuid.UUID,
    body: dict[str, Any],
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, str]:
    """Out-of-band op acknowledgment (also piggybacked on heartbeat)."""
    server, _ = auth
    op = await db.get(DNSRecordOp, op_id)
    if op is None or op.server_id != server.id:
        raise HTTPException(status_code=404, detail="Op not found")
    await ack_op(db, str(op_id), body.get("result", "error"), body.get("message"))
    await db.commit()
    return {"status": "ok"}


class ZoneStateEntry(BaseModel):
    zone_name: str
    serial: int


class ZoneStateReport(BaseModel):
    zones: list[ZoneStateEntry]


@router.post("/zone-state")
async def agent_zone_state(
    body: ZoneStateReport,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, int]:
    """Agents POST the serial they just rendered, per zone.

    Called after a successful ``apply_config`` pass — the serial
    reported here is the "ground truth" of what this particular
    server is serving, as distinct from ``DNSZone.last_serial`` which is
    the latest value the control plane *pushed*. Used for per-server
    drift detection on the zone detail page + (future) a
    ``zone_serial_drift`` alert-rule type.

    Upsert by ``(server_id, zone_id)`` — no history, one row per
    pair. Unknown zone names are silently skipped (zone deleted from
    control plane but agent still serves it; the next config bundle
    will drop it).
    """
    server, _ = auth
    now = datetime.now(UTC)
    updated = 0

    # Index known zones by name for one DB round-trip on the lookup.
    names = [e.zone_name.rstrip(".") for e in body.zones]
    if not names:
        return {"updated": 0}
    res = await db.execute(select(DNSZone).where(DNSZone.name.in_(names)))
    zones_by_name: dict[str, DNSZone] = {}
    for z in res.scalars().all():
        zones_by_name[z.name.rstrip(".")] = z

    for entry in body.zones:
        key = entry.zone_name.rstrip(".")
        zone = zones_by_name.get(key)
        if zone is None:
            continue

        # Upsert: look up existing row, update or insert.
        existing_res = await db.execute(
            select(DNSServerZoneState).where(
                DNSServerZoneState.server_id == server.id,
                DNSServerZoneState.zone_id == zone.id,
            )
        )
        row = existing_res.scalar_one_or_none()
        if row is None:
            row = DNSServerZoneState(
                server_id=server.id,
                zone_id=zone.id,
                current_serial=entry.serial,
                reported_at=now,
            )
            db.add(row)
        else:
            row.current_serial = entry.serial
            row.reported_at = now
        updated += 1

    await db.commit()
    return {"updated": updated}


class DNSKeyReport(BaseModel):
    """One DNSSEC key's public state (issue #49 — BIND9 ``rndc dnssec
    -status``). No private material; BIND owns + rotates the keys."""

    key_tag: int
    key_type: str = "zsk"  # ksk | zsk | csk
    algorithm: int = 0
    state: str = "unknown"
    ds_records: list[str] = []
    timing: dict[str, Any] = {}


class DNSSECStateReport(BaseModel):
    """One zone's DNSSEC state, posted by the agent after signing.

    ``ds_records`` is the zone-level DS rrset the operator copies into the
    parent registrar verbatim (empty = unsigned). ``keys`` is the optional
    per-key breakdown BIND9 agents report from ``rndc dnssec -status``
    (issue #49); PowerDNS agents omit it.
    """

    zone_name: str
    ds_records: list[str]
    keys: list[DNSKeyReport] = []


class DNSSECStateBatch(BaseModel):
    zones: list[DNSSECStateReport]


class IngestedRecord(BaseModel):
    """One record the agent read back off a live dynamic zone (issue #641)."""

    name: str  # relative label, "@" = apex
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


class IngestedRecordsReport(BaseModel):
    """The *complete* current external record set for one dynamic zone.

    The agent sends everything it found on-wire that isn't in the shipped
    bundle; the control plane reconciles its ``ddns_external`` mirror rows
    to match (add new, drop vanished), skipping anything a managed record
    or the daemon owns. See ``app.services.dns.ingest``.
    """

    zone_name: str
    records: list[IngestedRecord] = []


@router.post("/ingested-records")
async def agent_ingested_records(
    body: IngestedRecordsReport,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest externally-injected DDNS records back into the control plane.

    Alt.1 of issue #641's drift solution: records a third-party writer
    (AD DC, DHCP server) injected over RFC 2136 live only in the daemon
    journal; the agent AXFRs them and posts them here so they become
    UI/IPAM-visible + survive a full re-render. Gated on the zone actually
    having ``dynamic_update_enabled`` (defense-in-depth against a
    misbehaving agent) and scoped to the posting server's group.
    """
    from app.services.dns.ingest import (  # noqa: PLC0415
        IncomingRecord,
        reconcile_external_records,
        to_summary,
    )

    server, _ = auth
    zone_name = body.zone_name.rstrip(".")
    # Match either stored form (with/without trailing dot). Under split-horizon
    # the same name can exist once per view, so we can't use
    # ``scalar_one_or_none`` (it raises MultipleResultsFound): prefer the global
    # zone (``view_id IS NULL``) and take the first — loopback AXFR is
    # inherently view-ambiguous, and the global copy is the common case.
    zone = (
        (
            await db.execute(
                select(DNSZone)
                .where(
                    DNSZone.group_id == server.group_id,
                    DNSZone.name.in_([zone_name + ".", zone_name]),
                    DNSZone.deleted_at.is_(None),
                )
                .order_by(DNSZone.view_id.nulls_first())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if zone is None:
        # Zone unknown to the control plane (deleted, or agent serving a
        # stale bundle). Silently accept — the next bundle drops it.
        return {"zone": zone_name, "skipped": "unknown_zone"}
    if not zone.dynamic_update_enabled:
        return {"zone": zone_name, "skipped": "dynamic_update_disabled"}

    incoming = [
        IncomingRecord(
            name=r.name,
            record_type=r.record_type,
            value=r.value,
            ttl=r.ttl,
            priority=r.priority,
            weight=r.weight,
            port=r.port,
        )
        for r in body.records
    ]
    result = await reconcile_external_records(db, zone, incoming)
    await db.commit()
    summary = to_summary(result)
    if summary["added"] or summary["removed"]:
        logger.info(
            "dns_ingested_external_records",
            server_id=str(server.id),
            zone=zone_name,
            **summary,
        )
    return {"zone": zone_name, **summary}


@router.post("/dnssec-state")
async def agent_dnssec_state(
    body: DNSSECStateBatch,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, int]:
    """Agents POST DS-record state per zone after a signing change
    (issue #127, Phase 3c.fe).

    Updates ``DNSZone.dnssec_ds_records`` + ``dnssec_synced_at`` so
    the operator-facing zone-edit page can render the DS rrset
    without round-tripping the agent on every page load.

    Empty ``ds_records`` = the zone was just unsigned; we clear the
    cache so the UI doesn't display stale records the parent zone
    no longer trusts.

    Unknown zone names are silently skipped (deleted between sign
    and report) — same fail-soft semantic as ``/zone-state``.
    """
    _, _ = auth
    now = datetime.now(UTC)
    updated = 0

    if not body.zones:
        return {"updated": 0}

    # DNSZone.name is stored *with* the trailing dot in the DB
    # (per ZoneCreate.ensure_trailing_dot validator). The agent
    # ships fully-qualified names that already carry the dot; we
    # build both forms in the IN-clause so the lookup matches
    # regardless of whether the agent normalised before sending,
    # then key the dict by the canonical (trailing-dot) form.
    name_set: set[str] = set()
    for e in body.zones:
        n = e.zone_name
        name_set.add(n)
        name_set.add(n.rstrip("."))
        if not n.endswith("."):
            name_set.add(n + ".")
    res = await db.execute(select(DNSZone).where(DNSZone.name.in_(name_set)))
    zones_by_name: dict[str, DNSZone] = {z.name.rstrip("."): z for z in res.scalars().all()}

    for entry in body.zones:
        zone = zones_by_name.get(entry.zone_name.rstrip("."))
        if zone is None:
            continue
        zone.dnssec_ds_records = entry.ds_records or None
        zone.dnssec_synced_at = now
        # Per-key state (issue #49) — replace the zone's DNSKey rows wholesale
        # so the table mirrors the agent's latest ``rndc dnssec -status``.
        # ``keys`` PRESENT (even empty) replaces — so an unsign that reports
        # ``keys: []`` clears stale rows. ``keys`` OMITTED (PowerDNS agents)
        # leaves existing rows untouched.
        if "keys" in entry.model_fields_set:
            await db.execute(sa_delete(DNSKey).where(DNSKey.zone_id == zone.id))
            for k in entry.keys:
                db.add(
                    DNSKey(
                        zone_id=zone.id,
                        key_tag=k.key_tag,
                        key_type=k.key_type,
                        algorithm=k.algorithm,
                        state=k.state,
                        ds_records=k.ds_records or None,
                        timing=k.timing or None,
                        reported_at=now,
                    )
                )
        updated += 1

    await db.commit()
    return {"updated": updated}


class DNSMetricReport(BaseModel):
    """One time-bucketed sample of BIND9 query counters.

    Agents report *deltas* (the difference between two consecutive
    polls of the statistics-channels endpoint), already bucketed to
    whatever cadence the agent runs at (default 60 s). That keeps
    counter resets on daemon restart from back-propagating into the
    stored time series — the agent absorbs them.
    """

    bucket_at: datetime
    queries_total: int = 0
    noerror: int = 0
    nxdomain: int = 0
    servfail: int = 0
    recursion: int = 0
    rate_dropped: int = 0
    rate_slipped: int = 0
    batch_id: BatchId = None


class DNSMetricsAck(IngestAck):
    """Response for ``POST /dns/agents/metrics``."""


@router.post("/metrics", response_model=DNSMetricsAck)
async def agent_metrics(
    body: DNSMetricReport,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest one sample row, accumulating into ``(server_id, bucket_at)``.

    A second report for a bucket that already exists is ADDED to it rather
    than replacing it — the same fix #980 made on the DHCP side. These are
    counter deltas over disjoint intervals, and the agent floors
    ``bucket_at`` to the minute while its own interval is 60 s ± 3 s of
    jitter, so roughly one bucket in forty receives two genuinely different
    deltas; the old last-write-wins overwrite silently discarded one of them.

    Accumulating is only safe because a *retried* body is no longer a second
    delta: since #1077 the agent spools a failed POST and replays it with the
    same ``batch_id``, and a replay of a batch already committed is answered
    as a duplicate before anything is added. A body with no ``batch_id`` (an
    agent older than #1077, which never retries a metric POST) accumulates
    unconditionally. Counters that arrive negative (e.g. a buggy agent) are
    clamped to zero so the dashboard can't render impossible dips.
    """
    server, _ = auth
    if not await claim_batch(db, server_id=server.id, batch_id=body.batch_id, stream="dns.metrics"):
        return duplicate_response()
    values = {
        "queries_total": max(0, body.queries_total),
        "noerror": max(0, body.noerror),
        "nxdomain": max(0, body.nxdomain),
        "servfail": max(0, body.servfail),
        "recursion": max(0, body.recursion),
        "rate_dropped": max(0, body.rate_dropped),
        "rate_slipped": max(0, body.rate_slipped),
    }
    existing = await db.get(DNSMetricSample, (server.id, body.bucket_at))
    if existing is None:
        db.add(DNSMetricSample(server_id=server.id, bucket_at=body.bucket_at, **values))
    else:
        for k, v in values.items():
            setattr(existing, k, (getattr(existing, k, 0) or 0) + v)
    await db.commit()
    return {"status": "ok", "duplicate": False}


# ── Query log ingestion ──────────────────────────────────────────────


class QueryLogBatch(BaseModel):
    """Batch of raw BIND9 query log lines pushed by the agent.

    The agent tails the configured query log file (default
    ``/var/log/named/queries.log``), collects up to ~200 lines or 5 s
    worth of activity, and POSTs them here. The control plane parses
    each line into structured fields and inserts.

    Replays are idempotent per batch (#1077): the agent spools a batch the
    control plane did not acknowledge and replays it with the same
    ``batch_id``, and a batch already committed under that id is answered
    as a duplicate without inserting anything. That is the dedupe the
    issue asked for — keyed on the batch rather than on the row's
    ``(ts, client, qname, qtype)``, because a client legitimately repeats
    an identical query inside one second and a row-level key would erase
    real traffic. A body without ``batch_id`` (a pre-#1077 agent) is not
    deduplicated, as before.
    """

    lines: list[str]
    batch_id: BatchId = None


class QueryLogAck(IngestAck):
    """Response for ``POST /dns/agents/query-log-entries``."""

    inserted: int = 0
    rpz_inserted: int = 0
    responses_matched: int = 0
    responses_unmatched: int = 0
    dropped: int = 0
    #: Query lines older than the control plane's own query-log retention
    #: (``prune_logs.DEFAULT_RETENTION_HOURS``) — skipped rather than
    #: inserted into a table the nightly prune would empty straight away.
    expired: int = 0


@router.post("/query-log-entries", response_model=QueryLogAck)
async def agent_query_log_entries(
    body: QueryLogBatch,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest a batch of query-log lines from the agent.

    The ingest is driver-aware: BIND9 lines go through
    ``bind9_parser`` (RFC 5424 + BIND's ``query: ...`` body), and
    PowerDNS lines go through ``pdns_parser`` (``Remote ip:port
    wants 'qname|qtype'`` shape). Both parsers normalise into the
    shared :class:`ParsedQueryLine` dataclass so this endpoint
    stays driver-agnostic past the dispatch.

    Capped at 1000 lines per request to keep individual transactions
    bounded. Anything beyond is dropped with a count returned so the
    agent can log + alert.

    Lines that the parser couldn't pull a ``qname`` out of are
    silently dropped — pdns mixes startup banners + status messages
    into the same stderr stream the agent captures, so non-query
    lines are expected and stored as noise without filling the DB.

    Query lines whose own timestamp is older than the query-log retention
    window are counted as ``expired`` and not inserted (#1077): a replay of
    a long outage's backlog would otherwise write rows the nightly prune
    deletes on its next run. The agent drops by spool age too; this is the
    server-side belt. A line with no parseable timestamp is stamped with
    the arrival time by the parser and is therefore never expired. RPZ
    hits are exempt — they are kept for 30 days, not 24 h.
    """
    from app.services.logs import bind9_parser, pdns_parser  # noqa: PLC0415

    server, _ = auth
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dns.query_log"
    ):
        return duplicate_response(inserted=0)
    if server.driver == "powerdns":
        parse_fn = pdns_parser.parse_query_line
    else:
        # BIND9 (and any future driver until it ships its own parser)
        # stays on the BIND parser. Mismatched-driver lines just won't
        # parse and end up as noise rows the operator can ignore.
        parse_fn = bind9_parser.parse_query_line

    # RPZ hits are per-client domain-lookup history kept for 30 days —
    # longer than the 24 h query log they are carved out of — so they are
    # gated on the SAME default-off module that gates every reader
    # (``require_module`` on the router include, ``module=`` on every MCP
    # tool, the rollup task's own check). That module is default-off on
    # privacy grounds; without this check a default install would silently
    # accumulate data the operator never opted into and cannot view,
    # because the whole /dns-threat prefix 404s while it is disabled.
    #
    # Capability comes from the driver ABC rather than a driver-name
    # string (non-negotiable #10): bind9 advertises ``rpz: True`` and
    # powerdns ``False``, so a future agent-based driver is not silently
    # opted into BIND9 regex matching against its own log format.
    rpz_capable = False
    if await is_module_enabled(db, "security.dns_threat"):
        with contextlib.suppress(Exception):
            rpz_capable = bool(get_dns_driver(server.driver).capabilities().get("rpz"))

    # Response logging (#914) is BIND9-only and opt-in, but the flag that
    # decides it lives on the server group's options rather than here.
    # Keying off the driver's own capability instead of a driver-name
    # string keeps a future agent-based driver from being silently opted
    # into BIND9 line matching (non-negotiable #10); the parser's own
    # ``response:`` reject makes the probe cheap on every other line.
    response_capable = False
    with contextlib.suppress(Exception):
        response_capable = bool(get_dns_driver(server.driver).capabilities().get("response_log"))

    capped = body.lines[:1000]
    dropped = max(0, len(body.lines) - len(capped))
    now = datetime.now(UTC)
    expired_cutoff = now - timedelta(hours=QUERY_LOG_RETENTION_HOURS)
    inserted = 0
    expired = 0
    rpz_inserted = 0
    responses_matched = 0
    # Query rows added in THIS batch, keyed for the response line that
    # follows them microseconds later. named writes the pair together, so
    # the overwhelming majority of responses are matched here without
    # touching the database at all.
    pending: dict[tuple[str | None, int | None, str | None, str | None], DNSQueryLogEntry] = {}
    # Responses whose question landed in an EARLIER batch — only possible
    # when the 1000-line cap or the shipper's own batch boundary fell
    # between the two lines. Resolved against the DB after the loop.
    deferred: list[bind9_parser.ParsedResponseLine] = []
    for raw in capped:
        # RPZ policy hits (issue #699) ride the same channel as queries —
        # named logs them under its own ``rpz`` category, which the
        # BIND9 template points at ``queries_channel`` so no second
        # shipper is needed. They are tried FIRST because they do not
        # contain the ``: query: `` separator the query parser splits
        # on, so they would otherwise be dropped by the ``qname is
        # None`` guard below and the hit lost.
        #
        # PowerDNS has no equivalent category, so this is BIND9-only;
        # the parser returns None for every non-RPZ line, which makes
        # running it against pdns output harmless rather than
        # conditional.
        if rpz_capable:
            rpz = bind9_parser.parse_rpz_line(raw, fallback_ts=now)
            if rpz is not None:
                db.add(
                    DNSRPZHit(
                        server_id=server.id,
                        ts=rpz.ts,
                        client_ip=rpz.client_ip,
                        qname=rpz.qname,
                        trigger=rpz.trigger,
                        policy=rpz.policy,
                        rpz_zone=rpz.rpz_zone,
                        raw=rpz.raw,
                    )
                )
                rpz_inserted += 1
                continue
        # Response lines (issue #914) ride the same channel as queries when
        # the operator enabled ``response_log_enabled``. They are tried
        # before the query parser because a response line carries no
        # ``: query: `` separator and would otherwise be dropped by the
        # ``qname is None`` guard below — losing the only record of what
        # the client was actually told. BIND9-only; the parser returns
        # None for every other shape, which makes running it against
        # pdns output harmless rather than conditional.
        if response_capable:
            resp = bind9_parser.parse_response_line(raw, fallback_ts=now)
            if resp is not None:
                row = pending.get(_correlation_key(resp))
                if row is not None:
                    row.rcode = resp.rcode
                    row.answer_count = resp.answer_count
                    responses_matched += 1
                else:
                    deferred.append(resp)
                continue
        parsed = parse_fn(raw, fallback_ts=now)
        if parsed is None or parsed.qname is None:
            continue
        if parsed.ts < expired_cutoff:
            expired += 1
            continue
        entry = DNSQueryLogEntry(
            server_id=server.id,
            ts=parsed.ts,
            client_ip=parsed.client_ip,
            client_port=parsed.client_port,
            qname=parsed.qname,
            qclass=parsed.qclass,
            qtype=parsed.qtype,
            flags=parsed.flags,
            view=parsed.view,
            raw=parsed.raw,
        )
        db.add(entry)
        if response_capable:
            # Last writer wins: an ephemeral source port is effectively
            # unique per query, but a client that retries the identical
            # question from the same port would otherwise have its second
            # answer stamped onto its first row.
            pending[_correlation_key(parsed)] = entry
        inserted += 1

    deferred_matched = await _stamp_deferred_responses(db, server.id, deferred)
    await db.commit()
    return {
        "status": "ok",
        "inserted": inserted,
        "rpz_inserted": rpz_inserted,
        "responses_matched": responses_matched + deferred_matched,
        # Reported rather than swallowed: a persistently non-zero count
        # means the correlation is failing, and the operator-visible
        # symptom of that is an rcode column that is quietly blank.
        "responses_unmatched": len(deferred) - deferred_matched,
        "dropped": dropped,
        "expired": expired,
    }


# ── Response-line correlation (issue #914) ───────────────────────────

#: Response lines whose question was not in the same batch are resolved
#: with one small query each. The split can only happen at a batch
#: boundary, so the realistic count is 0 or 1; the cap is a backstop
#: against a malformed or replayed batch turning one POST into a
#: thousand round trips.
_MAX_DEFERRED_RESPONSES = 50

#: How far back to look for the question a late response answers. named
#: writes the two lines microseconds apart, so this only has to cover the
#: shipper's own batching interval; anything older is a different query
#: that happens to share the ephemeral port.
_RESPONSE_MATCH_WINDOW = timedelta(seconds=60)


def _correlation_key(
    parsed: Any,
) -> tuple[str | None, int | None, str | None, str | None]:
    """The tuple that ties a response line back to its question.

    The ephemeral source port does nearly all the work — it is unique per
    outstanding query from a given client — with qname and qtype as
    corroboration so a port reused inside the batch cannot cross-stamp.
    """
    return (parsed.client_ip, parsed.client_port, parsed.qname, parsed.qtype)


async def _stamp_deferred_responses(
    db: AsyncSession,
    server_id: uuid.UUID,
    deferred: list[Any],
) -> int:
    """Stamp responses whose query row was committed by an earlier batch.

    Returns how many were matched. An unmatched response is dropped
    rather than stored on its own: a row with an outcome and no question
    answers nothing, and inventing a query row for it would double-count
    every query in the analytics rollups.
    """
    if not deferred:
        return 0
    matched = 0
    for resp in deferred[:_MAX_DEFERRED_RESPONSES]:
        stmt = (
            select(DNSQueryLogEntry)
            .where(DNSQueryLogEntry.server_id == server_id)
            .where(DNSQueryLogEntry.rcode.is_(None))
            .where(DNSQueryLogEntry.qname == resp.qname)
            .where(DNSQueryLogEntry.qtype == resp.qtype)
            .where(DNSQueryLogEntry.client_port == resp.client_port)
            .where(DNSQueryLogEntry.ts >= resp.ts - _RESPONSE_MATCH_WINDOW)
            # A response cannot precede its question, but the two lines
            # carry independently-formatted timestamps, so allow a small
            # amount of slack rather than losing a match to rounding.
            .where(DNSQueryLogEntry.ts <= resp.ts + timedelta(seconds=1))
            .order_by(DNSQueryLogEntry.ts.desc(), DNSQueryLogEntry.id.desc())
            .limit(1)
        )
        if resp.client_ip is not None:
            stmt = stmt.where(DNSQueryLogEntry.client_ip == resp.client_ip)
        row = (await db.execute(stmt)).scalars().first()
        if row is None:
            continue
        row.rcode = resp.rcode
        row.answer_count = resp.answer_count
        matched += 1
    return matched


# ── Admin runtime-state push (rendered config + rndc status) ─────────


class RenderedConfigFile(BaseModel):
    """One materialised file from the agent's rendered config tree."""

    path: str  # relative path inside the rendered/ dir, e.g. "named.conf" or "zones/example.com.db"
    content: str


class RenderedConfigReport(BaseModel):
    """Snapshot the agent ships after a successful structural apply.

    The agent walks ``state_dir/rendered/`` and ships every file it
    finds. Total payload is bounded by the size of the operator's
    config — typically <100 KB even for groups with hundreds of zones.
    """

    files: list[RenderedConfigFile]


# Hard cap on what the control plane will accept. Defends against an
# agent shipping an unbounded zone tree without the operator noticing.
_RENDERED_FILES_MAX = 5_000
_RENDERED_FILE_SIZE_MAX = 256 * 1024  # 256 KB per file
_RENDERED_TOTAL_SIZE_MAX = 8 * 1024 * 1024  # 8 MB total


@router.post("/admin/rendered-config")
async def agent_rendered_config(
    body: RenderedConfigReport,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest the agent's most-recent rendered config snapshot.

    Idempotent: writes (or upserts) the single ``DNSServerRuntimeState``
    row keyed on server_id. The previous snapshot is replaced wholesale
    — there is no history kept beyond "current".
    """
    server, _ = auth
    files = body.files[:_RENDERED_FILES_MAX]
    total = 0
    sanitised: list[dict[str, str]] = []
    for f in files:
        if len(f.content) > _RENDERED_FILE_SIZE_MAX:
            # Truncate rather than reject — operator wants to *see*
            # something even if a single file blew the cap.
            content = f.content[:_RENDERED_FILE_SIZE_MAX] + "\n... [truncated by control plane]\n"
        else:
            content = f.content
        total += len(content)
        if total > _RENDERED_TOTAL_SIZE_MAX:
            break
        sanitised.append({"path": f.path, "content": content})

    now = datetime.now(UTC)
    state = await db.get(DNSServerRuntimeState, server.id)
    if state is None:
        state = DNSServerRuntimeState(
            server_id=server.id,
            rendered_files=sanitised,
            rendered_at=now,
        )
        db.add(state)
    else:
        state.rendered_files = sanitised
        state.rendered_at = now
    await db.commit()
    return {"status": "ok", "files": len(sanitised)}


class RndcStatusReport(BaseModel):
    text: str


@router.post("/admin/rndc-status")
async def agent_rndc_status(
    body: RndcStatusReport,
    db: DB,
    auth: tuple[DNSServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, str]:
    """Ingest the agent's most-recent ``rndc status`` output.

    The agent shells out to ``rndc status`` once a minute. We keep the
    raw text plus a timestamp; the UI shows it on the Overview tab so
    operators can confirm ``named`` is up + which zones are loaded
    without SSHing into the host.
    """
    server, _ = auth
    text = body.text[:_RENDERED_FILE_SIZE_MAX]  # rndc status is normally a few KB
    now = datetime.now(UTC)
    state = await db.get(DNSServerRuntimeState, server.id)
    if state is None:
        state = DNSServerRuntimeState(
            server_id=server.id,
            rndc_status_text=text,
            rndc_observed_at=now,
        )
        db.add(state)
    else:
        state.rndc_status_text = text
        state.rndc_observed_at = now
    await db.commit()
    return {"status": "ok"}
