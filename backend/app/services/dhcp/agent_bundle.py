"""Stored DHCP agent config bundles (#1111) — what the agent long-poll serves.

The DHCP long-poll used to rebuild the whole bundle (``build_config_bundle``:
the group, its scopes, pools, reservations, classes, the E911 / fingerprint
lookups) on the api's request loop, once per agent per wake and per safety
tick. It is now rendered by the worker (``tasks.dhcp_agent_bundles``), stored
in ``dhcp_agent_bundle`` and served as stored. The wire shape is unchanged
(:func:`wire_bundle` is the serialisation the route always did inline) and so
is the ETag (``bundle.compute_etag`` inside the render, the fleet and host
config blocks mixed in by the route as before): no agent change.

Whether a stored bundle is current is two integers, as for DNS
(``is_current``): ``DHCPServer.bundle_dirty_seq`` is bumped in the transaction
of every change the listener below recognises, and the stored row records the
value it was rendered at. A bundle also reads inputs that change without a
write the listener can attribute (E911 location freshness, observed
fingerprints, an expiring MAC block), so the worker's sweep re-renders every
agent server at least every ``dhcp_agent_bundle_refresh_seconds``; a render
that changes nothing stores nothing. Over-marking costs one render, never a
stale bundle; the sweep bounds anything the listener misses.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import event, func, select, update
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.drivers.dhcp.base import ConfigBundle
from app.drivers.dhcp.kea import option_defs_for_option_maps
from app.models.dhcp import (
    DHCPAgentBundle,
    DHCPClientClass,
    DHCPMACBlock,
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPPool,
    DHCPPXEArchMatch,
    DHCPPXEProfile,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.feature_module import FeatureModule
from app.models.ipam import Subnet
from app.models.ownership import Site
from app.models.vlans import VLAN
from app.services.dhcp.config_bundle import build_config_bundle

logger = structlog.get_logger(__name__)

RENDERED_BY_WORKER = "worker"
RENDERED_BY_API = "api"

# Bump with anything that changes the wire body for the same database state
# (``wire_bundle``, ``build_config_bundle``, the ETag mix). A stored bundle
# from an older revision reads as stale and is re-rendered, so an upgrade never
# serves the previous renderer's bytes. Compared with ``>=``: an older process
# never replaces a newer render during a rolling upgrade.
RENDERER_REVISION = 1


def wire_bundle(bundle: ConfigBundle) -> dict[str, Any]:
    """The ``bundle`` object of the agent's ``/config`` response."""
    return {
        "server_name": bundle.server_name,
        "driver": bundle.driver,
        "roles": list(bundle.roles),
        # Issue #365 — server-wide Kea interfaces-config. The
        # agent's render_kea reads ``dhcp_socket_type`` here;
        # ``raw`` (from group socket_mode "direct") lets Kea
        # receive broadcast DISCOVERs from directly-attached
        # clients, ``udp`` is relay-only. Folded into the
        # bundle ETag so a mode change wakes the long-poll.
        "server": {
            "interfaces": ["*"],
            "dhcp_socket_type": bundle.dhcp_socket_type,
            # #637 — group-wide Kea lease cache. Scopes may
            # override (see the per-scope keys below); the agent
            # falls back to these when the scope value is null.
            "lease_cache_threshold": bundle.lease_cache_threshold,
            "lease_cache_max_age": bundle.lease_cache_max_age,
            # #980 — Kea's packet-worker pool. Serialized here
            # as well as folded into the ETag; those are
            # separate steps and skipping this one is the #430
            # silent no-op the lease-cache keys above call out.
            "kea_thread_pool_size": bundle.kea_thread_pool_size,
            "kea_packet_logging": bundle.kea_packet_logging,
        },
        "scopes": [
            {
                "subnet_cidr": s.subnet_cidr,
                "lease_time": s.lease_time,
                # #430 — min/max were settable + in the ETag but
                # never shipped, so the agent never rendered
                # min/max-valid-lifetime (silent no-op).
                "min_lease_time": s.min_lease_time,
                "max_lease_time": s.max_lease_time,
                # #637 — per-scope lease-cache override; null =
                # inherit the group value from the "server" block
                # above. Serialized here as well as folded into
                # the ETag: those are separate steps, and skipping
                # this one is exactly the #430 silent no-op.
                "lease_cache_threshold": s.lease_cache_threshold,
                "lease_cache_max_age": s.lease_cache_max_age,
                "options": s.options,
                # Issue #330 — the agent's render_kea branches on
                # these to emit a Dhcp6/subnet6 entry for v6
                # scopes. Without them every scope rendered as
                # Dhcp4 regardless of family. v6_address_mode
                # gates whether the v6 subnet serves pools /
                # options (stateful | stateless | slaac).
                "address_family": s.address_family,
                "v6_address_mode": s.v6_address_mode,
                # Issue #337 — relay-agent IPs the agent's
                # render_kea emits as ``relay: {"ip-addresses":
                # [...]}`` so a centralized Kea matches this
                # scope on giaddr for relayed remote subnets.
                "relay_addresses": list(s.relay_addresses),
                # #2731: the classes of the PXE profile bound
                # to this scope. The agent has Kea evaluate
                # them for this subnet alone; rendered for the
                # whole server, one scope's profile booted the
                # PXE clients of every scope on it.
                "pxe_class_names": list(s.pxe_class_names),
                "pools": [
                    {
                        "start_ip": p.start_ip,
                        "end_ip": p.end_ip,
                        "pool_type": p.pool_type,
                        # DHCPv6 prefix delegation (#368) — the
                        # agent's render_kea reads these for
                        # pool_type == "pd". Null for v4 / range
                        # pools.
                        "pd_prefix": p.pd_prefix,
                        "delegated_length": p.delegated_length,
                        "excluded_prefix": p.excluded_prefix,
                        "class_restriction": p.class_restriction,
                        # #858 — per-pool option overrides are
                        # settable and ETag-hashed, and the
                        # control-plane driver renders them, but
                        # were omitted here: the same silent drop
                        # #430 hit for statics' options_override
                        # (serialized on the very next block).
                        "options_override": p.options_override,
                    }
                    for p in s.pools
                ],
                "statics": [
                    {
                        "ip_address": st.ip_address,
                        "mac_address": st.mac_address,
                        "hostname": st.hostname,
                        # #430 — client_id + options_override
                        # are settable, ETag-hashed, and the
                        # agent renderer reads them, but were
                        # omitted here: a client-id-keyed
                        # reservation silently fell back to MAC
                        # and per-host options were dropped.
                        "client_id": st.client_id,
                        "options_override": st.options_override,
                        # DHCPv6 DUID (#368) — keys the v6
                        # reservation instead of the MAC.
                        "duid": st.duid,
                    }
                    for st in s.statics
                ],
            }
            for s in bundle.scopes
        ],
        "client_classes": [
            {
                "name": c.name,
                "match_expression": c.match_expression,
                # ``options`` stays for an agent older than
                # #1229, which renders it into both daemons.
                # A newer agent reads ``address_family`` and
                # the per-family maps instead. It carries the
                # Dhcp4 share, not the whole map: an ``ipv6``
                # or ``dual`` class may now hold an IPv6
                # ``dns-servers``, which an old agent would
                # put into Dhcp4 and have the config refused.
                "options": c.options_v4,
                "address_family": c.address_family,
                "options_v4": c.options_v4,
                "options_v6": c.options_v6,
            }
            for c in bundle.client_classes
        ],
        # #858 — PXE + phone classes were folded into the bundle
        # ETag and rendered by the control-plane driver, but
        # never serialized here. The consequence was worse than a
        # plain omission: editing a PXE profile DID move the
        # ETag, so it broke every agent's /config long-poll and
        # they all re-fetched — a payload with no PXE classes in
        # it, which re-rendered byte-identical config. A
        # guaranteed no-op resync of the whole group, and a
        # feature (README-advertised PXE provisioning profiles)
        # that could never reach agent-managed Kea at all.
        "pxe_classes": [
            {
                "name": p.name,
                "match_expression": p.match_expression,
                "next_server": p.next_server,
                "boot_file_name": p.boot_file_name,
                "is_ipxe_chain": p.is_ipxe_chain,
            }
            for p in bundle.pxe_classes
        ],
        "phone_classes": [
            {
                "name": c.name,
                "match_expression": c.match_expression,
                "options": c.options,
            }
            for c in bundle.phone_classes
        ],
        # #700 — fingerprint-driven device policies. Serialized
        # here for the reason #858 documents one block up: a
        # class that is ETag-hashed and rendered by the
        # control-plane driver but absent from the wire cannot
        # reach agent-managed Kea, which is how both the
        # appliance and the Compose stack run DHCP — i.e. the
        # feature would work nowhere it actually runs.
        "device_policy_classes": [
            {
                "name": c.name,
                "match_expression": c.match_expression,
                "options": c.options,
                "lease_time": c.lease_time,
            }
            for c in bundle.device_policy_classes
        ],
        # #858 — Kea types a raw ``code:NN`` option as BINARY,
        # so an operator's string value ("not a valid string of
        # hexadecimal digits") fails the WHOLE config. The real
        # type comes from the VoIP / option-code catalogues,
        # which live in this package and not the agent's, so the
        # control plane resolves the definitions once and the
        # agent emits them verbatim — rather than keeping a
        # second copy of the table, which is the drift that
        # caused #856.
        "option_defs": option_defs_for_option_maps(
            [bundle.options.options]
            + [s.options for s in bundle.scopes]
            + [p.options_override for s in bundle.scopes for p in s.pools]
            + [st.options_override for s in bundle.scopes for st in s.statics]
            + [c.options for c in bundle.client_classes]
            + [c.options for c in bundle.phone_classes]
            # #700 — a device policy can deliver a raw
            # ``code:NN`` vendor option just as a phone profile
            # can; without its definition Kea types the value
            # BINARY and rejects the WHOLE config.
            + [c.options for c in bundle.device_policy_classes]
        ),
        "mac_blocks": [
            {
                "mac_address": m.mac_address,
                "reason": m.reason,
                "description": m.description,
            }
            for m in bundle.mac_blocks
        ],
        # Kea HA hook configuration — absent when the
        # server isn't part of a failover channel. The
        # agent's render_kea.py keys off the presence of
        # this ``peers`` list to decide whether to emit
        # ``libdhcp_ha.so``.
        "failover": (
            {
                "channel_id": bundle.failover.channel_id,
                "channel_name": bundle.failover.channel_name,
                "mode": bundle.failover.mode,
                "this_server_name": bundle.failover.this_server_name,
                "peers": list(bundle.failover.peers),
                "heartbeat_delay_ms": bundle.failover.heartbeat_delay_ms,
                "max_response_delay_ms": bundle.failover.max_response_delay_ms,
                "max_ack_delay_ms": bundle.failover.max_ack_delay_ms,
                "max_unacked_clients": bundle.failover.max_unacked_clients,
                # HA peer credential (PEM). Absent until every
                # Kea member advertises ``ha_peer_tls``; an
                # agent that predates it ignores the key.
                "tls": (
                    {
                        "ca_pem": bundle.failover.tls_ca_pem,
                        "cert_pem": bundle.failover.tls_cert_pem,
                        "key_pem": bundle.failover.tls_key_pem,
                    }
                    if bundle.failover.tls_key_pem
                    else None
                ),
            }
            if bundle.failover is not None
            else None
        ),
        # IPv6 Router Advertisements (issue #524) — the
        # pre-rendered radvd.conf the agent writes + runs
        # radvd from when RADVD_MANAGED=1. Empty string when
        # no scope in the group has ``ra_enabled`` set.
        "radvd_conf": bundle.radvd_conf,
    }


def is_current(server: DHCPServer, stored: DHCPAgentBundle | None) -> bool:
    """True when ``stored`` reflects every change marked so far and came from
    this process's renderer revision or a newer one."""
    return (
        stored is not None
        and stored.dirty_watermark >= server.bundle_dirty_seq
        and stored.renderer_revision >= RENDERER_REVISION
    )


async def load_stored(db: AsyncSession, server_id: uuid.UUID) -> DHCPAgentBundle | None:
    # populate_existing: the store is a Core upsert, which never touches an
    # instance already in the session's identity map.
    return (
        await db.execute(
            select(DHCPAgentBundle)
            .where(DHCPAgentBundle.server_id == server_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


@dataclass
class Rendered:
    etag: str
    watermark: int
    render_ms: int


async def render_and_store(db: AsyncSession, server: DHCPServer, *, rendered_by: str) -> Rendered:
    """Render ``server``'s bundle at its current dirty sequence and store it.

    The sequence is read BEFORE the build, so a change committing mid-render
    leaves the stored watermark behind the server's and the next render runs.
    Idempotent: a second render of the same state replaces the row with the
    same bytes. The caller commits.
    """
    watermark = (
        await db.execute(select(DHCPServer.bundle_dirty_seq).where(DHCPServer.id == server.id))
    ).scalar_one()
    started = time.monotonic()
    bundle = await build_config_bundle(db, server)
    body = json.dumps(
        wire_bundle(bundle), separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=str
    )
    render_ms = int((time.monotonic() - started) * 1000)
    values = {
        "server_id": server.id,
        "dirty_watermark": watermark,
        "renderer_revision": RENDERER_REVISION,
        "bundle_etag": bundle.etag,
        "has_failover": bundle.failover is not None,
        "body": body,
        "rendered_by": rendered_by,
        "render_ms": render_ms,
    }
    stmt = pg_insert(DHCPAgentBundle).values(id=uuid.uuid4(), **values)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_dhcp_agent_bundle_server",
        set_={**{k: v for k, v in values.items() if k != "server_id"}, "built_at": func.now()},
        # Never move a stored bundle backwards: a render that started earlier
        # and finished later than a newer one must not replace it.
        where=DHCPAgentBundle.dirty_watermark <= watermark,
    )
    await db.execute(stmt)
    return Rendered(etag=bundle.etag, watermark=watermark, render_ms=render_ms)


# ── Dirty marking ──────────────────────────────────────────────────────────
#
# Every agent-based DHCP server's bundle reads the group's configuration, its
# peers (the failover block) and rows outside ``dhcp_*`` (subnet, VLAN, site,
# ERLs, feature modules). DHCP estates are a handful of servers, so a change to
# any contributor marks EVERY agent server: over-marking costs a render, and a
# render that changes nothing stores nothing.

_CONTRIBUTORS: tuple[type, ...] = (
    DHCPServerGroup,
    DHCPScope,
    DHCPPool,
    DHCPStaticAssignment,
    DHCPClientClass,
    DHCPMACBlock,
    DHCPPXEProfile,
    DHCPPXEArchMatch,
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPDevicePolicy,
    EmergencyResponseLocation,
    ERLBinding,
    FeatureModule,
    VLAN,
    Site,
)
# Columns of a DHCPServer the bundle reads (identity, group membership, HA).
_SERVER_COLUMNS = (
    "name",
    "driver",
    "roles",
    "server_group_id",
    "ha_peer_url",
    "agent_capabilities",
)
# Columns of a Subnet the bundle reads.
_SUBNET_COLUMNS = ("network", "site_id", "vlan_ref_id", "dns_servers", "domain_name")


def _net_change(obj: Any, columns: Iterable[str]) -> bool:
    insp = sa_inspect(obj)
    for col in columns:
        hist = insp.attrs[col].history
        if hist.has_changes() and list(hist.added) != list(hist.deleted):
            return True
    return False


def _touches_bundle(session: Any) -> bool:
    for obj in session.new:
        if isinstance(obj, (*_CONTRIBUTORS, DHCPServer, Subnet)):
            return True
    for obj in session.deleted:
        if isinstance(obj, (*_CONTRIBUTORS, DHCPServer, Subnet)):
            return True
    for obj in session.dirty:
        if isinstance(obj, _CONTRIBUTORS) and session.is_modified(obj):
            return True
        if isinstance(obj, DHCPServer) and _net_change(obj, _SERVER_COLUMNS):
            return True
        if isinstance(obj, Subnet) and _net_change(obj, _SUBNET_COLUMNS):
            return True
    return False


@dataclass
class _Marks:
    pending: bool = False
    issued: bool = False
    bumped: set[uuid.UUID] = field(default_factory=set)


_MARKS_KEY = "spatium_dhcp_bundle_marks"


def _marks(session: Any) -> _Marks:
    marks = session.info.get(_MARKS_KEY)
    if marks is None:
        marks = session.info[_MARKS_KEY] = _Marks()
    return marks


def _bump(session: Any) -> list[uuid.UUID]:
    """Bump every agent server's ``bundle_dirty_seq`` on the session's
    connection, locking the rows in id order first so two committers marking
    the same servers cannot deadlock."""
    conn = session.connection()
    ids = list(
        conn.execute(select(DHCPServer.id).order_by(DHCPServer.id).with_for_update(key_share=True))
        .scalars()
        .all()
    )
    if not ids:
        return []
    conn.execute(
        update(DHCPServer)
        .where(DHCPServer.id.in_(ids))
        .values(bundle_dirty_seq=DHCPServer.bundle_dirty_seq + 1)
    )
    return ids


async def mark_bundles_dirty(db: AsyncSession) -> None:
    """Mark every DHCP bundle dirty for a write the listener cannot see (a Core
    statement on a bundle input). Takes effect at the caller's commit."""
    await db.run_sync(lambda session: setattr(_marks(session), "pending", True))


def _after_flush(session: Any, flush_context: Any) -> None:  # noqa: ARG001
    if not _touches_bundle(session):
        return
    marks = _marks(session)
    if marks.issued:
        marks.bumped.update(_bump(session))
    else:
        marks.pending = True


def _before_commit(session: Any) -> None:
    if session.in_nested_transaction():
        return
    # before_commit runs before commit's own final flush: flush now so the
    # marks of whatever is still pending are collected before the bump.
    session.flush()
    marks = _marks(session)
    if marks.pending:
        marks.bumped.update(_bump(session))
        marks.pending = False
    marks.issued = True


def _after_commit(session: Any) -> None:
    if session.in_nested_transaction():
        return
    marks = session.info.pop(_MARKS_KEY, None)
    if marks is not None and marks.bumped:
        schedule_renders(marks.bumped)


def _after_transaction_end(session: Any, transaction: Any) -> None:
    if transaction.parent is None:
        session.info.pop(_MARKS_KEY, None)


def _enqueue_sync(server_ids: list[str]) -> None:
    if not settings.dhcp_agent_bundle_enqueue_renders:
        return
    try:
        from app.tasks.dhcp_agent_bundles import enqueue_render  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        logger.warning("dhcp_agent_bundle_enqueue_unavailable", error=str(exc))
        return
    for sid in server_ids:
        if not enqueue_render(sid):
            return


async def enqueue_renders(server_ids: Iterable[uuid.UUID | str]) -> None:
    ids = [str(s) for s in server_ids]
    if ids:
        await asyncio.to_thread(_enqueue_sync, ids)


def schedule_renders(server_ids: Iterable[uuid.UUID | str]) -> None:
    ids = [str(s) for s in server_ids]
    if not ids:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _enqueue_sync(ids)
        return
    loop.create_task(enqueue_renders(ids))


_LISTENERS = (
    ("after_flush", _after_flush),
    ("before_commit", _before_commit),
    ("after_commit", _after_commit),
    ("after_transaction_end", _after_transaction_end),
)


def install() -> None:
    """Attach the listeners to every session class. Idempotent; runs on
    import, which the api (``api.v1.dhcp.agents``) and the worker
    (``tasks.dhcp_agent_bundles``) both do."""
    target = AsyncSession.sync_session_class
    for name, fn in _LISTENERS:
        if not event.contains(target, name, fn):
            event.listen(target, name, fn)


def installed() -> bool:
    target = AsyncSession.sync_session_class
    return all(event.contains(target, name, fn) for name, fn in _LISTENERS)


install()

__all__ = [
    "RENDERED_BY_API",
    "RENDERED_BY_WORKER",
    "RENDERER_REVISION",
    "installed",
    "is_current",
    "load_stored",
    "mark_bundles_dirty",
    "render_and_store",
    "wire_bundle",
]
