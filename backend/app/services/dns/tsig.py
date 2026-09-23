"""Resolve the TSIG key the control plane signs zone transfers with (#734).

Agent-managed BIND9 and Technitium grant ``allow-transfer`` to a **key**,
not to a source address — the control plane's address is not knowable on
the appliance, where it can be any node in an HA control plane behind a
VIP. So every read-the-live-zone path (drift #61, sync-with-servers) has
to sign, and this module is the one place that decides *with which key*.

The choice has to agree with what the agent granted, or the transfer is
REFUSED just as surely as an unsigned one. Both agent drivers grant every
key in ``bundle["tsig_keys"]``, and ``build_agent_bundle`` builds that list
as ``[group legacy key] + [operator DNSTSIGKey rows, sorted by name]``.
Picking the head of that same list keeps the two ends in agreement by
construction, and prefers the legacy group key — which exists on every
agent-managed group without operator action, so drift works out of the box
rather than only after someone creates a key.

Split-horizon adds a second question — *which view* answers (#920). BIND
picks the view for a request by ``match-clients`` before it looks at
``allow-transfer``, and the operator's client lists never name the control
plane. So each view the agent renders also admits one key of its own, derived
here from the group's key, and a transfer of a zone is signed with the key of
the view that holds that zone's copy. See :func:`view_transfer_key`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import uuid
from collections.abc import Sequence
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.drivers.dns import AXFR_TSIG_DRIVERS
from app.drivers.dns.base import RecordData, TsigKey
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSTSIGKey, DNSView, DNSZone
from app.services.dns.pool_geo import (
    GEO_DEFAULT_VIEW,
    build_geo_steering,
    build_view_descriptors,
    view_renders_zone,
)

logger = structlog.get_logger(__name__)

#: Name prefix of the per-view transfer keys (#920). The underscore keeps the
#: namespace disjoint from both kinds of key a group already has: operator
#: key names are ``[a-z0-9.-]`` only (``_TSIG_NAME_RE`` in the DNS router), and
#: the legacy group key is ``spatium-<label>``. A clash would render two
#: ``key`` statements with one name, which fails ``named-checkconf`` — and with
#: it the whole group's config.
VIEW_TRANSFER_KEY_PREFIX = "spatium_xfr_"


def transfer_needs_tsig(server: DNSServer) -> bool:
    """True when this server's zone transfers have to be TSIG-signed.

    The driver alone is necessary but **not sufficient**. ``bind9`` and
    ``technitium`` are the drivers whose *agent* renders the key-gated
    ``allow-transfer`` — but a row with those drivers can equally be an
    operator's own BIND9 that SpatiumDDI never configures, pointed at by
    host and authorised the ordinary way, by address. Nothing was ever
    deployed there, so there is no group key on that server: signing would
    turn a working unsigned pull into NOTAUTH, and refusing to pull for
    lack of a key would break it a different way.

    ``agent_id`` is the discriminator, set only by
    ``POST /dns/agents/register``. A row awaiting its first registration
    reads as not-agent-managed, which is right — until the agent checks in
    there is no agent-rendered ``named.conf`` to have granted anything.
    """
    return server.driver in AXFR_TSIG_DRIVERS and server.agent_id is not None


async def resolve_group_transfer_key(db: AsyncSession, group_id: uuid.UUID) -> TsigKey | None:
    """Return the key to sign transfers from ``group_id`` with, or None.

    None means the group has no usable key. Callers must treat that as
    "this transfer cannot succeed" for a driver in ``AXFR_TSIG_DRIVERS``
    rather than falling through to an unsigned attempt, which fails the
    same way but reports a misleading reason.
    """
    legacy = legacy_group_key(await db.get(DNSServerGroup, group_id))
    if legacy is not None:
        return legacy

    # No legacy key — fall back to the first operator-managed key, matching
    # the bundle's ordering so the agent has granted this one too.
    rows = (
        (
            await db.execute(
                select(DNSTSIGKey).where(DNSTSIGKey.group_id == group_id).order_by(DNSTSIGKey.name)
            )
        )
        .scalars()
        .all()
    )
    for k in rows:
        try:
            secret = decrypt_str(k.secret_encrypted)
        except ValueError:
            # Same posture as the bundle builder: a row whose secret won't
            # decrypt is skipped, not fatal. It is also skipped from the
            # bundle, so the agent never granted it either — the two stay
            # consistent, and a later key in the list may still work.
            logger.warning(
                "dns.tsig.transfer_key_undecryptable",
                group=str(group_id),
                key=k.name,
            )
            continue
        return TsigKey(name=k.name, algorithm=k.algorithm, secret=secret)
    return None


def legacy_group_key(group: DNSServerGroup | None) -> TsigKey | None:
    """The group's own auto-minted key (``ensure_group_tsig_key``), or None.

    Never an operator key: this is the product's own identity toward its
    agents, and its secret is returned by no API.
    """
    if group is None or not group.tsig_key_name or not group.tsig_key_secret:
        return None
    return TsigKey(
        name=group.tsig_key_name,
        algorithm=group.tsig_key_algorithm or "hmac-sha256",
        secret=group.tsig_key_secret,
    )


def view_transfer_key(group_key: TsigKey, view_name: str) -> TsigKey:
    """The key that selects ``view_name`` for the control plane's own transfers (#920).

    Under split-horizon a request is answered by the first view whose
    ``match-clients`` it matches, and BIND decides that before it consults
    ``allow-transfer``. The operator fills ``match-clients`` with the clients
    each view is for; nothing in it names the control plane, whose address is
    not knowable on the appliance anyway (the reason #734 grants transfers by
    key). So a signed transfer from the api either matches no view — BIND then
    answers BADKEY, blaming a key that is loaded and granted — or is captured
    by whichever broad view happens to match the pod's address, and reads
    that view's copy of the zone. ``match-clients`` also selects by key, so
    the agent admits this key into exactly its own view (and refuses it in
    every other one) and the control plane signs with it.

    Derived, not stored: an HMAC-SHA256 of the view name under the group's
    legacy key. The bundle builder (which renders it into the view) and the
    resolver (which signs with it) compute it from the same two inputs, so
    they agree by construction; there is nothing to migrate, and rotating the
    group key rotates every view key with it. Only the legacy group key is a
    base — its secret is product-internal, whereas an operator key's secret
    is handed to the operator's own DDNS clients, which could then compute a
    key that selects any view regardless of their address.
    """
    try:
        material = base64.b64decode(group_key.secret, validate=True)
    except (binascii.Error, ValueError):
        # Every secret ensure_group_tsig_key mints is base64. A hand-edited row
        # that isn't still has to derive the same key on both ends, and does.
        material = group_key.secret.encode()
    digest = hmac.new(
        material, b"spatium-view-transfer\x00" + view_name.encode(), hashlib.sha256
    ).digest()
    return TsigKey(
        name=VIEW_TRANSFER_KEY_PREFIX + hashlib.sha256(view_name.encode()).hexdigest()[:16],
        algorithm="hmac-sha256",
        secret=base64.b64encode(digest).decode(),
    )


def is_view_transfer_key(key: TsigKey | None) -> bool:
    return key is not None and key.name.startswith(VIEW_TRANSFER_KEY_PREFIX)


async def transfer_view_name(db: AsyncSession, zone: DNSZone) -> str | None:
    """The view whose copy of ``zone`` the control plane reads, or None when
    the zone's group renders no views.

    Only views that hold a copy are candidates — the same rule the bundle
    expands zones by (:func:`~app.services.dns.pool_geo.view_renders_zone`).
    Among them: the zone's own pinned view; else the first operator view in
    precedence order (it serves every shared record, plus its own scoped
    ones); else the geo catch-all, which serves the default pool members;
    else the first view left, which can only be a geo view.
    """
    views = list(
        (await db.execute(select(DNSView).where(DNSView.group_id == zone.group_id))).scalars().all()
    )
    geo = await build_geo_steering(db, zone.group_id)
    if not views and not geo.active:
        return None
    descs = build_view_descriptors(sorted(views, key=lambda v: (v.order, v.name)), geo)
    scoped = set(
        (
            await db.execute(
                select(DNSRecord.view_id)
                .where(DNSRecord.zone_id == zone.id, DNSRecord.view_id.is_not(None))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    targets = scoped | ({zone.view_id} if zone.view_id is not None else set())
    holding = [vd for vd in descs if view_renders_zone(vd, targets)]
    for pick in (
        lambda vd: vd["kind"] == "operator" and vd["id"] == zone.view_id,
        lambda vd: vd["kind"] == "operator",
        lambda vd: vd["kind"] == "default" and vd["name"] == GEO_DEFAULT_VIEW,
        lambda vd: True,
    ):
        for vd in holding:
            if pick(vd):
                return str(vd["name"])
    return None


async def resolve_view_transfer_key(db: AsyncSession, zone: DNSZone) -> tuple[TsigKey, str] | None:
    """``(key, view name)`` addressing a transfer of ``zone`` to the view that
    holds its copy, or None when that is not possible — the group renders no
    views, or has no legacy key to derive from — in which case callers sign
    with :func:`resolve_group_transfer_key`, exactly as before #920."""
    legacy = legacy_group_key(await db.get(DNSServerGroup, zone.group_id))
    if legacy is None:
        return None
    view_name = await transfer_view_name(db, zone)
    if view_name is None:
        return None
    return view_transfer_key(legacy, view_name), view_name


def _answered_badkey(exc: BaseException) -> bool:
    """True when the server answered BADKEY — "I don't know that key".

    The one failure trying another key can change. The AXFR helper re-raises
    dnspython's ``PeerBadKey`` as a ``RuntimeError`` carrying it as the cause,
    so walk the chain rather than test the outer type.
    """
    seen: BaseException | None = exc
    for _ in range(8):
        if seen is None:
            return False
        if type(seen).__name__ == "PeerBadKey":
            return True
        seen = seen.__cause__
    return False


async def pull_zone_records_signed(
    driver: Any,
    server: Any,
    zone_name: str,
    keys: Sequence[TsigKey | None],
    *,
    view_name: str | None = None,
) -> tuple[list[RecordData], TsigKey | None]:
    """``driver.pull_zone_records`` with each of ``keys`` in turn.

    Moves to the next key only when the server answered BADKEY. That is how an
    agent that predates the per-view keys (#920) answers one — it never
    rendered the key — so falling back to the group key keeps such a server
    exactly as readable as it was: by whichever view its address selects.
    Every other failure (unreachable, REFUSED, a timeout) is final: another
    key cannot change it and would only double the wait.

    Returns the records and the key that read them. When every key fails, the
    FIRST failure is raised — the one a current agent should have accepted.
    If that was a view key answered BADKEY, the message says what BADKEY means
    under views, because the generic TSIG hint ("check the key name, secret
    and algorithm") sends the operator after a key that is fine.
    """
    first: Exception | None = None
    for i, key in enumerate(keys):
        try:
            return await driver.pull_zone_records(server, zone_name, tsig=key), key
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised
            first = first or exc
            if i == len(keys) - 1 or not _answered_badkey(exc):
                break
    assert first is not None  # keys is never empty at a call site
    if view_name is not None and is_view_transfer_key(keys[0]) and _answered_badkey(first):
        raise RuntimeError(
            f"{first} This zone is served from the DNS view {view_name!r}, and the "
            "server answers this way when a transfer matches none of its views: "
            "check that the server's agent has applied its current configuration, "
            "which admits SpatiumDDI's own transfers into each view."
        ) from first
    raise first


__all__ = [
    "VIEW_TRANSFER_KEY_PREFIX",
    "is_view_transfer_key",
    "legacy_group_key",
    "pull_zone_records_signed",
    "resolve_group_transfer_key",
    "resolve_view_transfer_key",
    "transfer_needs_tsig",
    "transfer_view_name",
    "view_transfer_key",
]


#: Characters legal in a derived TSIG key name. Everything else is folded to
#: a hyphen — see ``_safe_key_label``.
_UNSAFE_KEY_CHARS_RE = re.compile(r"[^a-z0-9_-]+")


def _safe_key_label(group: DNSServerGroup) -> str:
    """Fold a group name into a key name that is safe in ``named.conf``.

    The result is interpolated VERBATIM into ``key "<name>" { … };`` by both
    agent renderers, so a group named ``edge"; };`` would close the statement
    early and inject the rest. That is not a cosmetic break: BIND rejects the
    file whole, ``named-checkconf`` fails, and the agent declines the entire
    bundle — so one badly-named group stops its whole group converging, with
    the same blast radius as the #876 / #899 findings.

    Sanitising rather than rejecting is deliberate. The key name is DERIVED,
    not typed: an operator naming a group ``Edge (DMZ)`` has done nothing
    wrong and should not be refused because of how we build an identifier
    from it. Group names are not unique per rendered config either — a
    bundle carries one legacy key, its own group's — so folding two names
    together cannot collide in practice.
    """
    label = _UNSAFE_KEY_CHARS_RE.sub("-", (group.name or "").strip().lower()).strip("-")
    # Nothing survived (a name that is entirely punctuation or non-ASCII).
    # Fall back to the id, which is always a safe identifier and unique.
    return f"spatium-{label}" if label else f"spatium-{group.id}"


def ensure_group_tsig_key(group: DNSServerGroup) -> bool:
    """Give ``group`` a legacy group TSIG key if it has none yet.

    The agent renders this key into ``tsig/ddns.key`` and signs its
    loopback RFC 2136 updates with it; ``resolve_group_transfer_key``
    above prefers it for AXFR because it exists on every agent-managed
    group without operator action. Historically it was generated inline
    on first agent registration, which meant a group created through the
    UI — or one a server is MOVED into (#934) — could reach an agent with
    no key at all.

    Returns True when a key was generated, False when one already existed.
    Mutates the row; the caller commits.
    """
    if group.tsig_key_secret:
        return False
    group.tsig_key_name = _safe_key_label(group)
    group.tsig_key_secret = base64.b64encode(secrets.token_bytes(32)).decode()
    group.tsig_key_algorithm = "hmac-sha256"
    return True
