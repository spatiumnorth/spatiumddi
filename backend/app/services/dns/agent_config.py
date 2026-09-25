"""Build the AgentConfigBundle delivered to DNS agents via long-poll.

Seam with the driver-abstraction agent:
  The canonical ConfigBundle type lives at
  ``app.services.dns.config_bundle.ConfigBundle`` (authored by the parallel
  driver-abstraction agent). If that module is not present at import time we
  fall back to a local TypedDict-based adapter with the same shape so this
  code still builds. When the real module appears, imports resolve to it
  transparently.

#1111 — the assembly is split in two. ``render_bundle_body`` builds
everything except the ops page and is what the worker render (and the
migration-release inline fallback) store once per (server, watermark);
``page_pending_ops`` / ``retire_queued_ops`` are the per-server, per-poll
half the long-poll applies per request; ``build_config_bundle`` composes
the two into the whole dict for callers that still want it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypedDict

import structlog
from sqlalchemy import Boolean, Text, and_, cast, func, literal, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.types import UserDefinedType

from app.config import settings
from app.core.crypto import decrypt_str
from app.models.appliance import ApplianceCertificate
from app.models.dns import (
    DNSAcl,
    DNSRecord,
    DNSRecordOp,
    DNSSECPolicy,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ntp import ntp_bundle
from app.services.appliance.snmp import snmp_bundle
from app.services.dns.named_conf_validation import (
    AclCycleError,
    ViewValidationError,
    is_name_reference,
    order_acls_for_render,
    validate_acl_name,
    validate_address_match_list,
)
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    records_for_view,
)
from app.services.dns.record_ops import QUEUED_OP_STATES
from app.services.dns_blocklist import (
    build_effective_for_group,
    build_effective_for_view,
)

try:  # pragma: no cover - seam with parallel driver-abstraction agent
    from app.services.dns.config_bundle import ConfigBundle  # type: ignore[assignment]
except ImportError:  # fallback local adapter — same shape as canonical type

    class ConfigBundle(TypedDict, total=False):  # type: ignore[no-redef]
        etag: str
        server_id: str
        driver: str
        options: dict[str, Any]
        views: list[dict[str, Any]]
        acls: list[dict[str, Any]]
        zones: list[dict[str, Any]]
        tsig_keys: list[dict[str, Any]]
        forwarders: list[str]
        blocklists: list[dict[str, Any]]
        pending_record_ops: list[dict[str, Any]]
        # Phase 8f-3 — fleet upgrade orchestration carries the desired
        # appliance version + slot image URL the operator set from the
        # Fleet view. The agent reads these on every long-poll bundle
        # and fires the local slot-upgrade trigger when its installed
        # version doesn't match. None / absent when no upgrade pending.
        fleet_upgrade: dict[str, Any]
        # Issue #153 — singleton snmpd.conf body + content hash. Agent
        # writes a host-side trigger when the hash changes vs. its
        # last-rendered config; the host's spatiumddi-snmp-reload.path
        # unit picks the file up + reloads snmpd.
        snmp_settings: dict[str, Any]
        # Issue #154 — singleton chrony.conf body + content hash. Same
        # trigger pipeline as snmp_settings.
        ntp_settings: dict[str, Any]


if TYPE_CHECKING:
    pass


logger = structlog.get_logger(__name__)


def _compute_etag(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonicalized payload (sorted keys)."""
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _safe_acls_block(acls: Sequence[Any]) -> list[dict[str, Any]]:
    """Assemble the bundle's ``acls`` block so that it always renders.

    Validation on the ACL endpoints (#899) guards what an operator types
    *from now on*. It cannot guard what is already in the table: ACL names
    and entry values were completely unvalidated before this change, and
    the moment the agent started rendering them a legacy row holding a bad
    CIDR — or a quote, or the name ``any`` — would break ``named.conf`` on
    upgrade with nobody having touched anything.

    So the bundle drops what it cannot render, loudly, rather than shipping
    a config the agent will refuse:

    * an ACL whose name is not a legal identifier is skipped entirely;
    * an individual entry that is not a legal address-match element is
      dropped, leaving the rest of the ACL intact;
    * an ACL left with no entries still renders (as ``{ none; }`` on the
      agent) because its name may already be cited;
    * a cyclic reference falls back to alphabetical order with the cycle
      broken, instead of raising.

    That last point matters most: this runs inside the agent's ``/config``
    long-poll. An exception here is not a failed edit, it is every agent in
    the group getting a 500 on every poll, forever, with no way to fix it
    from the UI — strictly worse than the inert-config bug being fixed.
    """
    prepared: list[dict[str, Any]] = []
    for acl in acls:
        try:
            name = validate_acl_name(acl.name)
        except ViewValidationError as exc:
            logger.warning("dns_acl_skipped_unrenderable_name", acl=str(acl.name), error=str(exc))
            continue
        entries: list[dict[str, Any]] = []
        for e in sorted(acl.entries, key=lambda e: (e.order, e.value)):
            try:
                # Syntax only — whether a bare name actually resolves is
                # decided by the known-set sweep below.
                validate_address_match_list([e.value], field="entries", allow_unknown_names=True)
            except ViewValidationError as exc:
                logger.warning(
                    "dns_acl_entry_dropped_unrenderable",
                    acl=name,
                    value=e.value,
                    error=str(exc),
                )
                continue
            entries.append({"value": e.value, "negate": e.negate})
        prepared.append({"id": str(acl.id), "name": name, "entries": entries})

    # A reference to an ACL that was just skipped would be an undefined
    # symbol, so drop those entries too.
    known = {a["name"] for a in prepared}
    for a in prepared:
        kept = []
        for e in a["entries"]:
            target = is_name_reference(str(e["value"]))
            if target is not None and target not in known:
                logger.warning(
                    "dns_acl_entry_dropped_dangling_reference", acl=a["name"], value=target
                )
                continue
            kept.append(e)
        a["entries"] = kept

    try:
        # Dependency-ordered because BIND resolves ``acl`` statements
        # top-down — a reference to one declared later in the file is an
        # error, not a forward declaration.
        return order_acls_for_render(prepared)
    except AclCycleError as exc:
        logger.error("dns_acl_cycle_in_bundle", error=str(exc))
        return sorted(prepared, key=lambda a: a["name"])


@dataclass(frozen=True)
class RenderedBody:
    """The bundle minus its per-poll parts (#1111).

    ``body`` is the bundle dict WITHOUT ``etag``, ``pending_record_ops`` and
    ``pending_ops_remaining``. ``etag`` is ``_compute_etag`` over the same
    canonical payload the inline build always hashed — those two keys
    present and empty — so a server with nothing pending hashes to exactly
    what it did before. ``has_views`` says whether an ops page is ever
    shipped: under split-horizon records are structural and the queued ops
    are retired by the render instead (``retire_queued_ops``).
    """

    body: dict[str, Any]
    etag: str
    structural_etag: str
    records: int
    has_views: bool


async def render_bundle_body(db: AsyncSession, server: DNSServer) -> RenderedBody:
    """Build everything in the bundle except the ops page, from DB state.

    This is the assembly ``build_config_bundle`` always did. The worker
    render (#1111) calls it once per (server, watermark) and stores the
    result; the long-poll serves the stored bytes and splices the ops page
    in per request.
    """
    # Options (per group)
    opts_res = await db.execute(
        select(DNSServerOptions).where(DNSServerOptions.group_id == server.group_id)
    )
    opts = opts_res.scalar_one_or_none()

    # Views
    views_res = await db.execute(select(DNSView).where(DNSView.group_id == server.group_id))
    views = views_res.scalars().all()
    # Split-horizon (issue #24). When the group defines views, every zone is
    # rendered INSIDE a ``view { match-clients … }`` block and records are
    # scoped per view (``DNSRecord.view_id``; NULL = shared across all
    # views). Lower ``order`` first → BIND first-match precedence.
    ordered_views = sorted(views, key=lambda v: (v.order, v.name))

    # Geo / topology-aware steering (issue #530). Synthesized geo views
    # (one per distinct pool-member serving scope) render BEFORE the
    # operator split-horizon views (with a catch-all appended LAST) so
    # BIND's first-match-wins picks a specific geo view before any broad
    # operator view swallows the geo-CIDR client — see
    # ``build_view_descriptors``. Geo steering forces views mode on even
    # for a group with no operator views.
    geo = await build_geo_steering(db, server.group_id)
    has_views = bool(views) or geo.active

    # Unified, ordered list of view descriptors that both the zone loop
    # and ``views_block`` render from. kind ∈ {operator, geo, default}.
    view_descs = build_view_descriptors(ordered_views, geo)

    # ACLs
    acls_res = await db.execute(
        select(DNSAcl)
        .where(DNSAcl.group_id == server.group_id)
        .options(selectinload(DNSAcl.entries))  # type: ignore[attr-defined]
    )
    acls = acls_res.scalars().all()

    # Zones (+ records for primary only)
    zones_res = await db.execute(select(DNSZone).where(DNSZone.group_id == server.group_id))
    zones = zones_res.scalars().all()

    # Dynamic-update ACLs (issue #641). One JOIN across every ACL row in the
    # group's zones, resolving each TSIG entry's key NAME (never the secret)
    # so the agent renders ``allow-update { <cidr>; key "<name>."; }``. Keyed
    # by zone_id → ordered entry dicts. Secrets stay Fernet-encrypted; only
    # the key name crosses the wire (the key material itself already ships in
    # the ``tsig_keys`` block for the agent to build the ``key {}`` stanza).
    zone_ids = [z.id for z in zones]
    update_acls_by_zone: dict[Any, list[dict[str, Any]]] = {}
    if zone_ids:
        acl_rows = (
            await db.execute(
                select(DNSZoneUpdateAcl, DNSTSIGKey.name)
                .outerjoin(DNSTSIGKey, DNSZoneUpdateAcl.tsig_key_id == DNSTSIGKey.id)
                .where(DNSZoneUpdateAcl.zone_id.in_(zone_ids))
                .order_by(DNSZoneUpdateAcl.zone_id, DNSZoneUpdateAcl.seq)
            )
        ).all()
        for acl, key_name in acl_rows:
            update_acls_by_zone.setdefault(acl.zone_id, []).append(
                {
                    "action": acl.action,
                    "match_kind": acl.match_kind,
                    "ip_cidr": acl.ip_cidr,
                    "tsig_key_name": key_name,
                    "name_scope": acl.name_scope,
                    "name_pattern": acl.name_pattern,
                    "record_types": acl.record_types,
                }
            )

    # Every record of every zone in ONE query, as column rows rather than
    # ORM instances. This was one ``select(DNSRecord)`` per zone inside the
    # loop below (N+1), and each row came back as a tracked ORM object — on
    # the sizing campaign's 250k A+PTR zone the build held ~500k instances
    # in the identity map for the life of the request, most of the api's
    # working set on every long-poll (2026-09-02/03). Only the eight fields
    # the bundle and the view filter read are fetched.
    #
    # The ordering exists so the rendered payload — and therefore the ETag —
    # is the same from one poll to the next. #1111: it is now the
    # ``ix_dns_record_zone_name`` prefix followed by every remaining shipped
    # column, not ``(zone_id, id)``. Stability needs a total order on what
    # the payload CARRIES — two rows identical in every shipped column
    # render identically whichever comes first — so ``id`` buys nothing,
    # and it cost a lot: no index covers ``(zone_id, id)`` and ``id`` is a
    # random UUID, so at 1.09 M rows the planner sorted the whole table
    # (an external merge at the shipped ``work_mem``) inside asyncpg's 30 s
    # ``command_timeout``, and every poll of every agent answered 503
    # (seven-node probe, 2026-09-21). With the index prefix the planner can
    # walk ``(zone_id, name)`` and finish the tie-break with an incremental
    # sort on the tiny per-name groups instead of sorting the table.
    records_by_zone: dict[Any, list[Any]] = {}
    if zone_ids:
        rec_res = await db.execute(
            select(
                DNSRecord.zone_id,
                DNSRecord.name,
                DNSRecord.record_type,
                DNSRecord.ttl,
                DNSRecord.value,
                DNSRecord.priority,
                DNSRecord.weight,
                DNSRecord.port,
                DNSRecord.view_id,
                DNSRecord.pool_member_id,
            )
            .where(DNSRecord.zone_id.in_(zone_ids))
            .order_by(
                DNSRecord.zone_id,
                DNSRecord.name,
                DNSRecord.record_type,
                DNSRecord.value,
                DNSRecord.ttl,
                DNSRecord.priority,
                DNSRecord.weight,
                DNSRecord.port,
                DNSRecord.view_id,
                DNSRecord.pool_member_id,
            )
        )
        for rec in rec_res:
            records_by_zone.setdefault(rec.zone_id, []).append(rec)

    def _rec_dict(r: Any) -> dict[str, Any]:
        return {
            "name": r.name,
            "type": r.record_type,
            "ttl": r.ttl,
            "value": r.value,
            "priority": r.priority,
            "weight": r.weight,
            "port": r.port,
        }

    # DNSSEC policies (issue #49) — resolve each signed zone's policy name +
    # ship the referenced custom policy definitions so the BIND9 agent can
    # render ``dnssec-policy { ... }`` blocks + per-zone inline-signing. The
    # built-in "default" carries no block (BIND ships it).
    dnssec_policy_rows = list((await db.execute(select(DNSSECPolicy))).scalars().all())
    dnssec_policies_by_id = {p.id: p for p in dnssec_policy_rows}

    def _zone_policy_name(z: DNSZone) -> str | None:
        pid = getattr(z, "dnssec_policy_id", None)
        if not getattr(z, "dnssec_enabled", False) or pid is None:
            return None
        pol = dnssec_policies_by_id.get(pid)
        return pol.name if pol is not None else None

    zone_payload: list[dict[str, Any]] = []
    for z in zones:
        base_zp: dict[str, Any] = {
            "id": str(z.id),
            "name": getattr(z, "name", None) or getattr(z, "fqdn", None),
            "type": getattr(z, "zone_type", "primary"),
            # #430 — was getattr(z, "default_ttl", 3600): DNSZone has no
            # default_ttl, so this silently pinned every zone's $TTL to the
            # literal 3600 and editing a zone's TTL never re-rendered.
            "ttl": getattr(z, "ttl", 3600),
            # #430 (D1) — the agent's zone-state reporter skips any zone with
            # serial=None, so omitting this made it report nothing for every
            # zone and the per-server ZoneSyncPill stayed empty. Ship the
            # authoritative serial the agent renders from.
            "serial": getattr(z, "last_serial", 0),
            # Forward-zone-only fields (ignored by the agent for other types).
            "forwarders": list(getattr(z, "forwarders", []) or []),
            "forward_only": bool(getattr(z, "forward_only", True)),
            # Secondary / stub primaries (issue #336). The agent renders these
            # as ``masters { <ip> [port <n>]; … };`` for slave/stub zones;
            # ignored for primary / forward.
            "masters": list(getattr(z, "masters", []) or []),
            # DNSSEC inline-signing (issue #49). policy_name None ⇒ BIND
            # built-in "default".
            "dnssec_enabled": bool(getattr(z, "dnssec_enabled", False)),
            "dnssec_policy_name": _zone_policy_name(z),
            # Dynamic-update ACL (issue #641). Flows into the structural
            # etag below (zones_structural derives from zone_payload), so
            # flipping the flag or editing an ACL row shifts the etag and
            # wakes the long-poll → a full, allow-update-correct re-render.
            "dynamic_update_enabled": bool(getattr(z, "dynamic_update_enabled", False)),
            "update_acl": update_acls_by_zone.get(z.id, []),
            # #734 — per-zone transfer override. Settable and persisted since
            # the column landed, but never shipped, so the agent could not
            # have rendered it even in principle. None (the common case)
            # means "inherit the server-level allow_transfer"; the agent
            # emits a zone-level clause only for a non-None value, because in
            # BIND a zone-level allow-transfer shadows the options one.
            "allow_transfer": getattr(z, "allow_transfer", None),
        }
        # Ship records to every server in the group. The is_primary flag
        # historically gated this, but agents need records to render zone
        # files for serving — primary/secondary distinction matters for
        # accepting RFC 2136 updates, not for which server gets the data.
        rec_rows: list[Any] = records_by_zone.get(z.id, [])

        if not has_views:
            # Flat render — one zone copy, all records, no view (today's path).
            zone_payload.append(
                {
                    **base_zp,
                    "view_name": None,
                    "records": [_rec_dict(r) for r in rec_rows],
                }
            )
            continue

        # Split-horizon expansion (issue #24) composed with geo steering
        # (issue #530). Operator views: the zone materialises in every
        # view it has content for — each view referenced by a scoped
        # record PLUS the zone's own pinned ``view_id``; with no explicit
        # scoping it's "global" and renders into every operator view.
        # Geo + catch-all views always render the zone (like a global
        # zone) so the catch-all serves the default member set. Per-view
        # record filtering is delegated to ``records_for_view``.
        record_view_ids = {r.view_id for r in rec_rows if r.view_id is not None}
        zone_view_ids = {z.view_id} if z.view_id is not None else set()
        operator_target_ids = record_view_ids | zone_view_ids
        for vd in view_descs:
            if (
                vd["kind"] == "operator"
                and operator_target_ids
                and vd["id"] not in operator_target_ids
            ):
                continue
            recs = records_for_view(rec_rows, vd, geo)
            zone_payload.append(
                {
                    **base_zp,
                    "view_name": vd["name"],
                    "records": [_rec_dict(r) for r in recs],
                }
            )

    # The ops page is not part of the body — see ``page_pending_ops`` /
    # ``retire_queued_ops`` below (#1111).

    # Group-level TSIG key for RFC 2136 dynamic updates
    grp = await db.get(DNSServerGroup, server.group_id)
    tsig_keys: list[dict[str, Any]] = []
    if grp and grp.tsig_key_name and grp.tsig_key_secret:
        tsig_keys.append(
            {
                "name": grp.tsig_key_name,
                "secret": grp.tsig_key_secret,
                "algorithm": grp.tsig_key_algorithm,
            }
        )

    # Operator-managed named TSIG keys (DNSTSIGKey rows). These are for
    # external nsupdate clients / AXFR auth — distinct from the legacy
    # auto-generated single key on DNSServerGroup. Both kinds end up in
    # the same `key { … };` block via the named.conf template.
    #
    # Ordered by name (#734): the agent takes ``tsig_keys[0]`` as the
    # loopback identity, and ``resolve_group_transfer_key`` reproduces this
    # same ordering to decide what to sign a transfer with. Unordered, the
    # head of the list was whatever the planner returned, so two agents in
    # one group could render different configs from the same bundle.
    op_keys = (
        (
            await db.execute(
                select(DNSTSIGKey)
                .where(DNSTSIGKey.group_id == server.group_id)
                .order_by(DNSTSIGKey.name)
            )
        )
        .scalars()
        .all()
    )
    for k in op_keys:
        try:
            secret = decrypt_str(k.secret_encrypted)
        except ValueError:
            # Decryption failure (e.g. key rotated since this row was written).
            # Skip rather than write a broken key block — agent reload would
            # otherwise fail. Operator visibility is via the audit log.
            continue
        tsig_keys.append({"name": k.name, "secret": secret, "algorithm": k.algorithm})

    # The DNS group's ``is_recursive=False`` is the high-level authoritative-only
    # intent (§4.9 DNS safety); it MUST force ``recursion no;`` regardless of the
    # per-group server options. Previously only ``DNSServerOptions.recursion_enabled``
    # (default True) drove the render, so a group created with ``is_recursive=False``
    # silently stayed an open recursive resolver (perf #454). AND the two so the
    # group flag can only ever tighten, never loosen, recursion.
    group_is_recursive = bool(getattr(grp, "is_recursive", True)) if grp else True
    opts_recursion_enabled = getattr(opts, "recursion_enabled", True) if opts else True
    options_block = {
        "forwarders": getattr(opts, "forwarders", []) if opts else [],
        "forward_policy": getattr(opts, "forward_policy", "first") if opts else "first",
        "recursion_enabled": opts_recursion_enabled and group_is_recursive,
        "dnssec_validation": (getattr(opts, "dnssec_validation", "auto") if opts else "auto"),
        "allow_query": getattr(opts, "allow_query", ["any"]) if opts else ["any"],
        "allow_transfer": (getattr(opts, "allow_transfer", ["none"]) if opts else ["none"]),
        # Query logging — surfaced to BIND9's named.conf via template
        # render and to PowerDNS's pdns.conf via the agent's
        # ``_render_conf``. Keep ``query_log_enabled`` in the
        # structural fingerprint so toggling it in the UI reliably
        # triggers a daemon reload.
        "query_log_enabled": (bool(getattr(opts, "query_log_enabled", False)) if opts else False),
        # Response logging (#914) — same reasoning: it changes the rendered
        # named.conf, so it belongs in the fingerprint or a UI toggle would
        # not shift the etag and the agent would never re-render.
        "response_log_enabled": (
            bool(getattr(opts, "response_log_enabled", False)) if opts else False
        ),
        # Response Rate Limiting + amplification defenses (issue #146). These
        # ride the same options dict → bundle etag, so a UI change wakes the
        # long-poll and reliably re-renders named.conf.
        "rrl_enabled": (bool(getattr(opts, "rrl_enabled", False)) if opts else False),
        "rrl_responses_per_second": (
            int(getattr(opts, "rrl_responses_per_second", 15)) if opts else 15
        ),
        "rrl_window": int(getattr(opts, "rrl_window", 15)) if opts else 15,
        "rrl_slip": int(getattr(opts, "rrl_slip", 2)) if opts else 2,
        "rrl_qps_scale": getattr(opts, "rrl_qps_scale", None) if opts else None,
        "rrl_exempt_clients": (list(getattr(opts, "rrl_exempt_clients", []) or []) if opts else []),
        "rrl_log_only": (bool(getattr(opts, "rrl_log_only", False)) if opts else False),
        "minimal_responses": (bool(getattr(opts, "minimal_responses", False)) if opts else False),
        "tcp_clients": getattr(opts, "tcp_clients", None) if opts else None,
        "clients_per_query": getattr(opts, "clients_per_query", None) if opts else None,
        "max_clients_per_query": (getattr(opts, "max_clients_per_query", None) if opts else None),
        # dnsdist front for PowerDNS (issue #146 Phase 2). The PowerDNS agent
        # renders dnsdist.conf from these; the sidecar watches + reloads it.
        "dnsdist_enabled": (bool(getattr(opts, "dnsdist_enabled", False)) if opts else False),
        "dnsdist_max_qps_per_client": (
            getattr(opts, "dnsdist_max_qps_per_client", None) if opts else None
        ),
        "dnsdist_action": (getattr(opts, "dnsdist_action", "truncate") if opts else "truncate"),
        "dnsdist_dynblock_qps": (getattr(opts, "dnsdist_dynblock_qps", None) if opts else None),
        "dnsdist_dynblock_seconds": (
            int(getattr(opts, "dnsdist_dynblock_seconds", 60)) if opts else 60
        ),
        # Encrypted transports (issue #50). The listener flags below are the
        # operator's *intent*; the renderer additionally requires cert
        # material to actually be present (see ``tls_cert``) before it emits
        # a listener, so a deleted cert degrades to Do53-only rather than to
        # a daemon that won't start.
        "dot_enabled": (bool(getattr(opts, "dot_enabled", False)) if opts else False),
        "dot_port": int(getattr(opts, "dot_port", 853)) if opts else 853,
        "doh_enabled": (bool(getattr(opts, "doh_enabled", False)) if opts else False),
        "doh_port": int(getattr(opts, "doh_port", 443)) if opts else 443,
        "doh_path": (getattr(opts, "doh_path", "/dns-query") if opts else "/dns-query"),
        # DoQ (#741) — Technitium-only, and UDP where DoT/DoH are TCP.
        "doq_enabled": (bool(getattr(opts, "doq_enabled", False)) if opts else False),
        "doq_port": int(getattr(opts, "doq_port", 853)) if opts else 853,
        "forward_transport": (getattr(opts, "forward_transport", "do53") if opts else "do53"),
        "forward_tls_hostname": (getattr(opts, "forward_tls_hostname", None) if opts else None),
        "forward_tls_verify": (bool(getattr(opts, "forward_tls_verify", True)) if opts else True),
    }
    # Built from the unified descriptor list so operator split-horizon
    # views (issue #24), synthesized geo views + the geo catch-all
    # (issue #530) all render. Already ordered low→high so the rendered
    # view blocks honour BIND's first-match-wins precedence.
    # #430 — per-view query ACL overrides (allow_query / allow_query_cache).
    # None → inherit server-options allow-query (renderer omits the line).
    views_block = [
        {
            "id": str(vd["id"]) if vd["id"] is not None else None,
            "name": vd["name"],
            "match_clients": list(vd["match_clients"]) or ["any"],
            "match_destinations": list(vd["match_destinations"]),
            "recursion": vd["recursion"],
            "order": vd["order"],
            "allow_query": vd["allow_query"],
            "allow_query_cache": vd["allow_query_cache"],
        }
        for vd in view_descs
    ]
    # #899 — ship the entries, not just the name. The agent renders these
    # into ``acl "<name>" { … };`` stanzas; before this the block carried
    # ``{id, name}`` only, so an ACL was inert config and any reference to
    # one was an undefined symbol that failed the entire bundle.
    acls_block = _safe_acls_block(acls)

    # Blocklists: one RPZ zone per view (if any) + one group-level zone.
    # Each assembled list has its entries resolved against view/group scope
    # with exceptions already applied by `build_effective_for_{view,group}`.
    def _entries_payload(eff_entries: list[Any]) -> list[dict[str, Any]]:
        return [
            {
                "domain": e.domain,
                "action": e.action,
                "block_mode": e.block_mode,
                "target": e.target,
                "is_wildcard": e.is_wildcard,
            }
            for e in eff_entries
        ]

    # ── Catalog zones (RFC 9432) ──
    # When the group has the feature toggled on, build a producer or
    # consumer block depending on whether this server is the primary
    # (is_primary=True). Both BIND9 and PowerDNS (Phase 3d) consume
    # the same producer payload — the catalog zone format is RFC 9432
    # canonical, so the rendering driver doesn't need to fork.
    catalog_block: dict[str, Any] | None = None
    if (
        grp
        and grp.catalog_zones_enabled
        and server.driver
        in (
            "bind9",
            "powerdns",
            "technitium",
        )
    ):
        producer = (
            await db.execute(
                select(DNSServer)
                .where(
                    DNSServer.group_id == server.group_id,
                    DNSServer.driver == server.driver,
                    DNSServer.is_primary.is_(True),
                )
                # ``.limit(1)`` is load-bearing, not tidiness: without it a
                # group that somehow holds two primaries raises
                # MultipleResultsFound from ``scalar_one_or_none`` — INSIDE
                # the agent long-poll, so the failure is a 500 that stops the
                # whole group converging rather than a mis-picked producer.
                # Ordered so the pick is at least deterministic if it happens.
                # Every other primary lookup in the codebase already caps at 1.
                .order_by(DNSServer.created_at, DNSServer.id)
                .limit(1)
            )
        ).scalar_one_or_none()

        if producer is not None:
            # Members are every primary zone in the group. Forward / stub
            # zones don't belong in a catalog (they're lookups, not
            # served data); secondaries are the consumer's responsibility.
            member_names = sorted(z.name for z in zones if z.zone_type in ("primary", "master"))
            if server.id == producer.id:
                catalog_block = {
                    "mode": "producer",
                    "zone_name": grp.catalog_zone_name,
                    "members": [{"zone_name": n} for n in member_names],
                }
            else:
                catalog_block = {
                    "mode": "consumer",
                    "zone_name": grp.catalog_zone_name,
                    "producer_addr": producer.host,
                }

    blocklists_payload: list[dict[str, Any]] = []
    if views:
        for v in views:
            eff_v = await build_effective_for_view(db, v.id)
            if eff_v.entries:
                blocklists_payload.append(
                    {
                        "rpz_zone_name": f"spatium-blocklist-{v.name}.rpz.",
                        "entries": _entries_payload(eff_v.entries),
                        "exceptions": sorted(eff_v.exceptions),
                        # Issue #24 — when views exist, RPZ zones + the
                        # response-policy directive must live INSIDE the
                        # owning view block, not at global options scope.
                        "view_name": v.name,
                    }
                )
    eff_g = await build_effective_for_group(db, server.group_id)
    if eff_g.entries:
        blocklists_payload.append(
            {
                "rpz_zone_name": "spatium-blocklist.rpz.",
                "entries": _entries_payload(eff_g.entries),
                "exceptions": sorted(eff_g.exceptions),
                # Group-level blocklist. With views, it applies to EVERY
                # view (rendered into each); with no views it's the single
                # global RPZ as before. ``view_name=None`` marks it global.
                "view_name": None,
            }
        )

    # Phase 8f-3 — fleet upgrade intent. Only set when the operator
    # stamped a desired_appliance_version on this server row from the
    # Fleet view; the agent's existing long-poll picks it up on the
    # next ETag change and fires the local slot-upgrade trigger if
    # its installed version doesn't match. Always-present key (None
    # values when nothing pending) keeps the etag stable when the
    # operator clears intent on a healthy upgrade.
    fleet_upgrade_block: dict[str, Any] = {
        "desired_appliance_version": server.desired_appliance_version,
        "desired_slot_image_url": server.desired_slot_image_url,
        # Phase 8f-8 — operator-triggered reboot. Agent fires the
        # ``reboot-pending`` trigger file when this flips to True; the
        # heartbeat handler clears it once the agent reconnects post-
        # reboot.
        "reboot_requested": server.reboot_requested,
    }

    # Issue #153 — appliance SNMP. Singleton platform_settings drives
    # snmpd.conf on every fleet host; agent compares the bundle's
    # ``config_hash`` against its last-rendered hash and writes the
    # snmp-reload trigger when they differ. Always-present key keeps
    # the etag stable while SNMP stays disabled.
    settings_row = await db.get(PlatformSettings, 1)
    snmp_block: dict[str, Any] = (
        snmp_bundle(settings_row)
        if settings_row is not None
        else {"enabled": False, "config_hash": "", "snmpd_conf": ""}
    )
    # Issue #154 — appliance NTP. Same shape as SNMP. chrony is
    # always running on the appliance (default pool config seeded
    # by cloud-init), so the agent always has a config_hash to
    # compare against. The fields default to ``pool pool.ntp.org``
    # so a fresh install produces the same bytes the baseline
    # chrony.conf shipped — agent stamps the hash sidecar on first
    # apply and stays idempotent thereafter.
    ntp_block: dict[str, Any] = (
        ntp_bundle(settings_row)
        if settings_row is not None
        else {
            "enabled": False,
            "allow_clients": False,
            "config_hash": "",
            "chrony_conf": "",
        }
    )

    # Ship only the custom policies referenced by a signed zone (the agent
    # renders one ``dnssec-policy { ... }`` block per entry; "default" is
    # BIND's own and needs none).
    _referenced_policy_names = {
        _zone_policy_name(z) for z in zones if getattr(z, "dnssec_enabled", False)
    }
    dnssec_policies_block = [
        {
            "name": p.name,
            "algorithm": p.algorithm,
            "ksk_lifetime_days": p.ksk_lifetime_days,
            "zsk_lifetime_days": p.zsk_lifetime_days,
            "nsec3": p.nsec3,
            "nsec3_iterations": p.nsec3_iterations,
            "nsec3_salt_length": p.nsec3_salt_length,
            "nsec3_optout": p.nsec3_optout,
        }
        for p in dnssec_policy_rows
        if p.name != "default" and p.name in _referenced_policy_names
    ]

    # TLS cert material for the DoT / DoH listeners (issue #50). Loaded only
    # when a listener is actually on, so a group that never enabled encrypted
    # transports keeps a cert-free bundle (and an unchanged etag) even if an
    # operator later points ``tls_certificate_id`` at something.
    #
    # The PEM + key ride inside the bundle body — same trust model as the
    # TSIG secrets already shipped above — and land in the structural
    # fingerprint below so a cert ROTATION shifts the etag and the long-poll
    # actually delivers the new material. Without that, a renewed cert would
    # sit in the DB while the agent kept serving the expired one.
    #
    # ``populate_existing=True`` is load-bearing, not a style choice: the
    # long-poll holds ONE session across its whole wait and re-builds the
    # bundle on every wake, and the sessionmaker sets expire_on_commit=False.
    # A plain ``db.get()`` would hand back the identity-mapped instance with
    # the pre-renewal PEM and emit no SQL, so the etag wouldn't move and the
    # rotation wake would buy nothing.
    tls_cert_block: dict[str, Any] | None = None
    if (
        opts is not None
        and (opts.dot_enabled or opts.doh_enabled or opts.doq_enabled)
        and opts.tls_certificate_id
    ):
        cert_row = (
            await db.execute(
                select(ApplianceCertificate)
                .where(ApplianceCertificate.id == opts.tls_certificate_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        # cert_pem IS NULL is the canonical "CSR pending" sentinel — the
        # operator generated a CSR but hasn't pasted the signed cert back
        # yet, so there is nothing to serve.
        if cert_row is not None and cert_row.cert_pem:
            try:
                key_pem = decrypt_str(cert_row.key_encrypted)
            except ValueError:
                # Same posture as the TSIG loop above: skip rather than ship
                # a half-populated block the agent would render into an
                # unloadable ``tls`` statement. Operator visibility is via
                # the cert page (the row still lists) + agent logs.
                key_pem = ""
            if key_pem:
                tls_cert_block = {
                    "name": cert_row.name,
                    "cert_pem": cert_row.cert_pem,
                    "key_pem": key_pem,
                    "fingerprint_sha256": cert_row.fingerprint_sha256,
                }

    bundle_body: dict[str, Any] = {
        "server_id": str(server.id),
        "driver": server.driver,
        "options": options_block,
        "views": views_block,
        "acls": acls_block,
        "zones": zone_payload,
        "tsig_keys": tsig_keys,
        "forwarders": options_block["forwarders"],
        "blocklists": blocklists_payload,
        "catalog": catalog_block,
        "fleet_upgrade": fleet_upgrade_block,
        "snmp_settings": snmp_block,
        "ntp_settings": ntp_block,
        "dnssec_policies": dnssec_policies_block,
        "tls_cert": tls_cert_block,
    }

    # Structural fingerprint excludes records and pending ops so record-only
    # changes don't trigger a full daemon reload — agent applies them via
    # RFC 2136 over loopback instead. Agent compares this to its cached value
    # and only re-renders config when it changes.
    structural = {
        "options": options_block,
        "views": views_block,
        "acls": acls_block,
        "tsig_keys": tsig_keys,
        # Records are normally excluded so a record-only change rides the
        # incremental RFC 2136 path without a full reload. But under
        # split-horizon (issue #24) the incremental path can't target a
        # view, so records are folded in here — any record/view change then
        # shifts the structural etag and triggers a full, view-correct
        # re-render. ``view_name`` is always retained either way.
        "zones_structural": [
            {k: val for k, val in z.items() if (k != "records" or has_views)} for z in zone_payload
        ],
        # DNSSEC signing intent / policy params rewrite named.conf, so a
        # change must trigger a full reload (issue #49).
        "dnssec_policies": dnssec_policies_block,
        # Blocklists affect named.conf (response-policy block) + RPZ zone
        # files, so a change MUST trigger a daemon reload.
        "blocklists": blocklists_payload,
        # Catalog membership / mode changes also rewrite named.conf and
        # the catalog zone file, so they belong in the structural set.
        "catalog": catalog_block,
        # A cert rotation rewrites the on-disk PEM the ``tls`` statement
        # points at; named only picks that up on reload, so the cert MUST
        # be structural (issue #50).
        "tls_cert": tls_cert_block,
    }
    structural_etag = _compute_etag(structural)
    bundle_body["structural_etag"] = structural_etag

    # The canonical payload the inline build always hashed had the ops keys
    # present (and, with nothing pending, empty). Hashing that shape keeps a
    # stored bundle's ETag identical to the pre-#1111 ETag for the same
    # state whenever nothing is pending.
    etag = _compute_etag({**bundle_body, "pending_record_ops": [], "pending_ops_remaining": 0})
    records = sum(len(z["records"]) for z in zone_payload)
    return RenderedBody(
        body=bundle_body,
        etag=etag,
        structural_etag=structural_etag,
        records=records,
        has_views=has_views,
    )


class _XID8(UserDefinedType[Any]):
    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "xid8"


class _PGSnapshot(UserDefinedType[Any]):
    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "pg_snapshot"


def _covered_by(up_to: datetime | None, visible_xacts: str | None) -> Any | None:
    """The condition for "a body rendered at this snapshot reflects this op".

    ``visible_xacts`` is the ``pg_current_snapshot()`` the render took before
    it read anything (``agent_bundle_render``): an op whose transaction is
    visible in it had committed before the render's records query began,
    and under READ COMMITTED that query's own, later snapshot sees at least
    as much, so the body carries the op's record. ``created_at`` cannot say
    that: it is ``now()``, the op's transaction START, and a bulk write that
    started before the render and committed after its records query passes
    ``created_at <= snapshot_at`` with records the body never read.

    An op queued before ``dns_record_op.xact_id`` existed (NULL), and every op
    against a bundle rendered before ``visible_xacts`` existed, keep that time
    gate. So does any pair this cluster cannot compare: a transaction id or a
    snapshot it has not reached yet can only have come from another cluster
    (both tables are in the DNS backup section, and a restore onto a new
    appliance starts its transaction ids afresh), where the ids mean nothing
    here. ``None`` when neither bound is given (no gate).
    """
    if visible_xacts is None:
        return None if up_to is None else DNSRecordOp.created_at <= up_to
    xid = cast(cast(DNSRecordOp.xact_id, Text), _XID8())
    snapshot = cast(literal(visible_xacts, Text), _PGSnapshot())
    reached = func.pg_snapshot_xmax(func.pg_current_snapshot())
    comparable = and_(
        DNSRecordOp.xact_id.is_not(None),
        xid < reached,
        func.pg_snapshot_xmax(snapshot) <= reached,
    )
    visible = func.pg_visible_in_snapshot(xid, snapshot, type_=Boolean)
    by_time: Any = not_(comparable)
    if up_to is not None:
        by_time = and_(by_time, DNSRecordOp.created_at <= up_to)
    return or_(and_(comparable, visible), by_time)


async def retire_queued_ops(
    db: AsyncSession,
    server: DNSServer,
    *,
    up_to: datetime | None = None,
    visible_xacts: str | None = None,
) -> int:
    """Split-horizon: retire this server's queued ops as ``applied``.

    The incremental RFC 2136 path can't target a specific view (an nsupdate
    to loopback lands in whichever view matches 127.0.0.1, not necessarily
    the record's view), so under views records are folded into the
    structural fingerprint and every record change triggers a full,
    view-correct re-render. The bundle the agent is about to render already
    reflects the queued ops, so they are retired rather than left to pile
    up in ``pending``. A sibling view's op the sweep would otherwise leave
    behind is covered by ``record_ops.sweep_zone_ops``.

    #1111 — only the ops the render's snapshot covers are retired
    (``_covered_by``: committed before the render read), so an op whose
    transaction was still open when the render read is never marked applied
    by a body that did not see its record. That was reachable by time alone:
    a bulk write that started before the render and committed after its
    records query had ``created_at`` inside the window, and its ops were
    retired unseen — and an ACME DNS-01 wait read them as applied.
    """
    conds: list[Any] = [
        DNSRecordOp.server_id == server.id,
        DNSRecordOp.state.in_(QUEUED_OP_STATES),
    ]
    covered = _covered_by(up_to, visible_xacts)
    if covered is not None:
        conds.append(covered)
    stale_ops = (await db.execute(select(DNSRecordOp).where(*conds))).scalars().all()
    for op in stale_ops:
        op.state = "applied"
    if stale_ops:
        await db.flush()
    return len(stale_ops)


async def page_pending_ops(
    db: AsyncSession,
    server: DNSServer,
    *,
    up_to: datetime | None = None,
    visible_xacts: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """One PAGE of this server's pending ops, oldest first, marked ``in_flight``.

    Every agent-based server in the group gets its own queue (one op row per
    server per record change, see ``record_ops.enqueue_record_op``). The
    ``is_primary`` gate here was a pre-#170 carryover from the "primary
    writes, secondaries AXFR" assumption that doesn't match the
    per-server-authoritative shape every supervised appliance uses today;
    with the gate in place a secondary's ops sat in ``state=pending``
    forever. Marked ``in_flight`` on dispatch so the same op doesn't re-ship
    on every long-poll cycle until the agent's next heartbeat acks it; a
    failure ack resets it to pending (attempt++), and after 5 failures it
    becomes ``failed`` and stays out.

    One PAGE of the queue, never the whole backlog: the agent applies a page
    and acks it on its next heartbeat; the page it was shipped is
    ``in_flight`` meanwhile, so the next long-poll (which returns
    immediately while ops are pending) ships the next page. Unbounded, a
    bulk seed's backlog — 500k ops for 250k A+PTR records on one server —
    was materialised whole into every response and the api was memcg-killed
    on each poll (appliance sizing campaign, 2026-09-02/03). The second
    value is how deep the backlog still is beyond this page.

    Issue #182: nothing ships while the server is in operator-set
    maintenance mode; ops accumulate in ``pending`` and ship on resume.

    #1111 — the page is gated to the ops the stored bundle's snapshot
    covers (``_covered_by``: committed before its render read; ``up_to`` /
    ``visible_xacts`` are the bundle's ``snapshot_at`` / ``visible_xacts``).
    Every body an agent holds must be a superset of every op it has applied,
    or a later structural re-render (or a restart replaying the cached
    bundle) drops a record the agent already applied incrementally; the
    inline build had that by construction because the body was built
    moments before the page, and this is what keeps it once the body is
    rendered asynchronously. An op the snapshot does not cover rides with
    the next render — whose dirty mark its own commit already made.
    """
    if server.maintenance_mode:
        return [], 0
    batch = max(1, int(settings.dns_agent_ops_batch))
    conds: list[Any] = [DNSRecordOp.server_id == server.id, DNSRecordOp.state == "pending"]
    covered = _covered_by(up_to, visible_xacts)
    if covered is not None:
        conds.append(covered)
    op_res = await db.execute(
        select(DNSRecordOp)
        .where(*conds)
        .order_by(DNSRecordOp.created_at, DNSRecordOp.id)
        .limit(batch)
    )
    ops_to_dispatch = list(op_res.scalars().all())
    remaining = 0
    if len(ops_to_dispatch) == batch:
        remaining = int((await db.execute(select(func.count()).where(*conds))).scalar_one()) - len(
            ops_to_dispatch
        )
    page: list[dict[str, Any]] = []
    for op in ops_to_dispatch:
        page.append(
            {
                "op_id": str(op.id),
                "zone_name": op.zone_name,
                "op": op.op,
                "record": op.record,
                "target_serial": op.target_serial,
            }
        )
        op.state = "in_flight"
    if ops_to_dispatch:
        await db.flush()
    return page, remaining


def compose_bundle(
    rendered: RenderedBody, ops: list[dict[str, Any]], remaining: int
) -> ConfigBundle:
    """The whole bundle dict, ops page included, in the pre-#1111 shape.

    The ETag covers the composed payload exactly as it always did; with
    nothing pending that is ``rendered.etag`` already (same canonical
    payload), so the second walk is skipped in the common case.
    """
    body: dict[str, Any] = {
        **rendered.body,
        "pending_record_ops": ops,
        "pending_ops_remaining": remaining,
    }
    etag = rendered.etag if not ops and not remaining else _compute_etag(body)
    bundle: ConfigBundle = {"etag": etag, **body}  # type: ignore[misc]
    return bundle


async def build_config_bundle(db: AsyncSession, server: DNSServer) -> ConfigBundle:
    """Build the whole config bundle for a given server from DB state.

    Render the body, then — exactly as before — either retire the queued
    ops (split-horizon) or ship one page of them, and compose. Callers that
    serve agents go through the stored bundle instead (#1111); this stays
    for everything that wants the dict in one call.
    """
    rendered = await render_bundle_body(db, server)
    ops: list[dict[str, Any]] = []
    remaining = 0
    if server.maintenance_mode:
        pass
    elif rendered.has_views:
        await retire_queued_ops(db, server)
    else:
        ops, remaining = await page_pending_ops(db, server)
    return compose_bundle(rendered, ops, remaining)
