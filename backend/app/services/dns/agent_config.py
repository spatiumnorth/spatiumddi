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
import secrets
import tempfile
from collections.abc import AsyncGenerator, Callable, Sequence
from contextlib import aclosing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypedDict

import structlog
from sqlalchemy import Boolean, Text, and_, cast, func, literal, not_, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.types import UserDefinedType

from app.config import settings
from app.core.crypto import decrypt_str
from app.drivers.dns.base import TsigKey
from app.models.appliance import ApplianceCertificate
from app.models.dns import (
    DEFAULT_ALLOW_QUERY_CACHE,
    DEFAULT_ALLOW_RECURSION,
    ZONE_DEFAULT_TTL,
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
    servable_ttl,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ntp import ntp_bundle
from app.services.appliance.snmp import snmp_bundle
from app.services.dns.agent_bundle_store import WIRE_JSON, BodyWriter
from app.services.dns.named_conf_validation import (
    ADDRESS_MATCH_LIST_OPTIONS,
    UPDATE_POLICY_NAMED_SCOPES,
    AclCycleError,
    ViewValidationError,
    bind9_refused_prefix,
    is_name_reference,
    key_reference,
    order_acls_for_render,
    split_zone_forwarders,
    validate_acl_name,
    validate_address_match_list,
    validate_update_acl_entry,
)
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    records_for_view,
    views_rendering_zone,
)
from app.services.dns.powerdns_alias import alias_resolver
from app.services.dns.record_ops import (
    QUEUED_OP_STATES,
    RRSET_KEY_CHUNK,
    backed_off_match_where,
    mark_ops_applied,
    op_rrset_key,
    queued_after,
    supersede,
)
from app.services.dns.row_locks import ids_in, lock_ops
from app.services.dns.rrset import RRSET_OPS
from app.services.dns.soa_timers import served_soa_timers
from app.services.dns.tsig import (
    dedupe_tsig_keys,
    legacy_group_key,
    resolve_group_transfer_key,
    transfer_needs_tsig,
    tsig_secret_shape_problem,
    view_transfer_key,
)
from app.services.dns_blocklist import (
    build_effective_for_group,
    build_effective_for_view,
    effective_lists_for_group,
    effective_lists_for_view,
    exception_domains,
    has_entries,
    stream_entries,
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

# The zone-payload keys a record change moves: kept out of the structural
# fingerprint of a group without views, so a record-only change reaches the
# agent as RFC 2136 ops, not as a re-render (#1373). See ``zones_structural``.
_RECORD_DRIVEN_KEYS = frozenset({"records", "serial"})

# #1513 — the key, and its one value, by which a Technitium bundle says a
# dot-less SVCB / HTTPS target is zone-relative. The agent's
# ``drivers/technitium.py`` reads the same two literals; without the key it
# reads a dot-less target as absolute, which is what the renderer before
# #1513 meant.
SVCB_TARGET_RULE_KEY = "svcb_target_rule"
SVCB_TARGET_RULE_ZONE_FILE = "zone-file"

# #1759 — the same statement for every OTHER name-valued target (CNAME,
# DNAME, NS, PTR, MX exchange, SRV target, NAPTR replacement). A separate key,
# not a rename of the SVCB one: a bundle a #1513 control plane stored carries
# ``svcb_target_rule`` and not this, and the agent must keep reading that
# bundle's CNAME targets as absolute, as they were rendered. Without the key
# a dot-less target is absolute.
NAME_TARGET_RULE_KEY = "name_target_rule"
NAME_TARGET_RULE_ZONE_FILE = "zone-file"


#: How an ETag's payload is serialised before it is hashed. The streamed
#: render (#1662) hashes each batch of blocklist entries with these too.
_ETAG_JSON: dict[str, Any] = {"sort_keys": True, "default": str}


def _compute_etag(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonicalized payload (sorted keys)."""
    blob = json.dumps(payload, **_ETAG_JSON).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


#: The key under which a BIND9 bundle carries each RPZ zone's content hash
#: (#2157). The agent re-serialises a zone's file only when this moves, and
#: otherwise hard-links the file it already serves, so an apply that touched
#: no blocklist writes no RPZ bytes. Kept out of every other driver's bundle:
#: nothing there reads it, and it would move their ETags for nothing.
#:
#: The name is load-bearing for the streamed render: sorted, it lands after
#: ``entries`` (and ``exceptions``) in the zone's dict, and it is inserted
#: after ``entries`` in the unsorted wire body too, so in all three documents
#: its placeholder comes after the entries it hashes have been streamed.
RPZ_CONTENT_HASH_KEY = "rpz_sha256"


def _rpz_hasher(rpz_zone_name: str, exceptions: list[str]) -> Any:
    """A SHA-256 primed with everything about an RPZ zone but its entries.

    The entries follow as ``json.dumps(entries, **_ETAG_JSON)`` — whole, or a
    batch at a time by the streamed render, which joins to the same bytes —
    so both renders produce the same hash for the same state. Entries and
    exceptions are all the agent's RPZ renderer reads from the zone's dict
    (``block_mode`` and the wildcard flag ride on each entry), and the zone
    name is folded in so two zones can never share a hash.
    """
    h = hashlib.sha256()
    h.update(
        json.dumps({"exceptions": exceptions, "rpz_zone_name": rpz_zone_name}, **_ETAG_JSON).encode(
            "utf-8"
        )
    )
    h.update(b"\n")
    return h


def _rpz_hash_value(hasher: Any) -> str:
    return "sha256:" + hasher.hexdigest()


def _entry_dict(
    domain: str,
    action: str,
    block_mode: str,
    target: str | None,
    is_wildcard: bool,
    sinkhole_ip: str | None = None,
) -> dict[str, Any]:
    """One blocklist entry as the bundle ships it.

    ``sinkhole_ip`` rides only on a ``sinkhole`` entry whose list names an
    address (#2124) — the agent never received it, so every sinkhole list
    rendered as ``rpz-drop``. Leaving the key off everywhere else keeps the
    bundle of a list that does not sinkhole byte-identical, ETag included,
    and costs nothing on the ~600k-entry feeds the bundle is sized for.
    """
    out: dict[str, Any] = {
        "domain": domain,
        "action": action,
        "block_mode": block_mode,
        "target": target,
        "is_wildcard": is_wildcard,
    }
    if block_mode == "sinkhole" and sinkhole_ip:
        out["sinkhole_ip"] = sinkhole_ip
    return out


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
                # Syntax only: whether a bare name actually resolves is
                # decided by the known-set sweep below, and whether a prefix
                # BIND 9 refuses renders by the server's driver (#2695,
                # ``_drop_undefined_key_refs``).
                validate_address_match_list(
                    [e.value],
                    field="entries",
                    allow_unknown_names=True,
                    allow_bind9_refused_prefixes=True,
                )
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


def _key_name_norm(name: str) -> str:
    """A TSIG key name as BIND compares it: a DNS name, so case-insensitive
    and absolute (``Foo`` / ``foo.`` are one key)."""
    return name.rstrip(".").lower()


def _drop_undefined_key_refs(
    elements: Any,
    known_keys: frozenset[str],
    *,
    where: str,
    known_acls: frozenset[str] | None = None,
    deny_if_emptied: bool = False,
    drop_bind9_refused_prefixes: bool = False,
) -> Any:
    """``elements`` without any citation the bundle does not define (#2282, #2283).

    Covers ``key <name>`` (``key_reference`` also reads ``also-notify``'s
    ``<ip> key <name>``) and, when ``known_acls`` is given, a bare ACL name.
    A citation of an undefined name is an undefined symbol: ``named-checkconf``
    rejects the file and the agent declines the whole bundle. The write paths
    refuse to create or orphan one (rename / delete of a cited key or ACL is a
    409), so this covers a row stored before that guard, or an operator key
    whose secret no longer decrypts and was therefore left out of ``tsig_keys``.
    ``known_keys`` holds :func:`_key_name_norm` forms; ``known_acls`` holds ACL
    names verbatim (BIND ACL names are case-sensitive). Returns the original
    object untouched when nothing is dropped, so a healthy bundle keeps its
    ETag.

    Dropping must never widen access. Every renderer reads an empty
    address-match list as "unset" and falls back to something wider: the
    BIND9 agent renders an empty ``match-clients`` / options ``allow-query``
    as ``any`` and omits an empty zone / view ``allow-query`` so it inherits
    the server's (often ``any``). So for an access list
    (``deny_if_emptied``) that ends up empty, ``["none"]`` is returned. A
    dropped *negated* element (``!key x`` / ``!name``) collapses the list to
    ``["none"]`` too — conservative for a key (an undefined key matches no
    request), but it keeps one rule for every dropped negation. ``none`` is
    never substituted in place (``["none", "10/8"]`` denies everyone).
    ``also-notify`` is not an access list and ``none`` is not legal there;
    ACL entries are not either, since an entry-less ACL already renders
    ``{ none; }``.

    ``drop_bind9_refused_prefixes`` (a BIND9 server's bundle, #2695) also
    drops a prefix BIND 9 refuses, one with host bits set (``10.0.0.5/24``)
    or a mask where the length goes (``10.0.0.0/255.255.255.0``), under the
    same rules. The API refuses both now, but a row saved before that may
    hold one, and BIND refuses the element, so shipping it would keep the
    whole group from loading new config. The Technitium and PowerDNS agents
    apply the prefix's network, so their bundles keep the value.
    """
    if not isinstance(elements, list):
        return elements
    kept = []
    widened = False
    for el in elements:
        text = str(el)
        name = key_reference(text)
        acl = is_name_reference(text) if known_acls is not None else None
        network = bind9_refused_prefix(text) if drop_bind9_refused_prefixes else None
        if name is not None and _key_name_norm(name) not in known_keys:
            logger.warning("dns_bundle_entry_dropped_undefined_key", where=where, key=name)
        elif acl is not None and known_acls is not None and acl not in known_acls:
            logger.warning("dns_bundle_entry_dropped_undefined_acl", where=where, acl=acl)
        elif network is not None:
            logger.warning(
                "dns_bundle_entry_dropped_bind9_refused_prefix",
                where=where,
                value=text,
                network=str(network),
            )
        else:
            kept.append(el)
            continue
        widened = widened or text.strip().startswith("!")
    if len(kept) == len(elements):
        return elements
    if deny_if_emptied and (widened or not kept):
        return ["none"]
    return kept


def _master_host(master: Any) -> str:
    """``ip``, ``ip@port`` or ``[v6]`` of a neutral ``masters`` entry -> host."""
    text = str(master or "").strip()
    if "@" in text:
        text = text.rpartition("@")[0]
    return text.strip("[]").lower()


async def _master_granted_keys(db: AsyncSession, group_id: Any) -> list[TsigKey]:
    """Every key a managed master in ``group_id`` grants transfer to, in the
    order the control plane would sign with (#734): the group's transfer key
    first, then the operator keys by name. The BIND9 agent grants every key in
    its bundle (``_transfer_key_grants``); a Technitium master pins the same set."""
    keys: list[TsigKey] = []
    first = await resolve_group_transfer_key(db, group_id)
    if first is not None:
        keys.append(first)
    for k in (
        (
            await db.execute(
                select(DNSTSIGKey).where(DNSTSIGKey.group_id == group_id).order_by(DNSTSIGKey.name)
            )
        )
        .scalars()
        .all()
    ):
        try:
            keys.append(
                TsigKey(name=k.name, algorithm=k.algorithm, secret=decrypt_str(k.secret_encrypted))
            )
        except ValueError:
            continue
    return keys


async def _add_master_transfer_keys(
    db: AsyncSession,
    zone_payload: list[dict[str, Any]],
    catalog_block: dict[str, Any] | None,
    tsig_keys: list[dict[str, Any]],
) -> None:
    """Name the TSIG key a Technitium secondary signs its transfers with (#1765).

    A SpatiumDDI primary grants transfer only to the keys of ITS group (#734),
    so a secondary has to sign with one of them. A master is recognised by
    address among the agent-managed servers (``transfer_needs_tsig``); one that
    is not (an operator's own BIND, authorised by source address) gets no key,
    because signing a request its master has never heard of turns a working
    unsigned transfer into NOTAUTH.

    **Only a key this server's own group already holds is ever named** —
    matched by name, algorithm AND secret against a key the master grants.
    No other group's secret enters this bundle. That rules out shipping the
    master group's own key: on a BIND9 master that key is also the
    unrestricted ``allow-update`` grant on every primary zone, so handing it
    to another group's daemon would hand over write access to the whole master
    group to anyone who can create a secondary zone here. A master in the SAME
    group signs with the group key, which both sides hold. A master in another
    group needs a key the operator placed in both groups (same name, algorithm
    and secret); without one the zone is marked ``masters_tsig_unresolved`` and
    the agent reports the transfer as one that will be refused, rather than
    creating a zone that silently expires.

    Sets ``masters_tsig_key`` (or ``masters_tsig_unresolved``) on each
    secondary zone and ``producer_tsig_key`` on a consumer catalog block.
    """
    secondaries = [
        zp
        for zp in zone_payload
        if str(zp.get("type") or "").lower() in ("secondary", "slave") and zp.get("masters")
    ]
    consumer = catalog_block if (catalog_block or {}).get("mode") == "consumer" else None
    if not secondaries and consumer is None:
        return
    managed = {
        _master_host(row.host): row
        for row in (
            await db.execute(select(DNSServer).where(DNSServer.agent_id.is_not(None)))
        ).scalars()
        if transfer_needs_tsig(row)
    }
    local = {k["name"].rstrip(".").lower(): k for k in tsig_keys}
    granted: dict[Any, list[TsigKey]] = {}

    async def key_for(masters: list[Any]) -> tuple[str | None, bool]:
        """``(key name, a managed master was found)``."""
        found = False
        for master in masters:
            row = managed.get(_master_host(master))
            if row is None:
                continue
            found = True
            if row.group_id not in granted:
                granted[row.group_id] = await _master_granted_keys(db, row.group_id)
            for key in granted[row.group_id]:
                have = local.get(key.name.rstrip(".").lower())
                if (
                    have is not None
                    and have.get("secret") == key.secret
                    and str(have.get("algorithm") or "hmac-sha256").lower()
                    == str(key.algorithm or "hmac-sha256").lower()
                ):
                    return str(have["name"]).rstrip("."), True
        return None, found

    for zp in secondaries:
        name, found = await key_for(list(zp["masters"]))
        if name:
            zp["masters_tsig_key"] = name
        elif found:
            logger.warning("dns_secondary_master_shares_no_tsig_key", zone=zp.get("name"))
            zp["masters_tsig_unresolved"] = True
    if consumer is not None and consumer.get("producer_addr"):
        name, _ = await key_for([consumer["producer_addr"]])
        if name:
            consumer["producer_tsig_key"] = name


def _safe_update_acl(zone_id: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A zone's dynamic-update ACL with every unrenderable entry removed (#1357).

    ``name_pattern`` and ``record_types`` reach the agent's ``update-policy``
    rule verbatim, and were unvalidated before #1357 — so, as with the named
    ACLs above, a row stored before that would make BIND refuse the whole
    group's config on the next render. Such an entry is left out, loudly.

    How it is left out depends on the action, because ``update-policy`` is
    first-match. Dropping a bad ``grant`` only ever removes permission.
    Dropping a bad ``deny`` would let the grants BELOW it match updates it
    was refusing, so a bad ``deny`` drops every entry after it as well: what
    remains is a prefix of the operator's policy, which can only grant less
    than the whole of it did.
    """
    kept: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if entry.get("match_kind") != "tsig_key" or not entry.get("tsig_key_name"):
            # Never reaches an ``update-policy`` rule (the agent skips it), so
            # its fields cannot break the config — and dropping a ``deny``
            # here would take every valid entry after it down for nothing.
            kept.append(entry)
            continue
        # The agent renders the name only for a scope that carries one; a
        # value left over on a ``zonesub`` entry is never written.
        scope = entry.get("name_scope")
        pattern = entry.get("name_pattern") if scope in UPDATE_POLICY_NAMED_SCOPES else None
        try:
            # Validity only: a renderable row ships as stored, so a bundle
            # that was fine before #1357 keeps its ETag.
            validate_update_acl_entry(scope, pattern, entry.get("record_types"))
        except ViewValidationError as exc:
            deny = entry.get("action") == "deny"
            logger.warning(
                "dns_update_acl_entry_dropped_unrenderable",
                zone_id=str(zone_id),
                action=entry.get("action"),
                field=exc.field,
                value=exc.value,
                error=str(exc),
                entries_after_dropped=(len(entries) - index - 1) if deny else 0,
            )
            if deny:
                break
            continue
        kept.append(entry)
    return kept


def _zone_ttl(zone: Any) -> int:
    """The zone's ``$TTL`` as shipped: the stored one, or ``ZONE_DEFAULT_TTL``
    when it is not servable (a negative one stored before #2073)."""
    ttl = servable_ttl(getattr(zone, "ttl", None))
    return ZONE_DEFAULT_TTL if ttl is None else ttl


def _safe_zone_forwarders(zone: Any) -> list[str]:
    """A BIND9 zone's forwarders with every unrenderable entry removed (#1357).

    The BIND9 agent renders them into ``forwarders { … };`` and they were
    unvalidated before #1357 (an import or an old row could carry a
    hostname). A bad entry is dropped, loudly, rather than making BIND refuse
    the whole group's config; a forward zone left with none is skipped by
    the agent, as it always has been.
    """
    kept, dropped = split_zone_forwarders(list(getattr(zone, "forwarders", []) or []))
    for value, error in dropped:
        logger.warning(
            "dns_zone_forwarder_dropped_unrenderable",
            zone=getattr(zone, "name", None),
            zone_id=str(getattr(zone, "id", "")),
            value=value,
            error=error,
        )
    return kept


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


@dataclass(frozen=True)
class EncodedBody:
    """``RenderedBody`` as the store keeps it (#1662): the body serialised
    (``agent_bundle_store.WIRE_JSON``) and gzipped (``compress_body``'s
    bytes), with its uncompressed length, instead of the dict."""

    body_gz: bytes
    body_bytes: int
    etag: str
    structural_etag: str
    records: int
    has_views: bool


#: Blocklist entries read, serialised and hashed per step of the streamed
#: render (#1662). What the render holds of a list is one batch, whatever the
#: list's length: ~1.5 KB per entry with its row and its text, so ~8 MB here.
BLOCKLIST_RENDER_BATCH = 5000


@dataclass(frozen=True)
class _StreamedEntries:
    """One RPZ zone whose entries the streamed render writes in itself: the
    zone's dict carries ``mark`` in place of its ``entries`` list, and (a
    BIND9 bundle, #2157) ``hash_mark`` in place of its content hash, which
    ``hasher`` accumulates as the entries stream past."""

    mark: str
    lists: list[Any]
    hash_mark: str | None = None
    hasher: Any = None


@dataclass(frozen=True)
class _StreamedZones:
    """The group's zones, left out of the assembled body and structural
    payload for ``encode_bundle_body`` to write in (#2227): ``mark`` stands in
    for the body's ``zones`` list, ``structural_mark`` for the structural
    payload's ``zones_structural``. ``base``, ``copies`` and ``record`` are the
    assembly's own zone and record builders, so a zone is built exactly as the
    whole render builds it; ``annotations`` are the keys a Technitium render
    appends to a zone's copies (``_add_master_transfer_keys``), by the zone's
    index."""

    mark: str
    structural_mark: str
    zones: list[Any]
    base: Callable[[Any], dict[str, Any]]
    copies: Callable[[Any, dict[str, Any], list[Any]], list[dict[str, Any]]]
    record: Callable[[Any], dict[str, Any]]
    annotations: dict[int, dict[str, Any]]
    has_views: bool


def _zone_structural(zone: dict[str, Any], has_views: bool) -> dict[str, Any]:
    """A zone copy as the structural payload carries it."""
    return {k: val for k, val in zone.items() if has_views or k not in _RECORD_DRIVEN_KEYS}


@dataclass
class _Assembled:
    """Everything ``render_bundle_body`` builds before it hashes: the body
    (without ``structural_etag``) and the structural payload, plus the RPZ
    zones whose entries are left out of both when streaming."""

    body: dict[str, Any]
    structural: dict[str, Any]
    records: int
    has_views: bool
    streamed: list[_StreamedEntries] = field(default_factory=list)
    zones: _StreamedZones | None = None


def _placeholder() -> str:
    """A string no rendered value can equal: it stands in for a value that is
    written into the serialised body later. The NULs keep it out of anything
    an operator can store."""
    return f"\x00spatium-bundle-placeholder:{secrets.token_hex(16)}\x00"


async def render_bundle_body(db: AsyncSession, server: DNSServer) -> RenderedBody:
    """Build everything in the bundle except the ops page, from DB state.

    This is the assembly ``build_config_bundle`` always did. The worker
    render (#1111) stores the same bundle through ``encode_bundle_body``,
    which streams the blocklist entries instead of building them here
    (#1662); the long-poll serves the stored bytes and splices the ops page
    in per request.
    """
    return _finish_whole(await _assemble(db, server, stream=False))


def _finish_whole(assembled: _Assembled) -> RenderedBody:
    """Hash an assembly with nothing left out: both ETags, the structural one
    into the body."""
    bundle_body = assembled.body
    structural_etag = _compute_etag(assembled.structural)
    bundle_body["structural_etag"] = structural_etag

    # The canonical payload the inline build always hashed had the ops keys
    # present (and, with nothing pending, empty). Hashing that shape keeps a
    # stored bundle's ETag identical to the pre-#1111 ETag for the same
    # state whenever nothing is pending.
    etag = _compute_etag({**bundle_body, "pending_record_ops": [], "pending_ops_remaining": 0})
    return RenderedBody(
        body=bundle_body,
        etag=etag,
        structural_etag=structural_etag,
        records=assembled.records,
        has_views=assembled.has_views,
    )


def _cut(text: str, marks: list[str], kwargs: dict[str, Any]) -> list[bytes]:
    """``text`` (serialised with ``kwargs``) cut where each of ``marks`` was
    serialised, in order, each exactly once; the parts UTF-8 encoded."""
    parts: list[bytes] = []
    at = 0
    for mark in marks:
        quoted = json.dumps(mark, **kwargs)
        hit = text.find(quoted, at)
        if hit < 0 or text.find(quoted, hit + len(quoted)) >= 0:
            raise RuntimeError("a bundle placeholder did not serialise exactly once")
        parts.append(text[at:hit].encode("utf-8"))
        at = hit + len(quoted)
    parts.append(text[at:].encode("utf-8"))
    return parts


async def _stream_zone_entries(
    db: AsyncSession,
    lists: list[Any],
    hashes: tuple[Callable[[bytes], None], ...],
    write: Callable[[bytes], None],
) -> None:
    """Write one RPZ zone's ``entries`` list, a batch at a time: into the ETag
    hashes as ``json.dumps`` with ``_ETAG_JSON`` would serialise it, and into
    the body as ``WIRE_JSON`` would. A JSON list is its items joined by the
    item separator, so a batch serialised on its own, minus its brackets,
    joins the next one exactly where the whole list would have."""
    first = True
    for update in hashes:
        update(b"[")
    write(b"[")
    # ``aclosing``: a failure here (not in the generator) must close the
    # list's server-side cursor now, on this connection, rather than leave it
    # to the event loop's async-generator finaliser after the caller has
    # already rolled the session back or reused it.
    async with aclosing(stream_entries(db, lists, BLOCKLIST_RENDER_BATCH)) as batches:
        async for batch in batches:
            items = [_entry_dict(*entry) for entry in batch]
            hashed = json.dumps(items, **_ETAG_JSON)[1:-1].encode("utf-8")
            wire = json.dumps(items, **WIRE_JSON)[1:-1].encode("utf-8")
            del items
            if not first:
                # json.dumps's item separators: ", " by default, "," on the wire.
                hashed = b", " + hashed
                wire = WIRE_JSON["separators"][0].encode("utf-8") + wire
            for update in hashes:
                update(hashed)
            write(wire)
            first = False
    for update in hashes:
        update(b"]")
    write(b"]")


async def _zone_record_batches(
    db: AsyncSession, zones: list[Any]
) -> AsyncGenerator[tuple[int, Any, list[Any] | None], None]:
    """``(index, zone, its records)`` for every zone, in ``zones``' order,
    reading the records of a batch of zones per query (#2227).

    Each zone's records come in the order ``_records_query`` gives them, which
    within a zone is exactly the whole render's order. A batch is cut when its
    zones' records reach ``RECORD_RENDER_BATCH`` (counted first, per zone) or
    it holds ``ZONE_RENDER_BATCH`` zones, so what is held is one batch's rows
    whatever the group's size. A zone that alone has more records than a
    batch comes with ``None`` instead: the caller reads it in chunks
    (``_zone_record_chunks``). Every query runs after the render's snapshot
    statement, as the single records query did, so each sees at least every
    transaction that snapshot does (``agent_bundle_render``'s ordering).
    """
    if not zones:
        return
    group_ids = list({z.group_id for z in zones})
    counts: dict[Any, int] = {
        zone_id: int(n)
        for zone_id, n in (
            await db.execute(
                select(DNSRecord.zone_id, func.count())
                .where(
                    DNSRecord.zone_id.in_(select(DNSZone.id).where(DNSZone.group_id.in_(group_ids)))
                )
                .group_by(DNSRecord.zone_id)
            )
        ).all()
    }

    async def _flush(batch: list[tuple[int, Any]]) -> list[tuple[int, Any, list[Any]]]:
        by_zone: dict[Any, list[Any]] = {}
        result = await db.execute(_records_query(DNSRecord.zone_id.in_([z.id for _, z in batch])))
        for rec in result:
            by_zone.setdefault(rec.zone_id, []).append(rec)
        return [(i, z, by_zone.pop(z.id, [])) for i, z in batch]

    batch: list[tuple[int, Any]] = []
    held = 0
    for i, z in enumerate(zones):
        count = counts.get(z.id, 0)
        if count > RECORD_RENDER_BATCH:
            # Too big for any batch: what is pending goes first, in order.
            if batch:
                for item in await _flush(batch):
                    yield item
                batch, held = [], 0
            yield i, z, None
            continue
        batch.append((i, z))
        held += count
        if held >= RECORD_RENDER_BATCH or len(batch) >= ZONE_RENDER_BATCH:
            for item in await _flush(batch):
                yield item
            batch, held = [], 0
    if batch:
        for item in await _flush(batch):
            yield item


async def _zone_record_chunks(db: AsyncSession, zone: Any) -> AsyncGenerator[list[Any], None]:
    """One zone's records in ``_records_query`` order, ``RECORD_RENDER_BATCH``
    rows at a time, over a server-side cursor (#2227)."""
    result = await db.stream(
        _records_query(DNSRecord.zone_id == zone.id).execution_options(
            yield_per=RECORD_RENDER_BATCH
        )
    )
    try:
        async for chunk in result.partitions(RECORD_RENDER_BATCH):
            yield list(chunk)
    finally:
        await result.close()


class _Spool:
    """Bytes written now and read back once, in order: in memory up to
    ``SPOOL_MEMORY_BYTES``, on disk past it (#2227)."""

    def __init__(self) -> None:
        self._file = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES)  # noqa: SIM115

    def write(self, data: bytes) -> None:
        self._file.write(data)

    def drain(self, sink: Callable[[bytes], None]) -> None:
        self._file.seek(0)
        while chunk := self._file.read(1 << 20):
            sink(chunk)

    def close(self) -> None:
        self._file.close()


#: What a zone spool keeps in memory before it moves to a temporary file.
SPOOL_MEMORY_BYTES = 8 << 20


def _join(first: bool, sep: bytes, data: bytes) -> bytes:
    return data if first else sep + data


async def _stream_flat_zone(
    db: AsyncSession,
    plan: _StreamedZones,
    zone: Any,
    base: dict[str, Any],
    extra: dict[str, Any] | None,
    first: bool,
    write: Callable[[bytes], None],
    etag_spool: _Spool,
    structural_spool: _Spool,
) -> int:
    """A zone too large for a batch, in a group without views: its one copy,
    with the records read and written a chunk at a time (#2227). The copy is
    serialised with a placeholder for its ``records`` and cut there, as
    ``encode_bundle_body`` does for the whole body; the structural copy leaves
    the records out, so it needs no cut. Returns the records written."""
    mark = _placeholder()
    copy: dict[str, Any] = {**base, "view_name": None, "records": mark}
    if extra:
        copy.update(extra)
    wire_sep = WIRE_JSON["separators"][0].encode("utf-8")
    wire_head, wire_tail = _cut(json.dumps(copy, **WIRE_JSON), [mark], WIRE_JSON)
    etag_head, etag_tail = _cut(json.dumps(copy, **_ETAG_JSON), [mark], _ETAG_JSON)
    structural_spool.write(
        _join(
            first,
            b", ",
            json.dumps(_zone_structural(copy, False), **_ETAG_JSON).encode("utf-8"),
        )
    )
    write(_join(first, wire_sep, wire_head) + b"[")
    etag_spool.write(_join(first, b", ", etag_head) + b"[")
    records = 0
    chunk_first = True
    async with aclosing(_zone_record_chunks(db, zone)) as chunks:
        async for rows in chunks:
            items = [plan.record(r) for r in rows]
            del rows
            records += len(items)
            # A JSON list is its items joined by the item separator, so a
            # chunk serialised on its own, minus its brackets, joins the next
            # exactly where the whole list would have.
            write(
                _join(chunk_first, wire_sep, json.dumps(items, **WIRE_JSON)[1:-1].encode("utf-8"))
            )
            etag_spool.write(
                _join(chunk_first, b", ", json.dumps(items, **_ETAG_JSON)[1:-1].encode("utf-8"))
            )
            chunk_first = False
            del items
    write(b"]" + wire_tail)
    etag_spool.write(b"]" + etag_tail)
    return records


async def _stream_zones(
    db: AsyncSession,
    plan: _StreamedZones,
    write: Callable[[bytes], None],
    etag_spool: _Spool,
    structural_spool: _Spool,
) -> int:
    """Write the group's zone copies: into the body (``write``) as
    ``WIRE_JSON`` serialises the ``zones`` list, and into the two spools as
    ``_ETAG_JSON`` serialises the ETag payload's ``zones`` and the structural
    payload's ``zones_structural``. A JSON list is its items joined by the item
    separator, so each copy serialised on its own joins the next exactly where
    the whole list would have. Returns the records written."""
    wire_sep = WIRE_JSON["separators"][0].encode("utf-8")
    write(b"[")
    etag_spool.write(b"[")
    structural_spool.write(b"[")
    first = True
    records = 0
    # ``aclosing``: a failure in a caller's sink must not leave the generator
    # holding a batch until the event loop finalises it.
    async with aclosing(_zone_record_batches(db, plan.zones)) as batches:
        async for index, zone, rows in batches:
            base = plan.base(zone)
            extra = plan.annotations.get(index)
            if rows is None:
                if not plan.has_views:
                    records += await _stream_flat_zone(
                        db, plan, zone, base, extra, first, write, etag_spool, structural_spool
                    )
                    first = False
                    continue
                # Under views a zone's copies are cut from all of its records
                # at once (which views it renders in depends on them), so the
                # largest zone is what such a render holds.
                rows = []
                async with aclosing(_zone_record_chunks(db, zone)) as chunks:
                    async for chunk in chunks:
                        rows.extend(chunk)
            copies = plan.copies(zone, base, rows)
            del rows
            for copy in copies:
                if extra:
                    copy.update(extra)
                records += len(copy["records"])
                write(_join(first, wire_sep, json.dumps(copy, **WIRE_JSON).encode("utf-8")))
                etag_spool.write(
                    _join(first, b", ", json.dumps(copy, **_ETAG_JSON).encode("utf-8"))
                )
                structural_spool.write(
                    _join(
                        first,
                        b", ",
                        json.dumps(_zone_structural(copy, plan.has_views), **_ETAG_JSON).encode(
                            "utf-8"
                        ),
                    )
                )
                first = False
            del copies
    write(b"]")
    etag_spool.write(b"]")
    structural_spool.write(b"]")
    return records


async def encode_bundle_body(db: AsyncSession, server: DNSServer) -> EncodedBody:
    """``render_bundle_body``, serialised and gzipped as the store keeps it:
    the same bytes, ETag and structural ETag, without ever holding the group's
    records (#2227) or a blocklist (#1662) whole.

    Building every record of a group as a row and a dict, then serialising the
    payload three times over (the structural ETag, the ETag and the body), is
    what took a million-record group's render past 1 GB and a two-million
    record one past the worker's 4 GiB. Here the group's ``zones`` (and the
    structural ``zones_structural``) and every RPZ zone's ``entries`` are
    placeholders while the rest is serialised once per document; each
    document is cut where its placeholders landed, and the zones and entries
    are read from the database a batch at a time and written into all three.

    The three documents order their large parts differently, and SHA-256 only
    runs forwards, so two of them are spooled (``_Spool``). In the body
    (``WIRE_JSON``, insertion order) the zones come before the blocklists; in
    the ETag payload and the structural payload (``_ETAG_JSON``, sorted keys)
    the blocklists come first, then ``structural_etag`` (the ETag payload
    only, known once the structural payload is hashed), then the zones. So
    the zones are written straight into the gzip stream and spooled for the
    two hashes; the entries then go into all three at once; then the two
    spools are hashed in behind them.

    Placeholders serialise exactly once each: the zones are one list, each RPZ
    zone holds one ``entries`` (and, in a BIND9 bundle, one content hash,
    #2157, which follows its entries in every document), and
    ``structural_etag`` is one key.
    """
    assembled = await _assemble(db, server, stream=True)
    body = assembled.body
    plan = assembled.zones
    assert plan is not None  # stream=True always plans the zones
    # Every blocklist placeholder in document order: each RPZ zone's entries,
    # then (#2157) its content hash, which is known only once those entries
    # have streamed.
    seq: list[tuple[str, _StreamedEntries, bool]] = []
    for zone in assembled.streamed:
        seq.append((zone.mark, zone, False))
        if zone.hash_mark is not None:
            seq.append((zone.hash_mark, zone, True))
    bl_marks = [mark for mark, _zone, _is_hash in seq]
    n = len(bl_marks)
    structural_mark = _placeholder()
    body["structural_etag"] = structural_mark
    # The order each placeholder appears in each document (see above).
    wire_parts = _cut(
        json.dumps(body, **WIRE_JSON), [plan.mark, *bl_marks, structural_mark], WIRE_JSON
    )
    etag_parts = _cut(
        json.dumps({**body, "pending_record_ops": [], "pending_ops_remaining": 0}, **_ETAG_JSON),
        [*bl_marks, structural_mark, plan.mark],
        _ETAG_JSON,
    )
    structural_parts = _cut(
        json.dumps(assembled.structural, **_ETAG_JSON),
        [*bl_marks, plan.structural_mark],
        _ETAG_JSON,
    )
    body.clear()
    assembled.structural.clear()

    structural_hash = hashlib.sha256()
    etag_hash = hashlib.sha256()
    writer = BodyWriter()
    etag_spool, structural_spool = _Spool(), _Spool()
    try:
        writer.write(wire_parts[0])
        records = await _stream_zones(db, plan, writer.write, etag_spool, structural_spool)
        for i, (_mark, zone, is_hash) in enumerate(seq):
            structural_hash.update(structural_parts[i])
            etag_hash.update(etag_parts[i])
            writer.write(wire_parts[1 + i])
            if is_hash:
                value = _rpz_hash_value(zone.hasher)
                hashed = json.dumps(value, **_ETAG_JSON).encode("utf-8")
                structural_hash.update(hashed)
                etag_hash.update(hashed)
                writer.write(json.dumps(value, **WIRE_JSON).encode("utf-8"))
                continue
            hashes = (structural_hash.update, etag_hash.update)
            if zone.hasher is not None:
                hashes = (*hashes, zone.hasher.update)
            await _stream_zone_entries(db, zone.lists, hashes, writer.write)

        structural_hash.update(structural_parts[n])
        structural_spool.drain(structural_hash.update)
        structural_hash.update(structural_parts[n + 1])
        structural_etag = "sha256:" + structural_hash.hexdigest()

        etag_hash.update(
            etag_parts[n]
            + json.dumps(structural_etag, **_ETAG_JSON).encode("utf-8")
            + etag_parts[n + 1]
        )
        etag_spool.drain(etag_hash.update)
        etag_hash.update(etag_parts[n + 2])

        writer.write(
            wire_parts[n + 1]
            + json.dumps(structural_etag, **WIRE_JSON).encode("utf-8")
            + wire_parts[n + 2]
        )
    finally:
        etag_spool.close()
        structural_spool.close()
    return EncodedBody(
        body_gz=writer.finish(),
        body_bytes=writer.size,
        etag="sha256:" + etag_hash.hexdigest(),
        structural_etag=structural_etag,
        records=records,
        has_views=assembled.has_views,
    )


#: The record count at which the streamed render (#2227) stops adding zones
#: to one records query, and the most zones it puts in one: a batch holds
#: about this many rows (~700 B each as fetched), however many records the
#: group has. A zone with more records than this is read on its own over a
#: server-side cursor, this many rows at a time — and, in a group without
#: views, written that way too. Under split-horizon a zone's copies are cut
#: from all of its records at once, so there the largest zone is the bound.
RECORD_RENDER_BATCH = 20_000
ZONE_RENDER_BATCH = 1000


# The records the bundle ships, as column rows rather than ORM instances.
# This was once one ``select(DNSRecord)`` per zone inside ``_assemble``'s zone
# loop (N+1), and each row came back as a tracked ORM object — on
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
# sort on the tiny per-name groups instead of sorting the table. The
# streamed render (#2227) runs it per batch of zones or per zone, whose
# records come back in the same order.
def _records_query(where: Any) -> Any:
    return (
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
        .where(where)
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


async def _assemble(db: AsyncSession, server: DNSServer, *, stream: bool) -> _Assembled:
    """Build everything in the bundle except the ops page and the two
    ETags. ``stream``: leave each RPZ zone's entries out, for
    ``encode_bundle_body`` to write in."""
    # Options (per group)
    opts_res = await db.execute(
        select(DNSServerOptions)
        .where(DNSServerOptions.group_id == server.group_id)
        .options(selectinload(DNSServerOptions.trust_anchors))
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

    # Zones (+ records for primary only), by name like every other list the
    # structural fingerprint hashes, then by id (two views may each hold a
    # zone of the same name). Unordered, Postgres returned them in whatever
    # order its plan read them, and the UPDATE a record change makes to its
    # zone (``last_serial``) moved that zone in it, so a record change moved
    # the structural etag of any group of two zones or more (#1373).
    zones_res = await db.execute(
        select(DNSZone)
        .where(DNSZone.group_id == server.group_id)
        .order_by(DNSZone.name, DNSZone.id)
    )
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
        update_acls_by_zone = {
            zone_id: _safe_update_acl(zone_id, entries)
            for zone_id, entries in update_acls_by_zone.items()
        }

    # Every record of every zone in ONE query (``_records_query``). The
    # streamed render (#2227) reads them a batch of zones at a time instead
    # (``_zone_record_batches``), so it never holds the group's record set.
    records_by_zone: dict[Any, list[Any]] = {}
    if zone_ids and not stream:
        rec_res = await db.execute(_records_query(DNSRecord.zone_id.in_(zone_ids)))
        for rec in rec_res:
            records_by_zone.setdefault(rec.zone_id, []).append(rec)

    def _rec_dict(r: Any) -> dict[str, Any]:
        return {
            "name": r.name,
            "type": r.record_type,
            # #2073 — a TTL stored negative before the API bounded it would
            # make BIND refuse the whole zone file; the record inherits $TTL.
            "ttl": servable_ttl(r.ttl),
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

    # #1171 — whether the group's zones go out with their own SOA timers or the
    # literal every BIND9 agent of an older release writes (``soa_timers``).
    serves_soa_timers = bool(
        await db.scalar(
            select(DNSServerGroup.serves_soa_timers).where(DNSServerGroup.id == server.group_id)
        )
    )

    def _base_zone(z: Any) -> dict[str, Any]:
        base_zp: dict[str, Any] = {
            "id": str(z.id),
            "name": getattr(z, "name", None) or getattr(z, "fqdn", None),
            "type": getattr(z, "zone_type", "primary"),
            # #430 — was getattr(z, "default_ttl", 3600): DNSZone has no
            # default_ttl, so this silently pinned every zone's $TTL to the
            # literal 3600 and editing a zone's TTL never re-rendered.
            # #2073 — a $TTL stored negative before the API bounded it makes
            # BIND refuse the zone file, so it ships as the create default.
            "ttl": _zone_ttl(z),
            # #430 (D1) — the agent's zone-state reporter skips any zone with
            # serial=None, so omitting this made it report nothing for every
            # zone and the per-server ZoneSyncPill stayed empty. Ship the
            # authoritative serial the agent renders from.
            "serial": getattr(z, "last_serial", 0),
            # Forward-zone-only fields (ignored by the agent for other types).
            "forwarders": (
                _safe_zone_forwarders(z)
                if server.driver == "bind9" and getattr(z, "zone_type", None) == "forward"
                else list(getattr(z, "forwarders", []) or [])
            ),
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
            # #1523 — per-zone NOTIFY / query overrides. Same stored-but-
            # never-shipped class as #734: accepted, validated (#1316) and
            # persisted, but absent from the bundle, so neither agent could
            # render them. None means "inherit the server options"; the
            # BIND9 agent emits a zone clause only for a non-None value and
            # the PowerDNS agent folds the effective values into the zone
            # kind + ALSO-NOTIFY metadata. Shipping them here also puts
            # them inside the structural fingerprint (zones_structural
            # derives from zone_payload), so an edit re-renders.
            "allow_query": getattr(z, "allow_query", None),
            "also_notify": getattr(z, "also_notify", None),
            "notify_enabled": getattr(z, "notify_enabled", None),
            # #1153 — the zone's SOA MNAME / RNAME, and its NS when it has no
            # NS records of its own. Settable and persisted, never shipped, so
            # the BIND9 agent served the placeholder ``ns1.<zone>`` (glued to
            # 127.0.0.1) and ``admin.<zone>`` whatever was set. "" = unset.
            "primary_ns": getattr(z, "primary_ns", "") or "",
            "admin_email": getattr(z, "admin_email", "") or "",
            # #1171 — the zone's SOA timers. Stored, editable, exported and in
            # the control plane's own zone template, never shipped, so the
            # BIND9 agent wrote 3600/600/86400/300 into every zone's SOA. Like
            # the apex above they are structural (zones_structural keeps them),
            # so an edit re-renders the zone. That literal instead while a
            # BIND9 agent of the group still writes it, so the group serves
            # one SOA per serial (``soa_timers.served_soa_timers``).
            **served_soa_timers(z, serves_soa_timers),
        }
        # A forward zone's OWN upstream transport (#2121). It used to inherit
        # the group's ``forward_transport``; an agent older than #2121 ignores
        # these keys and keeps inheriting, so the fix needs the agent upgraded
        # too. Shipped only when the zone forwards over something other than
        # plain DNS: an absent key reads as ``do53`` on the agent
        # (``_forwarders.zone_forward_transport``), so a group that does not
        # use the feature ships the bundle it did before and its etag does not
        # move on upgrade, which would reload every agent in the fleet for a
        # byte-identical named.conf. Inside zone_payload, so setting or
        # clearing a transport shifts the structural etag.
        zone_transport = getattr(z, "forward_transport", None) or "do53"
        if getattr(z, "zone_type", None) == "forward" and zone_transport != "do53":
            base_zp["forward_transport"] = zone_transport
            base_zp["forward_tls_hostname"] = getattr(z, "forward_tls_hostname", None)
        return base_zp

    def _zone_copies(z: Any, base_zp: dict[str, Any], rec_rows: list[Any]) -> list[dict[str, Any]]:
        """The zone's copies as the bundle ships them: one, or one per view
        that renders it. ``rec_rows`` is every record of the zone."""
        # Ship records to every server in the group. The is_primary flag
        # historically gated this, but agents need records to render zone
        # files for serving — primary/secondary distinction matters for
        # accepting RFC 2136 updates, not for which server gets the data.
        copies: list[dict[str, Any]] = []
        if not has_views:
            # Flat render — one zone copy, all records, no view (today's path).
            copies.append(
                {
                    **base_zp,
                    "view_name": None,
                    # A member scoped to a site with no subnets serves nobody
                    # (#2292) — even when no geo view exists to carry it.
                    "records": [
                        _rec_dict(r)
                        for r in rec_rows
                        if str(r.pool_member_id) not in geo.unreachable_members
                    ],
                }
            )
            return copies

        # Split-horizon expansion (issue #24) composed with geo steering
        # (issue #530). Operator views: the zone materialises in every
        # view it has content for — each view referenced by a scoped
        # record PLUS the zone's own pinned ``view_id``; with no explicit
        # scoping it's "global" and renders into every operator view.
        # Geo + catch-all views always render the zone (like a global
        # zone) so the catch-all serves the default member set. Per-view
        # record filtering is delegated to ``records_for_view``. The rule is
        # shared with the transfer-key resolver (#920), so the view drift and
        # sync ask for is always one that holds the zone.
        # #2275 — the collision guard counts placements from the same call.
        for vd in views_rendering_zone(view_descs, z.view_id, (r.view_id for r in rec_rows)):
            recs = records_for_view(rec_rows, vd, geo)
            copies.append(
                {
                    **base_zp,
                    "view_name": vd["name"],
                    "records": [_rec_dict(r) for r in recs],
                }
            )
        return copies

    zone_payload: list[dict[str, Any]] = []
    if not stream:
        for z in zones:
            zone_payload.extend(_zone_copies(z, _base_zone(z), records_by_zone.get(z.id, [])))

    # The ops page is not part of the body — see ``page_pending_ops`` /
    # ``retire_queued_ops`` below (#1111).

    # Group-level TSIG key for RFC 2136 dynamic updates
    grp = await db.get(DNSServerGroup, server.group_id)
    tsig_keys: list[dict[str, Any]] = []
    if (group_key := legacy_group_key(grp)) is not None:
        tsig_keys.append(
            {
                "name": group_key.name,
                "secret": group_key.secret,
                "algorithm": group_key.algorithm,
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
        if (problem := tsig_secret_shape_problem(secret)) is not None:
            # A row stored before the API checked secrets. It is written
            # verbatim into the agent's key file, so a value that is not one
            # base64 string is left out rather than shipped; any reference
            # to the key is then dropped below like any other undefined key.
            logger.warning("dns_tsig_key_secret_unrenderable", key=k.name, problem=problem)
            continue
        tsig_keys.append({"name": k.name, "secret": secret, "algorithm": k.algorithm})
    # A stored operator key that duplicates another name (the legacy group
    # key, or ``foo`` vs ``foo.``) would render two ``key {}`` statements and
    # stop the whole group converging (#2295). One survives, deterministically.
    tsig_keys = dedupe_tsig_keys(tsig_keys)

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
        # NOTIFY behaviour (#1523). Settable in the UI / API, validated
        # (#1316) and persisted, but never shipped, so `notify no` (a
        # stealth primary) still sent NOTIFY from BIND9 (whose default is
        # yes), also-notify targets were never notified, and PowerDNS
        # zones stayed Native (which never notifies). The agents render
        # these now; shipping them here puts them inside the structural
        # fingerprint via options_block.
        "notify_enabled": (getattr(opts, "notify_enabled", "yes") if opts else "yes"),
        "also_notify": (list(getattr(opts, "also_notify", []) or []) if opts else []),
        "allow_notify": (list(getattr(opts, "allow_notify", []) or []) if opts else []),
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
    if (
        server.driver == "bind9"
        and opts is not None
        and list(opts.allow_query_cache or []) != list(DEFAULT_ALLOW_QUERY_CACHE)
    ):
        # #2264: the group-level ``allow-query-cache`` was validated, stored
        # and never shipped, so narrowing cache access (cache snooping) did
        # nothing. Shipped only when it differs from the stored default, so a
        # group nobody touched keeps its bundle (and etag) byte-identical and
        # an upgrade reloads nothing. BIND9-only: PowerDNS / Technitium have
        # no such setting and the API refuses a non-default value for them.
        options_block["allow_query_cache"] = list(opts.allow_query_cache or [])
    # #2263 — the group ``blackhole`` list. Accepted and validated since
    # #1244 and never shipped, so no agent could render it. Shipped only when
    # set: an absent key reads as empty on the agent, so a group that does not
    # use it keeps the bundle (and the structural etag) it had before, and an
    # upgrade does not reload every agent for a byte-identical config. The
    # BIND9 agent renders it; PowerDNS / Technitium groups refuse it at the
    # API, since neither daemon can drop a client by address.
    blackhole = list(getattr(opts, "blackhole", []) or []) if opts else []
    if blackhole:
        options_block["blackhole"] = blackhole
    if server.driver in ("technitium", "bind9"):
        # #1761 / #1786: Technitium and BIND9 read this (the BIND9 agent
        # renders ``allow-recursion`` from it, literally, #1817), so
        # PowerDNS's etag does not move with it.
        options_block["allow_recursion"] = (
            list(opts.allow_recursion if opts.allow_recursion is not None else [])
            if opts
            else list(DEFAULT_ALLOW_RECURSION)
        )
    if server.driver == "bind9" and opts is not None and opts.trust_anchors:
        # DNSSEC trust anchors (#2266). Stored and listed since the options
        # API shipped, shipped to nobody: ``dnssec-validation yes`` therefore
        # validated nothing. BIND9-only, and only when there are some, so a
        # group without anchors keeps a byte-identical bundle and etag.
        # Sorted: the relationship has no order, and an unstable list would
        # shift the etag on every poll.
        options_block["trust_anchors"] = sorted(
            (
                {
                    "zone_name": ta.zone_name,
                    "algorithm": ta.algorithm,
                    "key_tag": ta.key_tag,
                    "public_key": ta.public_key,
                    "is_initial_key": bool(ta.is_initial_key),
                }
                for ta in opts.trust_anchors
            ),
            key=lambda t: (t["zone_name"], t["algorithm"], t["key_tag"], t["public_key"]),
        )
    if server.driver == "powerdns":
        # PowerDNS ALIAS expansion (#1353): the group's own plain-DNS
        # forwarders, or "" for ALIAS off. Never a built-in public resolver.
        # PowerDNS-only, so no other driver's structural etag moves with it.
        options_block["alias_resolver"] = alias_resolver(
            getattr(opts, "forwarders", []) if opts else [],
            getattr(opts, "forward_transport", "do53") if opts else "do53",
        )
    # Built from the unified descriptor list so operator split-horizon
    # views (issue #24), synthesized geo views + the geo catch-all
    # (issue #530) all render. Already ordered low→high so the rendered
    # view blocks honour BIND's first-match-wins precedence.
    # #430 — per-view query ACL overrides (allow_query / allow_query_cache).
    # None → inherit server-options allow-query (renderer omits the line).
    views_block: list[dict[str, Any]] = [
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
    # #920 — the key that lets the control plane's own transfers (drift,
    # sync-with-servers) select each view. The agent admits it into its view's
    # match-clients and refuses it in every other; without it a signed transfer
    # matched no view (BADKEY) or whichever broad view caught the api's
    # address. Derived from the legacy group key, the same way the resolver
    # derives the key it signs with (``tsig.view_transfer_key``); a group with
    # no legacy key ships none, and its views render as before. The secret rides
    # the bundle body under the same trust model as ``tsig_keys``, and
    # ``views`` is structural, so a group-key rotation re-renders the views.
    # ``group_key`` is the legacy key resolved for ``tsig_keys`` above; it is
    # not re-read here, so the secret is decrypted once per render.
    if group_key is not None:
        for view_entry in views_block:
            vkey = view_transfer_key(group_key, view_entry["name"])
            view_entry["transfer_key"] = {
                "name": vkey.name,
                "secret": vkey.secret,
                "algorithm": vkey.algorithm,
            }
    # #899 — ship the entries, not just the name. The agent renders these
    # into ``acl "<name>" { … };`` stanzas; before this the block carried
    # ``{id, name}`` only, so an ACL was inert config and any reference to
    # one was an undefined symbol that failed the entire bundle.
    acls_block = _safe_acls_block(acls)

    # #2282 / #2283 — never ship a ``key <name>`` or ACL name the bundle does
    # not define. Access lists that empty out become ``none``, not "inherit".
    # #2695: nor, to a BIND9 server, a prefix BIND 9 refuses.
    known_key_names = frozenset(_key_name_norm(k["name"]) for k in tsig_keys)
    known_acl_names = frozenset(a["name"] for a in acls_block)
    bind9 = server.driver == "bind9"
    for a in acls_block:
        a["entries"] = [
            e
            for e in a["entries"]
            if _drop_undefined_key_refs(
                [e["value"]],
                known_key_names,
                where=f"acl:{a['name']}",
                drop_bind9_refused_prefixes=bind9,
            )
        ]
    for ve in views_block:
        for f in ("match_clients", "match_destinations", "allow_query", "allow_query_cache"):
            ve[f] = _drop_undefined_key_refs(
                ve.get(f),
                known_key_names,
                where=f"view:{ve['name']}.{f}",
                known_acls=known_acl_names,
                deny_if_emptied=True,
                drop_bind9_refused_prefixes=bind9,
            )
    for f in (*ADDRESS_MATCH_LIST_OPTIONS, "also_notify"):
        if f in options_block:
            options_block[f] = _drop_undefined_key_refs(
                options_block[f],
                known_key_names,
                where=f"options.{f}",
                known_acls=known_acl_names,
                deny_if_emptied=f != "also_notify",
                drop_bind9_refused_prefixes=bind9,
            )

    def _drop_zone_refs(zp: dict[str, Any]) -> dict[str, Any]:
        for f in ("allow_query", "allow_transfer", "also_notify"):
            zp[f] = _drop_undefined_key_refs(
                zp.get(f),
                known_key_names,
                where=f"zone:{zp['name']}.{f}",
                known_acls=known_acl_names,
                deny_if_emptied=f != "also_notify",
                drop_bind9_refused_prefixes=bind9,
            )
        return zp

    # The streamed render (#2227) builds its zones later, through
    # ``_StreamedZones.base``, which applies the same drop to each zone's base
    # (every copy of a zone carries its base's values).
    for zp in zone_payload:
        _drop_zone_refs(zp)

    # Blocklists: one RPZ zone per view (if any) + one group-level zone.
    # Each assembled list has its entries resolved against view/group scope
    # with exceptions already applied by `build_effective_for_{view,group}`.
    def _entries_payload(eff_entries: list[Any]) -> list[dict[str, Any]]:
        return [
            _entry_dict(e.domain, e.action, e.block_mode, e.target, e.is_wildcard, e.sinkhole_ip)
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
    streamed: list[_StreamedEntries] = []
    # #2157 — only the BIND9 agent reads the per-zone content hash.
    rpz_hashes = server.driver == "bind9"

    async def _streamed_zone(
        lists: list[Any] | None, rpz_zone_name: str, view_name: str | None
    ) -> bool:
        # #1662 — the zone exactly as below, with a placeholder for its
        # entries, which ``encode_bundle_body`` streams in. A zone with no
        # entry is left out, as below; an entry deleted between this check and
        # the stream leaves a zone with none, and the delete has marked the
        # bundle, so the next render drops it.
        if not lists or not await has_entries(db, lists):
            return False
        mark = _placeholder()
        exceptions = sorted(await exception_domains(db, lists))
        zone_dict: dict[str, Any] = {
            "rpz_zone_name": rpz_zone_name,
            "entries": mark,
            "exceptions": exceptions,
            "view_name": view_name,
        }
        zone = (
            _StreamedEntries(
                mark=mark,
                lists=lists,
                hash_mark=_placeholder(),
                hasher=_rpz_hasher(rpz_zone_name, exceptions),
            )
            if rpz_hashes
            else _StreamedEntries(mark=mark, lists=lists)
        )
        if zone.hash_mark is not None:
            zone_dict[RPZ_CONTENT_HASH_KEY] = zone.hash_mark
        streamed.append(zone)
        blocklists_payload.append(zone_dict)
        return True

    def _hashed(zone_dict: dict[str, Any]) -> dict[str, Any]:
        """The materialised render's half of #2157: the same hash the streamed
        render computes, over the same bytes."""
        if rpz_hashes:
            hasher = _rpz_hasher(zone_dict["rpz_zone_name"], zone_dict["exceptions"])
            hasher.update(json.dumps(zone_dict["entries"], **_ETAG_JSON).encode("utf-8"))
            zone_dict[RPZ_CONTENT_HASH_KEY] = _rpz_hash_value(hasher)
        return zone_dict

    # #1706 — a view's own zone already folds in the group's lists, so the
    # group zone rendered beside it would hold the same entries a second time.
    # Track which views got a zone of their own; the group zone is only needed
    # for one that did not.
    views_with_own_zone = 0
    if views:
        for v in views:
            if stream:
                if await _streamed_zone(
                    await effective_lists_for_view(db, v.id),
                    f"spatium-blocklist-{v.name}.rpz.",
                    v.name,
                ):
                    views_with_own_zone += 1
                continue
            eff_v = await build_effective_for_view(db, v.id)
            if eff_v.entries:
                views_with_own_zone += 1
                blocklists_payload.append(
                    _hashed(
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
                )
    # With views, only a view that got no zone of its own needs the group's
    # (the agent loads it into that view alone). Without views it is the one
    # global RPZ, as before.
    if not views or views_with_own_zone < len(views):
        if stream:
            await _streamed_zone(
                await effective_lists_for_group(db, server.group_id),
                "spatium-blocklist.rpz.",
                None,
            )
        else:
            eff_g = await build_effective_for_group(db, server.group_id)
            if eff_g.entries:
                blocklists_payload.append(
                    _hashed(
                        {
                            "rpz_zone_name": "spatium-blocklist.rpz.",
                            "entries": _entries_payload(eff_g.entries),
                            "exceptions": sorted(eff_g.exceptions),
                            # Group-level blocklist. ``view_name=None`` marks
                            # it global: the single RPZ with no views, or
                            # (#1706) the fallback for a view with no zone of
                            # its own.
                            "view_name": None,
                        }
                    )
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

    zones_streamed: _StreamedZones | None = None
    if stream:
        # #2227 — the zones are read, built and written a batch at a time by
        # ``encode_bundle_body``; here they are one placeholder in the body and
        # one in the structural payload.
        annotations: dict[int, dict[str, Any]] = {}
        if server.driver == "technitium":
            # ``_add_master_transfer_keys`` reads only a zone's name, type and
            # masters, and appends its keys after everything else in the zone's
            # dict. Run it over a probe per zone and keep what it added, to be
            # appended to each copy of that zone exactly where it would be.
            probes = [
                {
                    "name": getattr(z, "name", None),
                    "type": getattr(z, "zone_type", "primary"),
                    "masters": list(getattr(z, "masters", []) or []),
                }
                for z in zones
            ]
            await _add_master_transfer_keys(db, probes, catalog_block, tsig_keys)
            for i, probe in enumerate(probes):
                added = {k: v for k, v in probe.items() if k not in ("name", "type", "masters")}
                if added:
                    annotations[i] = added
        zones_streamed = _StreamedZones(
            mark=_placeholder(),
            structural_mark=_placeholder(),
            zones=list(zones),
            # #2282 / #2283 — the same undefined key / ACL drops the whole
            # render applies to ``zone_payload`` above.
            base=lambda z: _drop_zone_refs(_base_zone(z)),
            copies=_zone_copies,
            record=_rec_dict,
            annotations=annotations,
            has_views=has_views,
        )
    elif server.driver == "technitium":
        await _add_master_transfer_keys(db, zone_payload, catalog_block, tsig_keys)

    bundle_body: dict[str, Any] = {
        "server_id": str(server.id),
        "driver": server.driver,
        "options": options_block,
        "views": views_block,
        "acls": acls_block,
        "zones": zone_payload if zones_streamed is None else zones_streamed.mark,
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
        #
        # #1373 — ``serial`` is left out with the records, for the same reason:
        # every record change bumps it, so while it was in here (since #430
        # shipped it for the agent's zone-state reporter) every record change
        # on a flat group re-rendered the zone and froze/reloaded/thawed it
        # beside the RFC 2136 update. A change that should re-render moves a
        # field of its own (the TTL, the SOA timers, the apex); the serial bump
        # that comes with it is never the only difference.
        "zones_structural": (
            [_zone_structural(z, has_views) for z in zone_payload]
            if zones_streamed is None
            else zones_streamed.structural_mark
        ),
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
    if server.zone_resync_seq:
        # #2281 — this server was re-enabled. While it was disabled it got no
        # record ops, so its daemon still serves the records it had then; the
        # bundle body carries the current ones, but without views records do
        # not move the structural etag and the agent would never render them.
        # A new value here makes it re-render every zone from the body. Left
        # out at zero so a server never re-enabled keeps its etag.
        structural["zone_resync_seq"] = server.zone_resync_seq
    if server.driver == "technitium":
        # #1513 — say how a dot-less SVCB / HTTPS target in this bundle is
        # meant: relative to the zone, as in a zone file. Before #1513 the
        # Technitium agent sent it to the daemon as-is (absolute), and an
        # agent replaying a cached bundle from that renderer must keep that
        # meaning, so the agent reads the rule from the bundle rather than
        # assuming its own. Structural on purpose: its arrival moves the
        # structural etag once, so every Technitium agent re-reconciles its
        # zones under the rule even when nothing else changed.
        bundle_body[SVCB_TARGET_RULE_KEY] = SVCB_TARGET_RULE_ZONE_FILE
        structural[SVCB_TARGET_RULE_KEY] = SVCB_TARGET_RULE_ZONE_FILE
        # #1759 — and the same for every other name-valued target, so a
        # dot-less CNAME / NS / MX / SRV / PTR / DNAME / NAPTR target is
        # relative to the zone too. Structural for the same reason.
        bundle_body[NAME_TARGET_RULE_KEY] = NAME_TARGET_RULE_ZONE_FILE
        structural[NAME_TARGET_RULE_KEY] = NAME_TARGET_RULE_ZONE_FILE
    return _Assembled(
        body=bundle_body,
        structural=structural,
        records=sum(len(z["records"]) for z in zone_payload),
        has_views=has_views,
        streamed=streamed,
        zones=zones_streamed,
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


# The op kinds a views render folds into the zone payload (the record the op
# carries is in the body, so the render has already delivered the change).
# Everything else — ``dnssec_rollover`` (a one-shot ``rndc`` call), and
# ``dnssec_sign`` / ``dnssec_unsign`` (PowerDNS and Technitium act only from
# the op) — has NO carrier in a bundle, so a views render must neither retire
# it nor leave it unshipped (#1946).
# The same set as ``rrset.RRSET_OPS`` (the ops that describe an RRset): one
# definition, so a new record op kind cannot be retired by one and not the other.
RECORD_OP_KINDS: frozenset[str] = RRSET_OPS

# Queued ops a split-horizon render retires per statement (#2227).
RETIRE_CHUNK = 5000


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
        # #1946 — only the kinds the render carries; the rest ship (below).
        DNSRecordOp.op.in_(RECORD_OP_KINDS),
    ]
    covered = _covered_by(up_to, visible_xacts)
    if covered is not None:
        conds.append(covered)
    # #2227 — a chunk of ids at a time, never the rows: a group that went
    # unrendered while it was being loaded has a queue the size of its
    # records (813k per server on the scale lab), and loading them as ORM
    # objects to stamp them held about 4 kB each — 3.7 GB in one worker
    # process, more than the render itself ever did.
    # #1929 — locked in ``row_locks`` order (ascending id) before the write;
    # each chunk takes ids above the last, so the whole retire still locks in
    # one ascending order. A row a group move deletes meanwhile is skipped,
    # not a StaleDataError.
    # #2108 — stamped by ``mark_ops_applied``, which shares its field list with
    # the helper every other applied op goes through: the render delivered
    # it, once.
    now = datetime.now(UTC)
    # Rows of this server already in the session (read through the identity
    # key: an expired ``id`` would be a lazy load, which async cannot do).
    loaded = {
        sa_inspect(obj).identity[0]: obj
        for obj in list(db.identity_map.values())
        if isinstance(obj, DNSRecordOp) and obj.__dict__.get("server_id") == server.id
    }
    retired = 0
    after: Any = None
    while True:
        chunk = list(
            (
                await db.execute(
                    select(DNSRecordOp.id)
                    .where(*conds, *([DNSRecordOp.id > after] if after is not None else []))
                    .order_by(DNSRecordOp.id)
                    .limit(RETIRE_CHUNK)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        if not chunk:
            break
        await mark_ops_applied(db, chunk, now, loaded)
        retired += len(chunk)
        after = chunk[-1]
        if len(chunk) < RETIRE_CHUNK:
            # LIMIT counts rows after the lock re-check, so short is last.
            break
    return retired


async def page_pending_ops(
    db: AsyncSession,
    server: DNSServer,
    *,
    up_to: datetime | None = None,
    visible_xacts: str | None = None,
    non_record_only: bool = False,
    dispatched_to: str | None = None,
    poll_started_at: datetime | None = None,
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
    failure ack returns it to pending with a backoff, and after
    ``MAX_OP_ATTEMPTS`` it becomes ``failed`` (#1232). One never acknowledged
    is returned to the retry path by the heartbeat
    (``record_ops.reset_unacknowledged_ops``), and an op backing off is
    retired (``superseded``) once a newer op for its RRset ships.

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

    ``non_record_only`` (#1946): a split-horizon bundle carries record
    changes in the zone payload and retires their ops, but a DNSSEC op has
    no carrier there; the page then holds only those kinds.

    ``dispatched_to`` (#2042): the instance id of the agent process the page
    is for, stamped on each op so a replacement agent's poll can tell an op
    shipped to a predecessor from one shipped to itself
    (``record_ops.return_ops_dispatched_elsewhere``). ``poll_started_at`` is
    when the poll began, stamped with it: it decides which of two concurrent
    polls may take an op back from the other.
    """
    if server.maintenance_mode:
        return [], 0
    now = datetime.now(UTC)
    batch = max(1, int(settings.dns_agent_ops_batch))
    conds: list[Any] = [
        DNSRecordOp.server_id == server.id,
        DNSRecordOp.state == "pending",
        # #1232 — an op backing off after a failed attempt waits its turn.
        or_(DNSRecordOp.next_attempt_at.is_(None), DNSRecordOp.next_attempt_at <= now),
    ]
    if non_record_only:
        conds.append(DNSRecordOp.op.not_in(RECORD_OP_KINDS))
    covered = _covered_by(up_to, visible_xacts)
    if covered is not None:
        conds.append(covered)
    op_res = await db.execute(
        select(DNSRecordOp)
        .where(*conds)
        # #1489 — ``seq`` keeps one transaction's ops in the order they were
        # queued; ``id`` only breaks ties between rows from before it.
        .order_by(DNSRecordOp.created_at, DNSRecordOp.seq, DNSRecordOp.id)
        .limit(batch)
    )
    ops_to_dispatch = list(op_res.scalars().all())
    if not ops_to_dispatch:
        return [], 0
    remaining = 0
    if len(ops_to_dispatch) == batch:
        remaining = int((await db.execute(select(func.count()).where(*conds))).scalar_one()) - len(
            ops_to_dispatch
        )
    waiting = await _backed_off_candidates(db, server, ops_to_dispatch, now)
    # #1929 — lock every op this page writes, in one ascending statement
    # (``row_locks``), before writing any. Read unlocked, a row a server move
    # deleted meanwhile made the flush below match nothing (StaleDataError,
    # a 500 on the poll); locked here, a deleted row is simply not returned,
    # and one still pending is re-read as it is now.
    locked = {
        op.id
        for op in await lock_ops(
            db,
            ids_in([op.id for op in ops_to_dispatch] + [op.id for op in waiting]),
            DNSRecordOp.state == "pending",
        )
    }
    ops_to_dispatch = [op for op in ops_to_dispatch if op.id in locked]
    _supersede_backed_off_ops(
        ops_to_dispatch,
        [
            op
            for op in waiting
            if op.id in locked and op.next_attempt_at is not None and op.next_attempt_at > now
        ],
        now,
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
                # #1232 — which dispatch this is; the agent echoes it in its
                # ack, so a late ack for an earlier dispatch is not charged
                # to this one.
                "dispatch": op.attempts,
            }
        )
        op.state = "in_flight"
        # The dispatch time: the stale-``in_flight`` reset measures from it.
        op.updated_at = now
        op.dispatched_to = dispatched_to
        op.dispatched_poll_at = poll_started_at if dispatched_to is not None else None
    if ops_to_dispatch:
        await db.flush()
    return page, remaining


async def _backed_off_candidates(
    db: AsyncSession, server: DNSServer, shipping: list[DNSRecordOp], now: datetime
) -> list[DNSRecordOp]:
    """The ops still backing off for an RRset in this page, matched in SQL: a
    bulk backlog that failed can leave hundreds of thousands of ops backing
    off, and loading them on every page is what paging exists to avoid.
    Unlocked; the page locks them with its own rows (``page_pending_ops``)."""
    keys = sorted({key for op in shipping if (key := op_rrset_key(op)) is not None})
    found: list[DNSRecordOp] = []
    for i in range(0, len(keys), RRSET_KEY_CHUNK):
        found.extend(
            (
                await db.execute(
                    select(DNSRecordOp).where(
                        backed_off_match_where(server.id, now, keys[i : i + RRSET_KEY_CHUNK])
                    )
                )
            )
            .scalars()
            .all()
        )
    return found


def _supersede_backed_off_ops(
    shipping: list[DNSRecordOp], waiting: list[DNSRecordOp], now: datetime
) -> None:
    """Retire an op waiting out a backoff once a newer op for its RRset ships.

    Every op carries the whole desired RRset (#773), so the newer op delivers
    the older one's change; left alone, the older op would retry after it and
    put the RRset back the way it was. Only ops still backing off are
    candidates (``waiting``, from ``_backed_off_candidates``) — anything older
    and ready ships ahead in the same page. Strictly older only, by
    ``queued_after`` (#1489).
    """
    newest: dict[tuple[str, str, str], DNSRecordOp] = {}
    for op in shipping:
        key = op_rrset_key(op)
        if key is not None:
            newest[key] = op  # the page is oldest-first; the last one wins
    for op in waiting:
        key = op_rrset_key(op)
        successor = newest.get(key) if key is not None else None
        if successor is not None and queued_after(
            successor.created_at, successor.seq, op.created_at, op.seq
        ):
            supersede(op, successor.id, now)


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
        ops, remaining = await page_pending_ops(db, server, non_record_only=True)
    else:
        ops, remaining = await page_pending_ops(db, server)
    return compose_bundle(rendered, ops, remaining)
