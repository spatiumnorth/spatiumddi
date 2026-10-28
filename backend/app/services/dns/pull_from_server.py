"""Bi-directional DNS zone sync between SpatiumDDI's DB and the zone's
authoritative server.

Two phases, both additive:

1. **Pull** — AXFR the server and create ``DNSRecord`` rows for anything
   on the wire that's missing from our DB.
2. **Push** — for every record in our DB (after the pull) that isn't on
   the wire, send an RFC 2136 update via the driver's
   ``apply_record_change`` so it lands on the server.

Neither phase deletes anything. Delete intent flows through the normal
record-deletion UI (which already pushes a ``delete`` op through the
driver). Destructive reconciliation (three-way diff + confirmation UI)
is a later iteration.

Driver-agnostic via ``DNSDriver.pull_zone_records`` + the existing
``apply_record_change``. BIND9, Technitium, Windows DNS and the cloud
providers all implement the pull side; the agent-managed ones read over
a TSIG-signed AXFR (#734), the rest over their own authenticated API.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dns_server_channel
from app.drivers.dns import CLOUD_DNS_DRIVERS, get_driver, is_agentless
from app.drivers.dns._txt import quote_txt, txt_value
from app.drivers.dns.base import RecordChange, RecordData, TsigKey
from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
from app.services.dns.ingest import learned_record_op, server_ops_touching
from app.services.dns.record_ops import (
    QUEUED_OP_STATES,
    enqueue_agent_record_ops,
    resolve_primary_server,
    rrset_from_payload,
)
from app.services.dns.rrset import stamp_rrsets_for_ops
from app.services.dns.serial import bump_zone_serial
from app.services.dns.tsig import (
    pull_zone_records_signed,
    resolve_group_transfer_key,
    resolve_transfer_vip,
    resolve_view_transfer_key,
    transfer_fallback_hosts,
    transfer_needs_tsig,
)
from app.services.technitium.rdata import (
    canonical_ip,
    strip_bare_authority_slash,
    svcb_canonical,
)

logger = structlog.get_logger(__name__)


@dataclass
class PullResult:
    """What happened during a pull-from-server operation."""

    server_records: int  # count read from the wire
    existing_in_db: int  # count already in DB that matched
    imported: int  # count of rows we created
    imported_records: list[dict[str, Any]]  # user-visible list for UI
    skipped_unsupported: int  # count filtered because record_type not imported
    # The rows an ``apply=True`` import added (#2654), so the caller can send
    # them to the group's other agent servers. Empty in preview.
    created_rows: list[DNSRecord] = field(default_factory=list, repr=False)
    # Record ops queued to those other servers (#2654).
    peer_ops: int = 0
    # On-wire records not imported because an op for their name and type is
    # still queued to the server read (#2654): mid-change, so neither side
    # is the truth yet. The next sync looks again.
    skipped_in_flight: int = 0


@dataclass
class PushResult:
    """What happened during a push-to-server operation."""

    candidates: int  # DB rows considered (in DB but not on wire)
    pushed: int  # successfully applied on the wire
    pushed_records: list[dict[str, Any]]  # user-visible list for UI
    push_errors: list[str]  # one entry per failed push (first ~10)
    # #2667 — agent-managed server: the missing rows were queued as record
    # ops for the agent to apply, not applied on the wire by us.
    queued_for_agent: bool = False


@dataclass
class SyncResult:
    """Combined pull + push result returned by ``sync_zone_with_server``."""

    pull: PullResult
    push: PushResult


# Record types we import — matches the IP/host model. Excludes zone-level
# metadata (SOA/apex NS), security-heavy types that need their own editor
# (DNSKEY, DS, RRSIG), and IDN puns.
_IMPORTABLE_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "SRV",
    "PTR",
    "NS",  # non-apex NS only; apex NS is dropped upstream of the importer
    "TLSA",
}

# Every record type the DB/API layer can model (mirrors ``VALID_RECORD_TYPES``
# in the DNS router; kept local so this service doesn't import the router).
# A driver's advertised types are intersected with this set before sync
# uses them — a driver may advertise zone metadata (SOA) that has no
# ``DNSRecord`` representation.
_DB_MODELLED_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "ALIAS",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "PTR",
        "SRV",
        "CAA",
        "TLSA",
        "SSHFP",
        "NAPTR",
        "LOC",
        "LUA",
        "SVCB",
        "HTTPS",
        "DNAME",
    }
)


def _driver_record_types(driver: Any) -> frozenset[str] | None:
    """Record types ``driver`` advertises via ``capabilities()``, or None.

    None means the driver published no usable ``record_types`` list, in
    which case the caller falls back to its legacy hardcoded set rather
    than syncing nothing (or everything).
    """
    try:
        caps = driver.capabilities()
    except Exception:  # noqa: BLE001 — a broken caps probe must not break sync
        return None
    if not isinstance(caps, dict):
        return None
    raw = caps.get("record_types")
    if not raw:
        return None
    return frozenset(str(t).upper() for t in raw)


def _syncable_types(driver: Any, fallback: frozenset[str] | set[str]) -> frozenset[str]:
    """#1533 — the type filter for one sync phase, taken from the server's
    driver capabilities intersected with what the DB models.

    The old hardcoded sets omitted CAA entirely, so CAA drift could never
    be repaired through sync even though every cloud driver advertises
    CAA. Deriving the set per driver also keeps the push phase honest:
    the Windows driver's advertised set is exactly the old push set, so
    Windows pushes gain nothing it cannot serve.
    """
    advertised = _driver_record_types(driver)
    if advertised is None:
        return frozenset(fallback)
    return advertised & _DB_MODELLED_TYPES


# Record types whose value is a DNS name. Same-zone targets are sometimes
# stored relative ("aaa") and sometimes absolute ("aaa.zone.example."). A
# naive string compare would treat those as distinct and import a duplicate.
# ``_normalize_value`` folds both forms into a single canonical shape before
# we key on them.
_NAME_VALUED_TYPES = frozenset({"CNAME", "DNAME", "NS", "PTR", "MX", "SRV"})


def targets_are_relative(server: Any) -> bool:
    """How ``server``'s driver reads a name target with no trailing dot (#1794).

    True for the zone-file drivers: BIND9 and both Technitium drivers
    store and serve the value as a zone file would, so ``a.b`` is
    ``a.b.<zone>.`` and only a trailing dot makes a name absolute. The
    agentless Windows driver without WinRM credentials (Path A) is one too:
    its writes are RFC 2136 updates parsed against the zone origin.
    PowerDNS falls through to True as well. Its HTTP API refuses a dot-less
    target outright, so its agent qualifies one against the zone (#2060) and
    serves exactly what BIND9 would; the record API refuses NEW dot-less
    targets on a PowerDNS group (``app.services.dns.name_targets``). It
    implements no record pull, so drift and sync never reach a comparison
    for it.

    False for the drivers whose API takes the name as given, so a dot-less
    name holding a dot is already absolute: the cloud providers, and Windows
    Path B (``-HostNameAlias 'a.b'``). A single label stays relative on both.

    Both sides of a comparison are read the same way: the wire side is
    absolute (trailing dot) on every driver but the cloud ones, whose
    dot-less pulls are absolute names, so one flag per server is enough.
    """
    driver = getattr(server, "driver", None)
    if driver in CLOUD_DNS_DRIVERS:
        return False
    if driver == "windows_dns":
        return not getattr(server, "credentials_encrypted", None)
    return True


def loc_canonical(rtype: str, value: str) -> str:
    """A LOC / CAA value in dnspython's ``to_text`` form (what the AXFR reader
    prints); the lower-cased text when it does not parse, so a malformed
    value still keys deterministically instead of raising."""
    text = value.strip()
    try:
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype

        return dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text
        ).to_text()
    except Exception:  # noqa: BLE001 - any parse failure falls back to raw text
        return text.lower()


def _normalize_value(rtype: str, value: str, zone_name: str, *, relative_targets: bool) -> str:
    """Canonicalise a record value for dedup.

    * Name-valued types: lowercase, ensure trailing dot, and expand a name
      with no trailing dot against the zone origin. "aaa", "aaa.",
      "AAA.ZONE.LOCAL." and "aaa.zone.local" collapse to "aaa.zone.local."
      once the zone is "zone.local." — except that with
      ``relative_targets`` False a dot-less name holding a dot
      (``aaa.zone.local``) is already absolute, and with it True
      (``a.b``) is ``a.b.zone.local.`` (#1794; see
      :func:`targets_are_relative`).
    * Everything else: stripped + lowercased (fine for A/AAAA/IP literals
      where case doesn't matter either).
    """
    if rtype == "TXT":
        # #1760: a stored value may be bare (``v=spf1 -all``) or quoted, and
        # a server reads back whichever ``txt_value`` picks. Compare the
        # character-strings both stand for, as one canonical presentation
        # form, case kept: TXT content is case-sensitive (DKIM keys,
        # tokens). Not stripped: the renderers serve surrounding spaces.
        return quote_txt(value or "")
    if rtype in ("LOC", "CAA"):
        # #2925: ``7m`` and ``7.00m`` are one record, and so are a bare and
        # a quoted CAA value; the AXFR reader prints dnspython's canonical
        # form, a typed value can be any spelling.
        return loc_canonical(rtype, value or "")
    v = (value or "").strip().lower()
    if rtype in ("A", "AAAA"):
        # Canonical form (#1513): an expanded/upper-case address as
        # typed must key the same as the canonical form on the wire.
        return canonical_ip(v)
    if rtype in ("SVCB", "HTTPS"):
        # #1513: quoting, param order, key case and an in-zone target
        # written relative / absolute are all one record. Given the value
        # as stored, not ``v``: ``ech`` base64 is case-sensitive, and the
        # canonical form already folds what is case-insensitive.
        text = (value or "").strip()
        if not relative_targets:
            text = _absolute_svcb_target(text)
        return svcb_canonical(text, zone_name)
    if rtype == "NAPTR":
        # #1759: the replacement is the last token and a name like any
        # other, so ``web`` / ``web.`` / ``web.<zone>.`` are one record. The
        # other fields compare as the lower-cased text they are.
        head, sep, replacement = v.rpartition(" ")
        if not sep:
            return v
        return f"{head} {_normalize_name(replacement, zone_name, relative_targets)}"
    if rtype == "URI":
        # #1513: fold away the bare-authority trailing slash a server
        # may append when storing the record; a path's slash stays.
        return strip_bare_authority_slash(v)
    if rtype not in _NAME_VALUED_TYPES:
        return v
    return _normalize_name(v, zone_name, relative_targets)


_SVCB_TARGET = re.compile(r"^(\s*\d+\s+)([^\s\"=]+)(?=\s|$)")


def _absolute_svcb_target(text: str) -> str:
    """``text`` with a dot-less SVCB / HTTPS target holding a dot made
    absolute. ``svcb_canonical`` always reads zone-file style; a driver that
    takes the name as given needs ``svc.example.net`` kept absolute."""

    def _dot(m: re.Match[str]) -> str:
        tgt = m.group(2)
        return m.group(1) + (tgt + "." if "." in tgt and not tgt.endswith(".") else tgt)

    return _SVCB_TARGET.sub(_dot, text, count=1)


def _normalize_name(v: str, zone_name: str, relative_targets: bool) -> str:
    """A lower-cased name target in its one comparison form: absolute, with
    its trailing dot. ``@`` and the empty string are the zone."""
    zone = zone_name.lower().rstrip(".") + "."
    # "@" means the zone apex.
    if v == "@" or v == "":
        return zone
    # Already absolute.
    if v.endswith("."):
        return v
    # No trailing dot: relative to the zone, unless the driver takes a name
    # with a dot in it as given (#1794).
    if relative_targets or "." not in v:
        return f"{v}.{zone}".lower()
    return f"{v}.".lower()


#: Identity key for pull/sync dedup: (name, type, canonical value,
#: priority, weight, port) — see :func:`_key`. The structured fields are
#: only non-None for MX / SRV, whose priority (and weight/port) live in
#: their own columns rather than in the value (#1525).
RecordKey = tuple[str, str, str, int | None, int | None, int | None]


def is_apex_ns(r: RecordData | DNSRecord, zone_name: str) -> bool:
    """An NS record at the zone apex (``@`` or the zone's own FQDN)."""
    if r.record_type.upper() != "NS":
        return False
    name = (r.name or "").strip().lower()
    return name in ("@", "", zone_name.strip().lower().rstrip(".") + ".")


def _key(r: RecordData | DNSRecord, zone_name: str, *, relative_targets: bool) -> RecordKey:
    """Identity key for dedup: (name, type, canonical-value, priority,
    weight, port). TTL-only differences don't count — neither does
    relative-vs-FQDN storage for name-valued records.

    The structured fields only participate for MX / SRV (#1525): those
    types carry priority (and, for SRV, weight + port) in their own
    columns, not in the value, so a priority-only edit made directly on
    the server used to compare equal to the DB row and drift / sync
    reported the record as in sync. Every other type keys them as None.
    """
    name = (r.name or "").strip().lower()
    rtype = r.record_type.upper()
    if rtype in ("MX", "SRV"):
        struct: tuple[int | None, int | None, int | None] = (
            getattr(r, "priority", None),
            getattr(r, "weight", None),
            getattr(r, "port", None),
        )
    else:
        struct = (None, None, None)
    return (
        name,
        rtype,
        _normalize_value(rtype, r.value, zone_name, relative_targets=relative_targets),
        *struct,
    )


#: The address record the BIND9 agent writes into every primary zone file,
#: beside the apex ``NS ns1.<zone>`` it also writes, so BIND will load a zone
#: whose NS names an in-zone host (``_write_zone_file`` in
#: agent/dns/spatium_dns_agent/drivers/bind9.py). Keep the two in step.
_AGENT_NS_GLUE = RecordData(name="ns1", record_type="A", value="127.0.0.1")


def without_agent_ns_glue(
    on_wire: list[RecordData],
    server: Any,
    zone_name: str,
    db_keys: set[RecordKey],
) -> list[RecordData]:
    """``on_wire`` minus the agent's own NS glue, when ``server`` is agent-managed BIND9.

    The glue is render apparatus, the same class as the apex SOA and NS the
    AXFR helper already drops: nobody created it, and SpatiumDDI puts it on
    every zone the agent serves. Left in, every drift report on an
    agent-managed BIND9 zone lists ``ns1 A 127.0.0.1`` as extra on the
    server forever, so no zone ever reads in sync, and every sync-with-servers
    imports it into the DB as a record an operator never made — which the
    agent then renders a second time. Found once #920 let the transfer
    through on the QA seed. A zone whose DB really holds that exact record
    keeps it, and it is compared like any other. An operator-run BIND9, or any
    other driver, never had it added, so its records pass through untouched.
    """
    if getattr(server, "driver", None) != "bind9" or getattr(server, "agent_id", None) is None:
        return on_wire
    rel = targets_are_relative(server)
    glue = _key(_AGENT_NS_GLUE, zone_name, relative_targets=rel)
    if glue in db_keys:
        return on_wire
    return [r for r in on_wire if _key(r, zone_name, relative_targets=rel) != glue]


def without_server_apex_ns(
    on_wire: list[RecordData],
    server: Any,
    zone_name: str,
    db_keys: set[RecordKey],
) -> list[RecordData]:
    """``on_wire`` minus the apex NS Technitium writes into every primary zone it creates.

    The agentless ``technitium_api`` pull returns it as an ordinary record
    (``@ NS <the server's own name>``, #1696 / #1809), though it is the same
    class of apparatus as the apex SOA and NS the AXFR helper drops: nobody
    created it. Left in, Sync with Servers imports it as an operator-owned row
    and drift lists it as extra on the server forever, so the zone never reads
    in sync. An apex NS the DB really holds is compared like any other record
    (and so is the Technitium default if the DB holds that exact value); only
    apex NS the DB does not hold is dropped. Every other driver is untouched:
    the AXFR helper already drops the apex for BIND9 and the agent-managed
    Technitium driver, and a delegation below the apex always passes through.
    """
    if getattr(server, "driver", None) != "technitium_api":
        return on_wire
    rel = targets_are_relative(server)
    return [
        r
        for r in on_wire
        if not (
            r.record_type.upper() == "NS"
            and (r.name or "").strip() in ("@", "")
            and _key(r, zone_name, relative_targets=rel) not in db_keys
        )
    ]


async def _fallback_kwargs(db: AsyncSession, server: Any) -> dict[str, Any]:
    """``pull_zone_records`` kwargs naming the server's own pod address to retry
    on a refused connection behind the appliance DNS VIP (#1470); empty when
    it cannot apply."""
    if not transfer_needs_tsig(server):
        return {}
    hosts = transfer_fallback_hosts(server, await resolve_transfer_vip(db))
    return {"fallback_hosts": hosts} if hosts else {}


async def _resolve_primary_and_driver(
    db: AsyncSession, zone: DNSZone, server: Any | None = None
) -> tuple[Any, Any, list[TsigKey | None], str | None]:
    """Shared preamble for both pull and sync: find the zone's primary,
    sanity-check the driver supports pulling records, and resolve the TSIG
    key(s) its transfers have to be signed with.

    The third element is the keys to try, in order, through
    :func:`~app.services.dns.tsig.pull_zone_records_signed`: ``[None]``
    unless :func:`transfer_needs_tsig` says this server's agent granted one.
    Windows Path A, the cloud providers and an operator's own BIND9 all
    authorise the read some other way, and signing for them would break a
    working pull rather than fix a broken one (#734). For an agent-managed
    BIND9 whose group renders views, the key of the view holding this zone's
    copy goes first (#920) — without it the transfer matches no view, or the
    wrong one — and the group key follows for an agent that predates it. The
    fourth element is that view's name, or None.

    ``server`` (#1697) names the one server to sync with when the caller is
    walking a group's servers; it takes the primary's place for everything
    below. Without it the zone's primary is used.
    """
    primary = server if server is not None else await resolve_primary_server(db, zone)
    if primary is None:
        raise ValueError(
            "No primary DNS server is configured in this zone's group. "
            "Mark one of the group's servers as primary first."
        )
    driver = get_driver(primary.driver)
    if not hasattr(driver, "pull_zone_records"):
        raise ValueError(
            f"Driver {primary.driver!r} does not support syncing with the authoritative server."
        )
    if not transfer_needs_tsig(primary):
        return primary, driver, [None], None

    # #734 — the agent grants allow-transfer to the group key, so an
    # unsigned read is REFUSED. No key means the sync cannot work at all;
    # say so up front instead of surfacing a REFUSED that points the
    # operator at a named.conf the agent owns and they cannot edit.
    tsig = await resolve_group_transfer_key(db, primary.group_id)
    if tsig is None:
        raise ValueError(
            f"This zone's group has no TSIG key, so the zone transfer that "
            f"syncing reads from {primary.name!r} cannot be authenticated. "
            "Create a TSIG key on the group and let the agent apply the new "
            "config, then try again."
        )
    view_transfer = await resolve_view_transfer_key(db, zone) if primary.driver == "bind9" else None
    if view_transfer is None:
        return primary, driver, [tsig], None
    view_key, view_name = view_transfer
    return primary, driver, [view_key, tsig], view_name


def _legacy_technitium_txt_keys(
    db_rows: list[DNSRecord], zone_name: str, *, relative_targets: bool
) -> set[RecordKey]:
    """What a ``technitium_api`` server holds for each DB TXT row written
    before #1760, keyed like the wire.

    The old write sent the stored value, trailing dot stripped, as
    Technitium's ``text`` param, which takes it as content cut every 255
    octets: ``"v=spf1 -all"`` was served with its quotes, ``"a" "b"`` as one
    string, ``Hello.`` as ``Hello``. Such a record is the DB row served
    wrong, not a record the operator added on the server, so Sync and pull
    must not import it as a new row: a push (``overwrite=true`` on the
    RRset) replaces it. A row the old write served correctly keys the same
    as the wire and is never in this set.
    """
    out: set[RecordKey] = set()
    for row in db_rows:
        if row.record_type.upper() != "TXT":
            continue
        raw = (row.value or "").rstrip(".").encode("utf-8")
        served = txt_value([raw[i : i + 255] for i in range(0, len(raw), 255)])
        legacy = _key(
            RecordData(name=row.name, record_type="TXT", value=served),
            zone_name,
            relative_targets=relative_targets,
        )
        if legacy != _key(row, zone_name, relative_targets=relative_targets):
            out.add(legacy)
    return out


def _additive_import(
    db: AsyncSession,
    zone: DNSZone,
    on_wire: list[RecordData],
    db_keys: set[RecordKey],
    *,
    apply: bool,
    relative_targets: bool,
    importable_types: frozenset[str] | None = None,
    not_importable: set[RecordKey] | None = None,
    in_flight: Callable[[str, str], bool] | None = None,
) -> PullResult:
    """Create DNSRecord rows for on-wire entries that are missing from DB.

    ``not_importable`` names on-wire records that are a DB row served wrong
    (``_legacy_technitium_txt_keys``): neither existing nor new, so they are
    skipped and left for the push to replace.

    ``in_flight(name, type)`` true means an op for that RRset is still queued
    to the server read (#2654). Such a record is not imported: a record whose
    delete has not reached the server yet would otherwise come straight back
    as a new row and be re-sent to the servers that already dropped it.
    """
    if importable_types is None:
        importable_types = frozenset(_IMPORTABLE_TYPES)
    zone_name = zone.name
    zone_name_no_dot = zone.name.rstrip(".")
    imported_records: list[dict[str, Any]] = []
    created_rows: list[DNSRecord] = []
    skipped_in_flight = 0
    skipped_unsupported = 0
    existing = 0
    imported = 0

    for rec in on_wire:
        rtype = rec.record_type.upper()
        if rtype not in importable_types:
            skipped_unsupported += 1
            continue
        key = _key(rec, zone_name, relative_targets=relative_targets)
        if key in db_keys:
            existing += 1
            continue
        if not_importable and key in not_importable:
            continue
        if in_flight is not None and in_flight(rec.name, rtype):
            skipped_in_flight += 1
            continue

        fqdn = zone_name_no_dot if rec.name == "@" else f"{rec.name}.{zone_name_no_dot}"
        row = DNSRecord(
            zone_id=zone.id,
            name=rec.name,
            fqdn=fqdn,
            record_type=rtype,
            value=rec.value,
            ttl=rec.ttl,
            priority=rec.priority,
            weight=rec.weight,
            port=rec.port,
            auto_generated=False,
            ip_address_id=None,
        )
        if apply:
            db.add(row)
            created_rows.append(row)
        imported += 1
        imported_records.append(
            {
                "name": rec.name,
                "fqdn": fqdn,
                "record_type": rtype,
                "value": rec.value,
                "ttl": rec.ttl,
            }
        )

    return PullResult(
        server_records=len(on_wire),
        existing_in_db=existing,
        imported=imported,
        imported_records=imported_records,
        skipped_unsupported=skipped_unsupported,
        created_rows=created_rows,
        skipped_in_flight=skipped_in_flight,
    )


async def _send_imports_to_peers(
    db: AsyncSession, zone: DNSZone, read_from: Any, result: PullResult
) -> None:
    """Queue every row the import just created to the group's OTHER agent
    servers (#2654).

    The rows describe what ``read_from`` serves, so it is left out. In a
    no-views group an agent only ever receives a record as a record op, so
    without this the other servers of a multi-agent group never served what
    the import found. The ops are per value (``rrset_action="add"``), like
    the import itself: additive, so a value a peer holds that the database
    does not know about is left alone. The push phase cannot cover it: on an
    agent-managed BIND9 server the control plane has no RFC 2136 path of its
    own and the push reports an error per record instead. Agentless groups
    are left to the push phase, which is how they have always been written to.
    """
    if not result.created_rows or is_agentless(getattr(read_from, "driver", "")):
        return
    serial = bump_zone_serial(zone)
    ops = [
        {**learned_record_op("create", row), "target_serial": serial} for row in result.created_rows
    ]
    result.peer_ops = await enqueue_agent_record_ops(
        db, zone, ops, exclude_server_ids={read_from.id}
    )


def _not_importable(primary: Any, db_rows: list[DNSRecord], zone_name: str) -> set[RecordKey]:
    """On-wire keys the import must skip for ``primary``'s driver. Only the
    agentless Technitium driver ever wrote the pre-#1760 TXT form."""
    if getattr(primary, "driver", None) != "technitium_api":
        return set()
    return _legacy_technitium_txt_keys(
        db_rows, zone_name, relative_targets=targets_are_relative(primary)
    )


async def pull_zone_from_server(
    db: AsyncSession,
    zone: DNSZone,
    *,
    apply: bool = True,
) -> PullResult:
    """One-way pull: read the zone from the primary server, additively
    import anything missing from DB. No push phase. Used by the scheduled
    task when the admin wants read-only sync; for the UI "Sync with server"
    button see ``sync_zone_with_server``.
    """
    primary, driver, keys, view_name = await _resolve_primary_and_driver(db, zone)

    on_wire, _key_used = await pull_zone_records_signed(
        driver,
        primary,
        zone.name,
        keys,
        view_name=view_name,
        **await _fallback_kwargs(db, primary),
    )

    db_rows_res = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))
    db_rows = list(db_rows_res.scalars().all())
    rel = targets_are_relative(primary)
    db_keys = {_key(r, zone.name, relative_targets=rel) for r in db_rows}
    on_wire = without_agent_ns_glue(on_wire, primary, zone.name, db_keys)
    on_wire = without_server_apex_ns(on_wire, primary, zone.name, db_keys)

    result = _additive_import(
        db,
        zone,
        on_wire,
        db_keys,
        apply=apply,
        relative_targets=rel,
        importable_types=_syncable_types(driver, _IMPORTABLE_TYPES),
        not_importable=_not_importable(primary, db_rows, zone.name),
        in_flight=(await server_ops_touching(db, zone, primary, None)).queued_at,
    )
    if apply and result.imported:
        await db.flush()
        await _send_imports_to_peers(db, zone, primary, result)

    logger.info(
        "dns.pull_from_server",
        zone=zone.name,
        server=str(primary.id),
        driver=primary.driver,
        on_wire=len(on_wire),
        existing=result.existing_in_db,
        imported=result.imported,
        skipped=result.skipped_unsupported,
        mode="apply" if apply else "preview",
    )
    return result


# Record types the push phase will send to the server via apply_record_change.
# Legacy fallback only (#1533): the live filter is derived per server from
# the driver's advertised ``capabilities()["record_types"]`` — see
# ``_syncable_types``. This set mirrors the Windows driver's
# _SUPPORTED_RECORD_TYPES, which is what the derivation yields for Windows
# anyway; it survives solely for a driver that publishes no record_types.
_PUSHABLE_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS", "TLSA"})


async def _queue_for_agent(
    db: AsyncSession,
    server: Any,
    zone: DNSZone,
    rows: list[DNSRecord],
    payloads: list[dict[str, Any]],
    target_serial: int,
) -> PushResult:
    """Agent-managed server: hand the missing rows to its record-op queue (#2667).

    The control plane has no RFC 2136 / driver path to an agent-managed
    server (the agent applies ops against loopback ``named``), so calling
    ``apply_record_changes`` failed every record. Ops are queued for THIS
    server only — Sync with Servers is per-server. A row whose identical
    create is already pending / in flight is not queued twice.
    """
    queued = (
        (
            await db.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.server_id == server.id,
                    DNSRecordOp.zone_id == zone.id,
                    DNSRecordOp.state.in_(QUEUED_OP_STATES),
                    DNSRecordOp.op == "create",
                )
            )
        )
        .scalars()
        .all()
    )
    already = {
        (
            str((o.record or {}).get("name", "")),
            str((o.record or {}).get("type", "")).upper(),
            str((o.record or {}).get("value", "")),
        )
        for o in queued
    }
    new_ops: list[DNSRecordOp] = []
    pushed_records: list[dict[str, Any]] = []
    for row, payload in zip(rows, payloads, strict=True):
        rec = payload["record"]
        pushed_records.append(
            {
                "name": row.name,
                "fqdn": row.fqdn,
                "record_type": row.record_type.upper(),
                "value": row.value,
                "ttl": row.ttl,
            }
        )
        if (rec["name"], rec["type"], rec["value"]) in already:
            continue
        new_ops.append(
            DNSRecordOp(
                server_id=server.id,
                zone_id=zone.id,
                zone_name=zone.name,
                op="create",
                record=payload["record"],
                target_serial=target_serial,
                state="pending",
            )
        )
    if new_ops:
        db.add_all(new_ops)
        await db.flush()
        collect_wake(dns_server_channel(server.id))
    return PushResult(
        candidates=len(rows),
        pushed=len(pushed_records),
        pushed_records=pushed_records,
        push_errors=[],
        queued_for_agent=True,
    )


async def _additive_push(
    db: AsyncSession,
    primary: Any,
    driver: Any,
    zone: DNSZone,
    on_wire: list[RecordData],
    db_rows: list[DNSRecord],
    *,
    apply: bool,
    skip_apex_ns: bool = False,
) -> PushResult:
    """For every DB row whose key isn't on the wire, send a create op via
    the driver. Errors are collected, not raised, so one bad record
    doesn't abort the whole sync.

    Dispatch uses ``apply_record_changes`` (plural) so agentless drivers
    (Windows DNS) can ship the whole batch in one WinRM round trip
    instead of one per record. The ABC default falls back to a
    sequential loop for agent-based drivers (BIND9) where the control
    plane never calls the record writer anyway.
    """
    rel = targets_are_relative(primary)
    on_wire_keys = {_key(r, zone.name, relative_targets=rel) for r in on_wire}

    pushed_records: list[dict[str, Any]] = []
    push_errors: list[str] = []

    target_serial = bump_zone_serial(zone) if apply else 0

    # Build the candidate list — DB rows whose (name, type, value) isn't
    # already on the wire. Keeping this as a list (not a generator) so we
    # can zip the driver's per-op results back onto the source rows by
    # index after dispatch.
    pushable_types = _syncable_types(driver, _PUSHABLE_TYPES)
    candidate_rows: list[DNSRecord] = []
    for row in db_rows:
        rtype = row.record_type.upper()
        if rtype not in pushable_types:
            continue
        # #1893 — the caller found the read cannot see the apex NS; see
        # ``sync_zone_with_server``.
        if skip_apex_ns and is_apex_ns(row, zone.name):
            continue
        if _key(row, zone.name, relative_targets=rel) in on_wire_keys:
            continue
        candidate_rows.append(row)

    candidates = len(candidate_rows)

    if not apply:
        for row in candidate_rows:
            pushed_records.append(
                {
                    "name": row.name,
                    "fqdn": row.fqdn,
                    "record_type": row.record_type.upper(),
                    "value": row.value,
                    "ttl": row.ttl,
                }
            )
        return PushResult(
            candidates=candidates,
            pushed=candidates,
            pushed_records=pushed_records,
            push_errors=push_errors,
        )

    # Each op carries the complete DB set at its (name, type), as the record
    # op path does (#783). Without it a driver that writes a whole RRset
    # (technitium_api ``overwrite=true``, Windows) replaces the set with the
    # one pushed value, so pushing a TXT that is missing or served wrong
    # (#1760) retires its in-sync siblings, and the next Sync pushes those
    # back over it. The pulled rows were flushed above, so the set includes
    # them.
    payloads: list[dict[str, Any]] = [
        {
            "op": "create",
            "record": {
                "name": row.name,
                "type": row.record_type.upper(),
                "value": row.value,
                "ttl": row.ttl,
                "priority": row.priority,
                "weight": row.weight,
                "port": row.port,
            },
        }
        for row in candidate_rows
    ]
    await stamp_rrsets_for_ops(db, zone, payloads)
    changes: list[RecordChange] = [
        RecordChange(
            op="create",
            zone_name=zone.name,
            record=RecordData(
                name=row.name,
                record_type=row.record_type.upper(),
                value=row.value,
                ttl=row.ttl,
                priority=row.priority,
                weight=row.weight,
                port=row.port,
            ),
            target_serial=target_serial,
            rrset=rrset_from_payload(payload["record"]),
        )
        for row, payload in zip(candidate_rows, payloads, strict=True)
    ]

    if not changes:
        return PushResult(
            candidates=0, pushed=0, pushed_records=pushed_records, push_errors=push_errors
        )

    if not is_agentless(primary.driver):
        return await _queue_for_agent(db, primary, zone, candidate_rows, payloads, target_serial)

    try:
        results = await driver.apply_record_changes(primary, changes)
    except Exception as exc:  # noqa: BLE001 — whole-batch failure, surface once
        logger.warning(
            "dns.push_drift_batch_failed",
            zone=zone.name,
            server=str(primary.id),
            count=len(changes),
            error=str(exc),
        )
        return PushResult(
            candidates=candidates,
            pushed=0,
            pushed_records=pushed_records,
            push_errors=[f"batch failed: {exc}"],
        )

    pushed = 0
    for row, result in zip(candidate_rows, results, strict=True):
        rtype = row.record_type.upper()
        if result.ok:
            pushed += 1
            pushed_records.append(
                {
                    "name": row.name,
                    "fqdn": row.fqdn,
                    "record_type": rtype,
                    "value": row.value,
                    "ttl": row.ttl,
                }
            )
            continue
        err = f"{row.name} {rtype}: {result.error}"
        logger.warning(
            "dns.push_drift_failed",
            zone=zone.name,
            server=str(primary.id),
            name=row.name,
            record_type=rtype,
            error=result.error,
        )
        if len(push_errors) < 10:
            push_errors.append(err)

    return PushResult(
        candidates=candidates,
        pushed=pushed,
        pushed_records=pushed_records,
        push_errors=push_errors,
    )


async def restore_zone_records_to_server(
    db: AsyncSession, server: Any, driver: Any, zone: DNSZone
) -> PushResult:
    """Push ``zone``'s records back to one agentless ``server`` (#1613).

    Used when a zone delete is rolled back on a server where the delete
    had already succeeded: re-creating the zone there gives back an empty
    zone, and an empty zone that answers is worse than either outcome the
    operator asked for. So the records go back too, through the same
    additive push Sync with Servers uses — the zone is read first and only
    what is missing is sent, so whatever the provider created with the zone
    (apex NS / SOA) is not pushed a second time.

    A zone already in the trash (the purge sweep) carries records that were
    soft-deleted with it; they are part of what the server was serving, so
    those are restored rather than none. A record trashed separately before
    the zone keeps its own batch and stays gone.

    Never raises for a record-level failure: the caller reports what the
    result says, which is the whole point of not claiming a clean rollback.
    """
    stmt = select(DNSRecord).where(DNSRecord.zone_id == zone.id)
    if zone.deleted_at is not None and zone.deletion_batch_id is not None:
        stmt = stmt.where(DNSRecord.deletion_batch_id == zone.deletion_batch_id).execution_options(
            include_deleted=True
        )
    rows = list((await db.execute(stmt)).scalars().all())

    on_wire: list[RecordData] = []
    if hasattr(driver, "pull_zone_records"):
        try:
            on_wire = await driver.pull_zone_records(server, zone.name, tsig=None)
        except Exception as exc:  # noqa: BLE001 — push everything rather than nothing
            logger.warning(
                "dns.zone_restore_records_pull_failed",
                zone=zone.name,
                server=str(server.id),
                error=str(exc) or type(exc).__name__,
            )
    return await _additive_push(db, server, driver, zone, on_wire, rows, apply=True)


async def sync_zone_with_server(
    db: AsyncSession,
    zone: DNSZone,
    *,
    apply: bool = True,
    server: Any | None = None,
) -> SyncResult:
    """Bi-directional additive sync between DB and the zone's primary server.

    ``server`` (#1697) syncs with that server instead of the primary, so a
    group-level Sync walks each server's own copy rather than the primary's
    once per server.

    1. AXFR the server once.
    2. Pull phase: import on-wire records missing from DB.
    3. Push phase: for every DB row not on the wire, send an RFC 2136 add.

    Never deletes. Returns counts for both phases so the UI can surface
    them in one pass.
    """
    primary, driver, keys, view_name = await _resolve_primary_and_driver(db, zone, server)

    on_wire, _key_used = await pull_zone_records_signed(
        driver,
        primary,
        zone.name,
        keys,
        view_name=view_name,
        **await _fallback_kwargs(db, primary),
    )

    # Snapshot DB state BEFORE the pull so we can compute the push set
    # against the "old" DB. We still import new rows from the pull into
    # the DB first; those obviously live on the wire so they never need
    # pushing — they'd be no-ops on the server anyway, but filtering them
    # out keeps the push count honest.
    db_rows_res = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))
    db_rows = list(db_rows_res.scalars().all())
    rel = targets_are_relative(primary)
    db_keys = {_key(r, zone.name, relative_targets=rel) for r in db_rows}
    # #1893 — a read that carries no apex NS at all (the AXFR helper drops it
    # by design) cannot tell whether the server has the stored one, so every
    # run read it as missing and pushed it again (on agent-managed BIND9 the
    # control-plane push then fails for want of a TSIG key, every run). Every
    # zone has an apex NS set, so an empty one means the read could not see
    # it: the stored apex NS stays out of the push set. Decided on the read
    # as returned, before the filters below: ``without_server_apex_ns`` drops
    # a ``technitium_api`` server's own apex NS, and that read CAN see the
    # apex, so a stored apex NS the server lacks is still pushed there. A
    # read that carries one (a provider's) is compared like any record, and
    # delegations below the apex are always compared.
    read_sees_apex_ns = any(is_apex_ns(r, zone.name) for r in on_wire)
    on_wire = without_agent_ns_glue(on_wire, primary, zone.name, db_keys)
    on_wire = without_server_apex_ns(on_wire, primary, zone.name, db_keys)

    pull_result = _additive_import(
        db,
        zone,
        on_wire,
        db_keys,
        apply=apply,
        relative_targets=rel,
        importable_types=_syncable_types(driver, _IMPORTABLE_TYPES),
        not_importable=_not_importable(primary, db_rows, zone.name),
        in_flight=(await server_ops_touching(db, zone, primary, None)).queued_at,
    )
    if apply and pull_result.imported:
        await db.flush()
        await _send_imports_to_peers(db, zone, primary, pull_result)

    push_result = await _additive_push(
        db,
        primary,
        driver,
        zone,
        on_wire,
        db_rows,
        apply=apply,
        skip_apex_ns=not read_sees_apex_ns,
    )

    logger.info(
        "dns.sync_with_server",
        zone=zone.name,
        server=str(primary.id),
        driver=primary.driver,
        on_wire=len(on_wire),
        imported=pull_result.imported,
        pushed=push_result.pushed,
        push_errors=len(push_result.push_errors),
        mode="apply" if apply else "preview",
    )
    return SyncResult(pull=pull_result, push=push_result)
