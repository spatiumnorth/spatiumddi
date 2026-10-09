"""Phase 1 parity — what SpatiumDDI holds vs what Windows is serving *now* (#756).

The importers (#128 / #129) prove nothing about the present: they loaded a
snapshot, and the Windows server has kept running since. Before anyone reroutes
traffic, the operator has to be able to say "these two answer the same". That is
what this module computes, per zone and per scope.

It is deliberately close to, but not the same as, the #61 drift report:

* #61 keys on ``(name, type, value)`` and so reports a *changed* record as a
  missing+extra pair. During a migration that reads as two problems when it is
  one decision, so parity buckets on ``(name, type)`` first and pairs the
  leftovers into a single :data:`~app.services.cutover.canonical.ParityDifference`
  with ``classification="value_mismatch"``.
* #61 answers "is my managed estate converged". Parity answers "may I stop
  serving this from Windows", so a record only Windows has is classified by
  *why* it is only there — ``drifted_since_import`` when the SpatiumDDI object
  carries import provenance, ``never_imported`` when it does not.

Identity and value normalisation are reused verbatim from
:func:`app.services.dns.pull_from_server._key`, so relative-vs-FQDN storage and
TTL-only differences do not register as parity failures — the same rule the
additive sync and the drift report already apply. TTLs are the pre-flight step's
business (:mod:`app.services.cutover.preflight`), not parity's.

Nothing here raises for a per-object failure: an unreachable server or a
PowerShell error comes back as ``status="error"`` on the report, because a
whole-plan parity run fans out over every item and one dead host must not take
the rest of the report with it.

**Session note for callers that fan out.** Both entry points read from ``db``
*before* they touch the network, and never afterwards. Running several of them
concurrently against the same :class:`~sqlalchemy.ext.asyncio.AsyncSession` is
still unsafe (one session, one operation at a time) — a whole-plan run should
collect the DB-side inputs it needs first, or await these sequentially.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver as get_dhcp_driver
from app.drivers.dns import get_driver as get_dns_driver
from app.drivers.dns._axfr import _DNSSEC_ARTEFACTS
from app.drivers.dns.base import RecordData
from app.drivers.dns.windows import _PULL_RECORD_TYPES
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServer, DNSZone
from app.models.ipam import Subnet
from app.services.cutover.canonical import ParityDifference, ParityReport
from app.services.dhcp_import.options import normalise_mac
from app.services.dns.pull_from_server import _key

logger = structlog.get_logger(__name__)


# Carried verbatim from #61 (``app.services.dns.drift``): the same caveats apply
# to a parity pull, for the same reason — an AXFR is addressed by zone name, not
# by view, so under split horizon the wire may be answering from a different view
# than the row we are diffing.
_SPLIT_HORIZON_ZONE_WARNING = (
    "This zone belongs to a DNS view. A zone transfer is answered by "
    "whichever view matches the control plane's source address, so "
    "differences below may reflect a different view rather than real drift."
)
_SPLIT_HORIZON_RECORD_WARNING = (
    "Some records in this zone are scoped to a specific DNS view and are "
    "only served to clients matching it. They may appear as missing here "
    "even when the server is correct."
)


def _comparable_record(source_server: DNSServer, name: str, rtype: str) -> bool:
    """Can the source's read path see this record type at all?

    ``WindowsDNSDriver.pull_zone_records`` picks its path from
    ``bool(server.credentials_encrypted)`` alone — ``capabilities()`` is a
    static dict and says nothing about it — and the two paths are blind to
    different things:

    * **Path B** (WinRM ``Get-DnsServerResourceRecord``) maps only
      ``_PULL_RECORD_TYPES``. Anything else reaches the parser as a raw
      ``.ToString()`` it refuses to guess at, so a CAA / TLSA / SSHFP / NAPTR /
      LOC row in the database would read as "Windows does not have it" purely
      because the PowerShell walker cannot emit it.
    * **Path A** (AXFR) has no type allowlist but strips DNSSEC artefacts,
      which the signing daemon mints and rotates and which never exist as
      SpatiumDDI records anyway.

    Both paths also drop the SOA and the apex NS set, which SpatiumDDI manages
    as zone-level fields rather than as records.

    Excluding these from the diff — rather than letting them fall out as
    ``intentionally_diverged`` — is the difference between a parity report an
    operator can act on and one that sends them to "fix" records that are
    already correct on both sides. They are counted into ``not_compared`` and
    surfaced as a warning instead.
    """
    if rtype == "SOA":
        return False
    if rtype == "NS" and name in ("", "@"):
        return False
    if rtype in _DNSSEC_ARTEFACTS:
        return False
    if getattr(source_server, "credentials_encrypted", None):
        return rtype in _PULL_RECORD_TYPES
    return True


# ── shared helpers ─────────────────────────────────────────────────────


def _display_name(raw: str | None) -> str:
    """Record label for the report — apex records read better as ``@``."""
    name = (raw or "").strip()
    return name or "@"


def normalise_ip(raw: Any) -> str:
    """Canonicalise an address for comparison, tolerating junk.

    Postgres ``INET`` and PowerShell both hand back dotted-quad strings, but
    they can disagree on IPv6 zero-compression, so both sides go through
    :mod:`ipaddress`. A value that will not parse is compared as lowercased
    text rather than dropped — a malformed address on one side is exactly the
    kind of difference the operator wants to see.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def normalise_option_value(value: Any) -> str:
    """Render a DHCP option value as one stable comparable string.

    Windows emits every option as a PowerShell array; the importer collapses
    single-element arrays to scalars for the options Kea treats as scalar
    (:func:`app.services.dhcp_import.options.coerce_option_value`). So the same
    configuration legitimately arrives as ``["corp.local"]`` on one side and
    ``"corp.local"`` on the other. Flattening both to a joined string makes that
    a non-difference while a genuinely different list still compares unequal.

    Case is preserved: ``bootfile-name`` and ``tftp-server-name`` are passed to
    case-sensitive TFTP servers, so folding case here would hide a real break.
    """
    if value is None:
        return ""
    items = list(value) if isinstance(value, list | tuple) else [value]
    return ", ".join(str(v).strip() for v in items)


# ── DNS ────────────────────────────────────────────────────────────────


def _bucket_records(
    rows: list[Any], zone_name: str
) -> dict[tuple[str, str], list[tuple[Any, Any]]]:
    """Group records by ``(name, type)``, carrying each one's canonical value.

    The identity tuple from :func:`app.services.dns.pull_from_server._key`
    is split: the first two elements form the bucket, the rest — the
    normalised value plus, for MX / SRV, the structured priority / weight /
    port (#1525) — is the identity used for multiset matching inside it.
    """
    buckets: dict[tuple[str, str], list[tuple[Any, Any]]] = {}
    for row in rows:
        name, rtype, *rest = _key(row, zone_name)
        buckets.setdefault((name, rtype), []).append((tuple(rest), row))
    return buckets


def _split_bucket(
    wire_items: list[tuple[Any, Any]], db_items: list[tuple[Any, Any]]
) -> tuple[int, list[Any], list[Any]]:
    """Multiset-match one ``(name, type)`` bucket.

    Returns ``(matched_count, wire_only, db_only)``. Duplicates are handled by
    count rather than by set membership, so a zone with three A records at the
    same name where Windows has four reports exactly one leftover, not zero.
    """
    remaining: Counter[Any] = Counter(value for value, _ in db_items)

    matched = 0
    wire_only: list[Any] = []
    for value, row in wire_items:
        if remaining[value] > 0:
            remaining[value] -= 1
            matched += 1
        else:
            wire_only.append(row)

    # Whatever is still counted in ``remaining`` had no partner on the wire.
    # Walk the DB rows in their original order and take that many of each value
    # so the leftovers are real rows (with ids), not just value strings.
    db_only: list[Any] = []
    for value, row in db_items:
        if remaining[value] > 0:
            remaining[value] -= 1
            db_only.append(row)

    return matched, wire_only, db_only


def _windows_only_class(zone: DNSZone) -> str:
    """Why does Windows have a record SpatiumDDI does not?

    Provenance is the only evidence available: if the zone was imported, the
    object came across once and Windows has moved on since (``drifted``). If it
    was not, nothing drifted — it was simply never brought over.
    """
    return "drifted_since_import" if zone.import_source else "never_imported"


async def compute_dns_parity(
    db: AsyncSession,
    *,
    source_server: DNSServer,
    zone: DNSZone,
    source_zone_name: str,
) -> ParityReport:
    """Diff ``zone``'s records against what ``source_server`` serves live.

    ``source_zone_name`` is the zone's name on the *Windows* side (no trailing
    dot required); it can differ in trailing-dot form from ``zone.name``, which
    is what the value normaliser uses as the origin for both sides.

    Never raises for a source-side failure — an unknown driver, a driver that
    cannot pull records, or a WinRM/PowerShell error all come back as
    ``status="error"`` with the message.
    """
    report = ParityReport(kind="dns_zone", source_ref=source_zone_name)

    db_rows = list(
        (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars().all()
    )

    if zone.view_id is not None:
        report.warnings.append(_SPLIT_HORIZON_ZONE_WARNING)
    elif any(r.view_id is not None for r in db_rows):
        report.warnings.append(_SPLIT_HORIZON_RECORD_WARNING)

    try:
        driver = get_dns_driver(source_server.driver)
    except ValueError as exc:
        report.status = "error"
        report.error = str(exc)
        return report

    if not hasattr(driver, "pull_zone_records"):
        report.status = "error"
        report.error = (
            f"DNS driver {source_server.driver!r} cannot read live records, so parity "
            "against it cannot be established. Only the Windows DNS driver "
            "(and any driver implementing pull_zone_records) is supported as a "
            "cutover source."
        )
        return report

    try:
        on_wire: list[RecordData] = await driver.pull_zone_records(source_server, source_zone_name)
    except Exception as exc:  # noqa: BLE001 — per-item; a whole-plan run fans these out
        report.status = "error"
        report.error = str(exc)
        logger.warning(
            "cutover.parity.dns_pull_failed",
            zone=zone.name,
            source_zone=source_zone_name,
            server=str(source_server.id),
            driver=source_server.driver,
            error=str(exc),
        )
        return report

    wire_buckets = _bucket_records(list(on_wire), zone.name)
    db_buckets = _bucket_records(db_rows, zone.name)
    windows_only_class = _windows_only_class(zone)

    # An empty pull is NOT proof of an empty zone. ``_parse_records`` logs
    # ``windows_dns_record_parse_failed`` and returns ``[]`` on unparseable
    # output — indistinguishable from a zone with no records (contrast the DHCP
    # lease parser, which raises, #426). Reporting every DB row as
    # "SpatiumDDI-only" off the back of a transient PowerShell failure is the
    # worst possible answer, so the report says it could not be established
    # instead.
    if not on_wire and db_rows:
        report.status = "unverified"
        report.error = (
            f"The pull from {source_server.name} returned no records at all while "
            f"SpatiumDDI holds {len(db_rows)}. That is either a genuinely empty zone "
            "on Windows or a failed read that came back empty — the two are "
            "indistinguishable from here. Re-run the parity check, and check the "
            "server logs for a record-parse warning before trusting a clean result."
        )
        return report

    not_compared = 0
    uncomparable_types: set[str] = set()

    for bucket in sorted(set(wire_buckets) | set(db_buckets)):
        name, rtype = bucket
        label = _display_name(name)

        if not _comparable_record(source_server, name, rtype):
            not_compared += len(wire_buckets.get(bucket, [])) + len(db_buckets.get(bucket, []))
            uncomparable_types.add(rtype)
            continue
        matched, wire_only, db_only = _split_bucket(
            wire_buckets.get(bucket, []), db_buckets.get(bucket, [])
        )
        report.in_sync += matched

        # Pair leftovers positionally: the same name+type on both sides with
        # different data is one changed record, not one addition plus one
        # removal. Order within a bucket is arbitrary, so the pairing is too —
        # it only decides which value lands opposite which, and every leftover
        # is reported either way.
        paired = min(len(wire_only), len(db_only))
        for wire_row, db_row in zip(wire_only[:paired], db_only[:paired], strict=True):
            report.differences.append(
                ParityDifference(
                    classification="value_mismatch",
                    name=label,
                    record_type=rtype,
                    detail=(
                        f"{label} {rtype} exists on both sides with different data. "
                        "Decide which value is correct before cutting over."
                    ),
                    source_value=wire_row.value,
                    target_value=db_row.value,
                )
            )

        for wire_row in wire_only[paired:]:
            if windows_only_class == "drifted_since_import":
                detail = (
                    f"{label} {rtype} is served by Windows but missing from SpatiumDDI. "
                    f"This zone was imported from {zone.import_source!r}, so it was added "
                    "or changed on Windows afterwards — re-import or add it here."
                )
            else:
                detail = (
                    f"{label} {rtype} is served by Windows but missing from SpatiumDDI. "
                    "This zone carries no import provenance, so the record was never "
                    "brought across — add it here before cutting over."
                )
            report.differences.append(
                ParityDifference(
                    classification=windows_only_class,  # type: ignore[arg-type]
                    name=label,
                    record_type=rtype,
                    detail=detail,
                    source_value=wire_row.value,
                    target_value=None,
                )
            )

        for db_row in db_only[paired:]:
            report.differences.append(
                ParityDifference(
                    classification="intentionally_diverged",
                    name=label,
                    record_type=rtype,
                    detail=(
                        f"{label} {rtype} exists in SpatiumDDI but is not served by "
                        "Windows. Usually an addition made here after the import; "
                        "it will start being served at cutover."
                    ),
                    source_value=None,
                    target_value=db_row.value,
                )
            )

    report.not_compared = not_compared
    if not_compared:
        report.warnings.append(
            f"{not_compared} record(s) of type "
            f"{', '.join(sorted(uncomparable_types))} were not compared: the source "
            "server's read path cannot report them, so a difference here would be an "
            "artefact of the reader rather than real. Verify those types by hand."
        )

    logger.info(
        "cutover.parity.dns",
        zone=zone.name,
        source_zone=source_zone_name,
        server=str(source_server.id),
        on_wire=len(on_wire),
        in_db=len(db_rows),
        in_sync=report.in_sync,
        not_compared=not_compared,
        differences=report.difference_count,
    )
    return report


# ── DHCP ───────────────────────────────────────────────────────────────


def match_source_scope(
    scopes: list[dict[str, Any]], *, subnet_cidr: str, source_scope_id: str
) -> dict[str, Any] | None:
    """Find the Windows scope backing this managed scope.

    CIDR first — it is the identity the DHCP importer already reconciles on —
    then the scope id (its network address), which is what the plan item stores
    as ``source_ref`` and the only handle available if IPAM's prefix length was
    edited after the import.

    Public because :mod:`app.services.cutover.readiness` matches the same live
    ``get_scopes()`` payload when it re-evaluates blockers, and the two must not
    be able to disagree about which Windows scope an item refers to.
    """
    # An empty ``subnet_cidr`` matches nothing. Callers legitimately pass ""
    # when the item has no linked scope or its IPAM subnet is gone
    # (``readiness._refresh_dhcp_blockers``), and without this guard that empty
    # string would equal any pulled scope whose own ``subnet_cidr`` is absent —
    # returning an arbitrary Windows scope as the item's source and suppressing
    # the ``source_scope_missing`` hard block that should have fired.
    want_cidr = (subnet_cidr or "").strip().lower()
    if want_cidr:
        for entry in scopes:
            if str(entry.get("subnet_cidr") or "").strip().lower() == want_cidr:
                return entry
    want_id = normalise_ip(source_scope_id)
    if want_id:
        for entry in scopes:
            if normalise_ip(entry.get("scope_id")) == want_id:
                return entry
    return None


def _pool_key(start: Any, end: Any, pool_type: Any) -> tuple[str, str, str]:
    return (normalise_ip(start), normalise_ip(end), str(pool_type or "dynamic").strip().lower())


def _diff_dhcp_pools(
    report: ParityReport,
    *,
    source: dict[str, Any],
    pools: list[DHCPPool],
    windows_only_class: str,
) -> None:
    """Compare the pool set as ``(start, end, type)`` triples."""
    if not source.get("pools_ok", True):
        # #620: the driver could not enumerate exclusions, so its pool list is
        # short by an unknown amount. Reporting the difference would invent
        # drift out of a transient PowerShell failure.
        report.warnings.append(
            "Exclusion ranges could not be enumerated on the Windows scope, so "
            "pools were not compared. Re-run the parity check."
        )
        return

    wire = {
        _pool_key(p.get("start_ip"), p.get("end_ip"), p.get("pool_type"))
        for p in source.get("pools") or []
    }
    ours = {_pool_key(p.start_ip, p.end_ip, p.pool_type) for p in pools}

    report.in_sync += len(wire & ours)

    for start, end, ptype in sorted(wire - ours):
        report.differences.append(
            ParityDifference(
                classification=windows_only_class,  # type: ignore[arg-type]
                name="pool",
                detail=(
                    f"Windows serves a {ptype} range {start}–{end} that this scope "
                    "does not have. Clients in it would stop being served at cutover."
                ),
                source_value=f"{start}-{end} ({ptype})",
                target_value=None,
            )
        )
    for start, end, ptype in sorted(ours - wire):
        report.differences.append(
            ParityDifference(
                classification="intentionally_diverged",
                name="pool",
                detail=(
                    f"This scope has a {ptype} range {start}–{end} that Windows does "
                    "not. It starts being served at cutover."
                ),
                source_value=None,
                target_value=f"{start}-{end} ({ptype})",
            )
        )


def _diff_dhcp_reservations(
    report: ParityReport,
    *,
    source: dict[str, Any],
    statics: list[DHCPStaticAssignment],
    windows_only_class: str,
) -> None:
    """Compare reservations keyed by MAC — the identity Windows itself uses."""
    if not source.get("statics_ok", True):
        # Same #620 reasoning as pools: an enumeration failure is not an empty
        # reservation list, and must not be reported as one.
        report.warnings.append(
            "Reservations could not be enumerated on the Windows scope, so they "
            "were not compared. Re-run the parity check."
        )
        return

    wire: dict[str, tuple[str, str]] = {}
    for entry in source.get("statics") or []:
        mac = normalise_mac(entry.get("mac_address"))
        if mac is None:
            continue
        wire[mac] = (
            normalise_ip(entry.get("ip_address")),
            str(entry.get("hostname") or "").strip(),
        )

    ours: dict[str, tuple[str, str]] = {}
    for row in statics:
        mac = normalise_mac(row.mac_address)
        if mac is None:
            continue
        ours[mac] = (normalise_ip(row.ip_address), (row.hostname or "").strip())

    for mac in sorted(set(wire) & set(ours)):
        wire_ip, wire_host = wire[mac]
        our_ip, our_host = ours[mac]
        if wire_ip == our_ip and wire_host.lower() == our_host.lower():
            report.in_sync += 1
            continue
        report.differences.append(
            ParityDifference(
                classification="value_mismatch",
                name=mac,
                detail=(
                    f"Reservation for {mac} differs. A client honouring the wrong one "
                    "changes address at cutover."
                ),
                source_value=f"{wire_ip} {wire_host}".strip(),
                target_value=f"{our_ip} {our_host}".strip(),
            )
        )

    for mac in sorted(set(wire) - set(ours)):
        wire_ip, wire_host = wire[mac]
        report.differences.append(
            ParityDifference(
                classification=windows_only_class,  # type: ignore[arg-type]
                name=mac,
                detail=(
                    f"Windows reserves {wire_ip} for {mac}; this scope does not. The "
                    "client would get a pool address at cutover unless the lease "
                    "handover carries it across."
                ),
                source_value=f"{wire_ip} {wire_host}".strip(),
                target_value=None,
            )
        )
    for mac in sorted(set(ours) - set(wire)):
        our_ip, our_host = ours[mac]
        report.differences.append(
            ParityDifference(
                classification="intentionally_diverged",
                name=mac,
                detail=f"This scope reserves {our_ip} for {mac}; Windows does not.",
                source_value=None,
                target_value=f"{our_ip} {our_host}".strip(),
            )
        )


def _diff_dhcp_options(
    report: ParityReport,
    *,
    source: dict[str, Any],
    scope: DHCPScope,
    windows_only_class: str,
) -> None:
    """Compare scope options by canonical name."""
    wire = {str(k): normalise_option_value(v) for k, v in (source.get("options") or {}).items()}
    ours = {str(k): normalise_option_value(v) for k, v in (scope.options or {}).items()}

    for key in sorted(set(wire) & set(ours)):
        if wire[key] == ours[key]:
            report.in_sync += 1
            continue
        report.differences.append(
            ParityDifference(
                classification="value_mismatch",
                name=key,
                detail=f"Scope option {key!r} differs between Windows and SpatiumDDI.",
                source_value=wire[key],
                target_value=ours[key],
            )
        )
    for key in sorted(set(wire) - set(ours)):
        report.differences.append(
            ParityDifference(
                classification=windows_only_class,  # type: ignore[arg-type]
                name=key,
                detail=(
                    f"Windows hands out scope option {key!r}; this scope does not. "
                    "Clients stop receiving it at cutover."
                ),
                source_value=wire[key],
                target_value=None,
            )
        )
    for key in sorted(set(ours) - set(wire)):
        report.differences.append(
            ParityDifference(
                classification="intentionally_diverged",
                name=key,
                detail=f"This scope hands out option {key!r}; Windows does not.",
                source_value=None,
                target_value=ours[key],
            )
        )


def _diff_dhcp_activation(
    report: ParityReport, *, source_active: bool, target_active: bool
) -> None:
    """Report the activation posture — as a warning, never as a difference.

    ``is_active`` is migration *state*, not configuration. Through the whole
    parallel-run phase the two sides are deliberately never both active (an
    active managed scope is a hard blocker in
    :mod:`app.services.cutover.readiness`, precisely so the two never answer at
    once), so a mismatch here is the expected posture rather than drift.
    Recording it as a ``ParityDifference`` would make ``is_parity`` structurally
    unreachable and permanently trip the ``parity_differences`` blocker.
    """
    if source_active == target_active:
        report.in_sync += 1
        return
    if source_active and not target_active:
        report.warnings.append(
            "The Windows scope is active and this scope is not. That is the expected "
            "parallel-run posture, not a difference."
        )
        return
    report.warnings.append(
        "This scope is active and the Windows scope is not — the switch appears to "
        "have already happened. Verify before running it again."
    )


async def compute_dhcp_parity(
    db: AsyncSession,
    *,
    source_server: DHCPServer,
    scope: DHCPScope,
    source_scope_id: str,
) -> ParityReport:
    """Diff ``scope`` against the live Windows scope it was imported from.

    Compares lease time, activation posture, the pool set, reservations, and
    scope options. Like the DNS side, a source-side failure comes back as
    ``status="error"``; a scope the source server does not have comes back as
    ``status="unmatched"``.
    """
    report = ParityReport(kind="dhcp_scope", source_ref=source_scope_id)

    subnet = (
        await db.execute(select(Subnet).where(Subnet.id == scope.subnet_id))
    ).scalar_one_or_none()
    if subnet is None:
        report.status = "error"
        report.error = (
            "The IPAM subnet backing this scope no longer exists, so there is "
            "nothing to match the Windows scope against."
        )
        return report

    pools = list(
        (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))).scalars().all()
    )
    statics = list(
        (
            await db.execute(
                select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
            )
        )
        .scalars()
        .all()
    )

    try:
        driver = get_dhcp_driver(source_server.driver)
    except ValueError as exc:
        report.status = "error"
        report.error = str(exc)
        return report

    if not hasattr(driver, "get_scopes"):
        report.status = "error"
        report.error = (
            f"DHCP driver {source_server.driver!r} cannot read live scopes, so parity "
            "against it cannot be established. Windows DHCP is the supported "
            "cutover source."
        )
        return report

    try:
        source_scopes: list[dict[str, Any]] = await driver.get_scopes(source_server)
    except Exception as exc:  # noqa: BLE001 — per-item; a whole-plan run fans these out
        report.status = "error"
        report.error = str(exc)
        logger.warning(
            "cutover.parity.dhcp_pull_failed",
            scope=str(scope.id),
            source_scope=source_scope_id,
            server=str(source_server.id),
            driver=source_server.driver,
            error=str(exc),
        )
        return report

    source = match_source_scope(
        source_scopes, subnet_cidr=str(subnet.network), source_scope_id=source_scope_id
    )
    if source is None:
        report.status = "unmatched"
        report.error = (
            f"No scope for {subnet.network} (id {source_scope_id}) exists on the source "
            "Windows DHCP server. It was removed there, or the plan item's source "
            "reference is wrong — re-run Discover."
        )
        return report

    windows_only_class = "drifted_since_import" if scope.import_source else "never_imported"

    source_lease = int(source.get("lease_time") or 0)
    if source_lease == int(scope.lease_time):
        report.in_sync += 1
    else:
        report.differences.append(
            ParityDifference(
                classification="value_mismatch",
                name="lease_time",
                detail=(
                    "Lease duration differs. Clients re-lease on the new value at "
                    "cutover, which changes how long a rollback takes to drain."
                ),
                source_value=str(source_lease),
                target_value=str(scope.lease_time),
            )
        )

    _diff_dhcp_activation(
        report, source_active=bool(source.get("is_active")), target_active=bool(scope.is_active)
    )
    _diff_dhcp_pools(report, source=source, pools=pools, windows_only_class=windows_only_class)
    _diff_dhcp_reservations(
        report, source=source, statics=statics, windows_only_class=windows_only_class
    )
    _diff_dhcp_options(report, source=source, scope=scope, windows_only_class=windows_only_class)

    logger.info(
        "cutover.parity.dhcp",
        scope=str(scope.id),
        subnet=str(subnet.network),
        source_scope=source_scope_id,
        server=str(source_server.id),
        in_sync=report.in_sync,
        differences=report.difference_count,
    )
    return report


__all__ = [
    "compute_dhcp_parity",
    "compute_dns_parity",
    "match_source_scope",
    "normalise_ip",
    "normalise_option_value",
]
