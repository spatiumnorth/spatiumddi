"""Named evaluator functions for ``ConformityPolicy.check_kind``.

Each entry in :data:`CHECK_REGISTRY` is one declarative check the
operator can pin a policy to. The engine looks up the check by name,
runs it against the resolved target, and writes the resulting
:class:`CheckOutcome` as a ``ConformityResult`` row.

Adding a new check:

1. Write the function with the standard signature below.
2. Register it via the ``@register("name")`` decorator.
3. Document it in the inline catalog at module bottom so the
   frontend's "available check kinds" picker stays in sync.

Function contract:

.. code-block:: python

    @register("my_check")
    async def check_my_check(
        db: AsyncSession,
        *,
        target: object | None,
        target_kind: str,
        args: dict[str, Any],
        now: datetime,
    ) -> CheckOutcome: ...

``target`` is the resolved row (Subnet / IPAddress / DNSZone /
DHCPScope) or ``None`` when ``target_kind="platform"``. Checks that
require a target should defensively short-circuit to
:meth:`CheckOutcome.not_applicable` when ``target`` is None.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertRule
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.av import AVFlowProfile, AVReservedRange
from app.models.bacnet import BACnetDevice
from app.models.dicom import DICOMApplicationEntity
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.multicast import MulticastGroup
from app.models.network import NetworkDevice, NetworkInterface
from app.models.nmap import NmapScan
from app.models.ot import OTDevice, OTZone
from app.services import alerts as alert_service
from app.services.av.ranges import check_allocation_conflict
from app.services.dicom.titles import is_vendor_default
from app.services.ipam.probe_policy import resolve_probe_policy
from app.services.ot.zones import (
    effective_zone_for_address,
    purdue_mismatch,
    purdue_to_str,
)

# ── Outcome dataclass ───────────────────────────────────────────────


# ``status`` values. Kept narrow on purpose so the dashboard pivots
# (pass / fail / warn / not_applicable) don't drift.
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"
STATUS_NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class CheckOutcome:
    """Outcome of evaluating one (policy, target) pair."""

    status: str
    detail: str
    diagnostic: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def passed(cls, detail: str = "", diagnostic: dict | None = None) -> CheckOutcome:
        return cls(STATUS_PASS, detail, diagnostic or {})

    @classmethod
    def fail(cls, detail: str = "", diagnostic: dict | None = None) -> CheckOutcome:
        return cls(STATUS_FAIL, detail, diagnostic or {})

    @classmethod
    def warn(cls, detail: str = "", diagnostic: dict | None = None) -> CheckOutcome:
        return cls(STATUS_WARN, detail, diagnostic or {})

    @classmethod
    def not_applicable(cls, detail: str = "", diagnostic: dict | None = None) -> CheckOutcome:
        return cls(STATUS_NOT_APPLICABLE, detail, diagnostic or {})


CheckFn = Callable[..., Awaitable[CheckOutcome]]
CHECK_REGISTRY: dict[str, CheckFn] = {}


def register(name: str) -> Callable[[CheckFn], CheckFn]:
    """Register a check function under a friendly name.

    Decorator. Idempotent in normal use — the registry is built at
    import time and never cleared, so a duplicate registration is a
    programming error and raises immediately.
    """

    def _wrap(fn: CheckFn) -> CheckFn:
        if name in CHECK_REGISTRY:
            raise RuntimeError(f"Conformity check {name!r} already registered")
        CHECK_REGISTRY[name] = fn
        return fn

    return _wrap


# ── Check 1: has_field ──────────────────────────────────────────────


@register("has_field")
async def check_has_field(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when ``target.<field>`` is set to a non-empty value.

    ``args["field"]`` (str, required): name of the column on the
    target row.

    Treats empty string, ``None``, and empty list / dict as "unset".
    Useful for "PCI subnet must have customer_id assigned" style
    policies. Works on any target_kind whose row has the named field.
    """
    if target is None:
        return CheckOutcome.not_applicable("target is unresolved")
    field_name = args.get("field")
    if not isinstance(field_name, str) or not field_name:
        return CheckOutcome.not_applicable(
            "check_args.field is required (string)",
            {"args": args},
        )
    if not hasattr(target, field_name):
        return CheckOutcome.not_applicable(
            f"target_kind={target_kind} has no field {field_name!r}",
        )
    value = getattr(target, field_name, None)
    is_empty = (
        value is None
        or (isinstance(value, str) and not value.strip())
        or (isinstance(value, (list, dict)) and not value)
    )
    if is_empty:
        return CheckOutcome.fail(
            f"{field_name} is unset",
            {"field": field_name, "value": None},
        )
    return CheckOutcome.passed(
        f"{field_name} is set",
        {"field": field_name, "value": str(value)[:200]},
    )


# ── Check 2: in_separate_vrf ────────────────────────────────────────


async def _resolve_subnet_vrf_id(db: AsyncSession, subnet: Subnet) -> str | None:
    """Walk subnet → block → space to find the effective VRF.

    Subnet has no ``vrf_id`` column today (#86 puts the FK on IPSpace
    + IPBlock); the effective VRF is the first non-null we find on
    the block, then the space.
    """
    block = await db.get(IPBlock, subnet.block_id)
    if block is not None and block.vrf_id is not None:
        return str(block.vrf_id)
    space = await db.get(IPSpace, subnet.space_id)
    if space is not None and space.vrf_id is not None:
        return str(space.vrf_id)
    return None


@register("in_separate_vrf")
async def check_in_separate_vrf(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when the target subnet's effective VRF holds *only*
    classification-matched siblings.

    ``args["classification"]`` (str, required): one of the
    classification flag column names on Subnet
    (``pci_scope`` / ``hipaa_scope`` / ``internet_facing``).

    Subnets without an effective VRF (no FK on the enclosing block
    or space) come back ``not_applicable`` — there's no isolation
    boundary to evaluate. Subnets in a VRF that mixes flagged and
    non-flagged neighbours fail with the offending sibling list in
    the diagnostic.
    """
    if not isinstance(target, Subnet):
        return CheckOutcome.not_applicable("requires target_kind=subnet")
    classification = args.get("classification")
    if classification not in ("pci_scope", "hipaa_scope", "internet_facing"):
        return CheckOutcome.not_applicable(
            "check_args.classification is required and must be a known flag",
            {"args": args},
        )
    vrf_id = await _resolve_subnet_vrf_id(db, target)
    if vrf_id is None:
        return CheckOutcome.not_applicable(
            "target subnet has no effective VRF (no vrf_id on enclosing block / space)",
        )

    # Pull every subnet whose enclosing block or space binds to the
    # same VRF, then bucket by classification.
    blocks_in_vrf = (
        (await db.execute(select(IPBlock.id).where(IPBlock.vrf_id == vrf_id))).scalars().all()
    )
    spaces_in_vrf = (
        (await db.execute(select(IPSpace.id).where(IPSpace.vrf_id == vrf_id))).scalars().all()
    )
    siblings = (
        (
            await db.execute(
                select(Subnet).where(
                    (Subnet.block_id.in_(blocks_in_vrf)) | (Subnet.space_id.in_(spaces_in_vrf))
                )
            )
        )
        .scalars()
        .all()
    )
    mixed: list[str] = []
    for sib in siblings:
        if sib.id == target.id:
            continue
        if not getattr(sib, classification, False):
            mixed.append(f"{sib.network} ({sib.name or 'unnamed'})")
    if mixed:
        return CheckOutcome.fail(
            f"VRF mixes {classification} subnets with {len(mixed)} non-flagged sibling(s)",
            {
                "vrf_id": vrf_id,
                "classification": classification,
                "non_matching_siblings": mixed[:20],
            },
        )
    return CheckOutcome.passed(
        f"VRF holds only {classification} subnets",
        {"vrf_id": vrf_id, "classification": classification},
    )


# ── Check 3: no_open_ports ──────────────────────────────────────────


@register("no_open_ports")
async def check_no_open_ports(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when the most recent completed nmap scan against the
    target IP did not show any of ``args["ports"]`` open.

    ``args["ports"]`` (list[int], required): port numbers the policy
    forbids being open (e.g. ``[22, 23, 3389]`` for "no admin ports
    on PCI hosts").
    ``args["max_age_days"]`` (int, optional, default 30): if no
    completed scan exists within this window the result is ``warn``
    — operators see "we don't actually know yet" instead of a false
    pass. The same ``warn`` applies when the latest scan has no parsed
    summary, has no result for the target's address (a CIDR sweep
    omits hosts that did not answer), reports the host as anything but
    ``up``, shows a forbidden port only as ``open|filtered``, or never
    probed a forbidden port (a ping-only sweep, or a ``-p`` list that
    leaves it out).

    Today the check only runs against ``target_kind=ip_address``.
    Subnet-level is a useful follow-up but needs aggregation logic
    over every IP under the subnet, plus an opinion about IPs with
    no scan at all (``warn`` per-IP vs. count toward ``fail``).
    """
    if not isinstance(target, IPAddress):
        return CheckOutcome.not_applicable("requires target_kind=ip_address")
    ports = args.get("ports")
    if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
        return CheckOutcome.not_applicable(
            "check_args.ports is required (list[int])",
            {"args": args},
        )
    forbidden: set[int] = {int(p) for p in ports}
    max_age_days = int(args.get("max_age_days") or 30)
    cutoff = now - timedelta(days=max_age_days)

    scan = (
        (
            await db.execute(
                select(NmapScan)
                .where(NmapScan.ip_address_id == target.id)
                .where(NmapScan.status == "completed")
                .where(NmapScan.finished_at.is_not(None))
                .where(NmapScan.finished_at >= cutoff)
                .order_by(NmapScan.finished_at.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if scan is None:
        return CheckOutcome.warn(
            f"no completed nmap scan within {max_age_days} d for {target.address}",
            {"max_age_days": max_age_days, "ports": sorted(forbidden)},
        )
    scan_meta = {
        "scan_id": str(scan.id),
        "scan_finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "scan_target": scan.target_ip,
        "ports": sorted(forbidden),
    }
    # Every branch below that cannot positively establish the port
    # state is ``warn``, never ``pass`` (#2257): the check used to read
    # a key the parser never wrote and so passed every scanned host.
    summary = scan.summary_json
    if not isinstance(summary, dict):
        return CheckOutcome.warn(
            f"nmap scan {scan.id} has no parsed summary — port state unknown",
            scan_meta,
        )
    entry = _nmap_entry_for_address(
        summary, address=str(target.address), scan_target=scan.target_ip
    )
    if entry is None:
        return CheckOutcome.warn(
            f"nmap scan {scan.id} has no result for {target.address} — port state unknown",
            scan_meta,
        )
    host_state = entry.get("host_state")
    if host_state != "up":
        return CheckOutcome.warn(
            f"nmap scan {scan.id} reported {target.address} as "
            f"{host_state or 'unknown'} — port state unknown",
            {**scan_meta, "host_state": host_state},
        )
    raw_ports = entry.get("ports")
    if not isinstance(raw_ports, list):
        return CheckOutcome.warn(
            f"nmap scan {scan.id} has an unreadable port list — port state unknown",
            scan_meta,
        )
    open_ports: set[int] = set()
    ambiguous_ports: set[int] = set()
    for port_entry in raw_ports:
        if not isinstance(port_entry, dict) or not isinstance(port_entry.get("port"), int):
            continue
        state = port_entry.get("state")
        if state == "open":
            open_ports.add(int(port_entry["port"]))
        elif state == "open|filtered":
            # nmap could not tell open from filtered (typical for UDP).
            ambiguous_ports.add(int(port_entry["port"]))
    diagnostic = {
        **scan_meta,
        "host_state": host_state,
        "open_ports": sorted(open_ports),
        "forbidden": sorted(forbidden),
    }
    overlap = sorted(open_ports & forbidden)
    if overlap:
        return CheckOutcome.fail(
            f"forbidden port(s) {overlap} open per scan {scan.id}",
            diagnostic,
        )
    ambiguous = sorted(ambiguous_ports & forbidden)
    if ambiguous:
        return CheckOutcome.warn(
            f"forbidden port(s) {ambiguous} open|filtered per scan {scan.id} — "
            "nmap could not tell whether they are open",
            {**diagnostic, "open_filtered_ports": sorted(ambiguous_ports)},
        )
    unprobed = _unprobed_ports(summary, scan, forbidden)
    if unprobed:
        return CheckOutcome.warn(
            f"nmap scan {scan.id} did not probe forbidden port(s) {unprobed} — "
            "port state unknown",
            {**diagnostic, "unprobed_ports": unprobed},
        )
    return CheckOutcome.passed(
        f"no forbidden ports open per scan {scan.id}",
        diagnostic,
    )


def _services_cover(spec: str, port: int) -> bool:
    """True when nmap's ``<scaninfo services>`` range list (``"1,3-4,22"``)
    includes ``port``."""
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        try:
            if int(lo) <= port <= int(hi or lo):
                return True
        except ValueError:
            continue
    return False


def _unprobed_ports(summary: dict[str, Any], scan: NmapScan, forbidden: set[int]) -> list[int]:
    """Forbidden ports the scan never probed, so their absence from the
    port list proves nothing (nmap lists only ports in a non-default
    state). A ping-only ``-sn`` sweep probes none; ``-p 80`` probes one.

    Summaries stored before the parser recorded ``scanned_ports`` cannot
    say what was probed; only a ping sweep is known to have probed
    nothing, so those are still trusted otherwise.
    """
    scanned = summary.get("scanned_ports")
    if isinstance(scanned, dict):
        specs = [v for v in scanned.values() if isinstance(v, str)]
        return sorted(p for p in forbidden if not any(_services_cover(s, p) for s in specs))
    if scan.preset == "subnet_sweep" or "-sn" in (scan.extra_args or "").split():
        return sorted(forbidden)
    return []


def _normalise_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _nmap_entry_for_address(
    summary: dict[str, Any], *, address: str, scan_target: str
) -> dict[str, Any] | None:
    """Return the per-host block of a ``parse_nmap_xml`` summary that
    describes ``address``, or ``None`` when the scan says nothing about it.

    A multi-host (CIDR) scan carries one entry per host in ``hosts``;
    nmap omits hosts that did not answer, so a target missing from that
    list is unknown, not clean. A single-host summary carries its own
    ``address``; rows written before that field existed are trusted only
    when the scan targeted exactly this IP — a CIDR sweep where one host
    answered also produces a single-host summary, for whichever host it was.
    """
    want = _normalise_ip(address)
    if want is None:
        return None
    hosts = summary.get("hosts")
    if isinstance(hosts, list) and hosts:
        for host in hosts:
            if isinstance(host, dict) and _normalise_ip(host.get("address")) == want:
                return host
        return None
    if "address" in summary:
        return summary if _normalise_ip(summary.get("address")) == want else None
    return summary if _normalise_ip(scan_target) == want else None


# ── Check 4: alert_rule_covers ──────────────────────────────────────


@register("alert_rule_covers")
async def check_alert_rule_covers(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when at least one *enabled* alert rule of the named
    ``rule_type`` covers the target's classification.

    ``args["rule_type"]`` (str, required): the alert rule_type to
    look for.
    ``args["classification"]`` (str, optional): when set, also
    requires the rule's ``classification`` column to match — useful
    for the ``compliance_change`` rule type from #105 where the
    classification is a per-rule param.

    Platform-level policy (the rule shouldn't be missing for any
    operator). Operators expect the auditor to ask "do you have an
    alert rule that catches changes to PCI scope?" — this is the
    automated way to prove yes.
    """
    rule_type = args.get("rule_type")
    if not isinstance(rule_type, str) or rule_type not in alert_service.RULE_TYPES:
        return CheckOutcome.not_applicable(
            "check_args.rule_type is required and must be a known alert rule_type",
            {"args": args},
        )
    classification = args.get("classification")
    if classification is not None and not isinstance(classification, str):
        return CheckOutcome.not_applicable(
            "check_args.classification (when set) must be a string",
            {"args": args},
        )

    q = (
        select(func.count())
        .select_from(AlertRule)
        .where(
            AlertRule.rule_type == rule_type,
            AlertRule.enabled.is_(True),
        )
    )
    if classification:
        q = q.where(AlertRule.classification == classification)
    count = (await db.execute(q)).scalar_one()
    if count and int(count) > 0:
        return CheckOutcome.passed(
            f"{count} enabled rule(s) of type {rule_type!r} cover this scope",
            {"rule_type": rule_type, "classification": classification, "count": int(count)},
        )
    return CheckOutcome.fail(
        f"no enabled rule of type {rule_type!r} covers this scope",
        {"rule_type": rule_type, "classification": classification},
    )


# ── Check 5: last_seen_within ───────────────────────────────────────


@register("last_seen_within")
async def check_last_seen_within(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when the target has been seen within ``args["max_age_days"]``.

    Works on ``ip_address`` (uses ``last_seen_at``) and on
    ``subnet`` (every IP under the subnet must satisfy the window;
    fail lists any laggards).

    ``args["max_age_days"]`` (int, required): freshness window in
    days. A subnet-level run with the default 30 d window is the
    canonical "decommission stale rows" check.
    """
    max_age_days = args.get("max_age_days")
    if not isinstance(max_age_days, int) or max_age_days <= 0:
        return CheckOutcome.not_applicable(
            "check_args.max_age_days is required (positive int)",
            {"args": args},
        )
    cutoff = now - timedelta(days=max_age_days)

    if isinstance(target, IPAddress):
        last = target.last_seen_at
        if last is None:
            return CheckOutcome.fail(
                f"never seen ({target.address})",
                {"max_age_days": max_age_days},
            )
        if last < cutoff:
            return CheckOutcome.fail(
                f"last seen {last.isoformat()} (> {max_age_days} d ago)",
                {"last_seen_at": last.isoformat(), "max_age_days": max_age_days},
            )
        return CheckOutcome.passed(
            f"last seen {last.isoformat()}",
            {"last_seen_at": last.isoformat()},
        )

    if isinstance(target, Subnet):
        rows = (
            (await db.execute(select(IPAddress).where(IPAddress.subnet_id == target.id)))
            .scalars()
            .all()
        )
        if not rows:
            return CheckOutcome.not_applicable(
                "subnet has no allocated IPs to evaluate",
            )
        stale: list[str] = []
        for ip in rows:
            last = ip.last_seen_at
            if last is None:
                stale.append(f"{ip.address} (never)")
            elif last < cutoff:
                stale.append(f"{ip.address} ({last.isoformat()})")
        if stale:
            return CheckOutcome.fail(
                f"{len(stale)} of {len(rows)} IP(s) older than {max_age_days} d",
                {
                    "max_age_days": max_age_days,
                    "stale_count": len(stale),
                    "total_count": len(rows),
                    "stale_sample": stale[:30],
                },
            )
        return CheckOutcome.passed(
            f"all {len(rows)} IP(s) seen within {max_age_days} d",
            {"max_age_days": max_age_days, "total_count": len(rows)},
        )

    return CheckOutcome.not_applicable(
        f"requires target_kind ip_address or subnet (got {target_kind})",
    )


# ── Check 6: audit_log_immutable (platform-level) ───────────────────


@register("audit_log_immutable")
async def check_audit_log_immutable(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when the audit_log table is queryable and reachable.

    Platform-level. Useful for the auditor checkbox "audit log is
    append-only and tamper-resistant" — the SpatiumDDI promise is
    that ``audit_log`` rows never mutate (DB trigger guards
    DELETE) so this check always passes when the table is healthy.
    Used as a positive presence signal in the PDF artifact.
    """
    if target_kind != "platform":
        return CheckOutcome.not_applicable(
            f"requires target_kind=platform (got {target_kind})",
        )
    try:
        count = (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    except Exception as exc:  # noqa: BLE001
        return CheckOutcome.fail(
            "audit_log table is unreachable",
            {"error": str(exc)},
        )
    return CheckOutcome.passed(
        f"audit_log healthy ({int(count)} row(s))",
        {"row_count": int(count)},
    )


# ── Check 7: voice_segment_not_internet_facing ──────────────────────


@register("voice_segment_not_internet_facing")
async def check_voice_segment_not_internet_facing(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when a voice-VLAN subnet is not flagged ``internet_facing``.

    Voice-segment metadata + the existing ``internet_facing``
    classification combine here — phone fleets reaching the public
    internet directly is almost always a misconfiguration (voice
    traffic should be inside a private VRF / NAT'd through the SBC).
    The check is meaningful only on subnets the operator has tagged
    ``subnet_role='voice'``; everything else is not_applicable.

    Issue #112 phase 2 — flips voice-segment metadata from passive
    UI labelling into a real audit signal.
    """
    _ = args, now, db
    if not isinstance(target, Subnet):
        return CheckOutcome.not_applicable("requires target_kind=subnet")
    if target.subnet_role != "voice":
        return CheckOutcome.not_applicable(
            "subnet is not tagged as a voice segment",
            {"subnet_role": target.subnet_role},
        )
    if target.internet_facing:
        return CheckOutcome.fail(
            "voice subnet is also flagged internet_facing",
            {
                "subnet_role": target.subnet_role,
                "internet_facing": True,
                "network": str(target.network),
            },
        )
    return CheckOutcome.passed(
        "voice subnet is not flagged internet_facing",
        {"subnet_role": target.subnet_role, "network": str(target.network)},
    )


# ── Check: no_multicast_collision ──────────────────────────────────


@register("no_multicast_collision")
async def check_no_multicast_collision(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Multicast group address must be unique within an IPSpace.

    Two groups holding the same address inside the same space
    indicate a misconfiguration — the operator-facing IPAM tree
    treats ``(space_id, address)`` as the stream identity, and
    duplicates surface as silent renderer ambiguity (which row
    "wins" when an ARP lookup or pool dispatch consults the
    registry). The DB layer doesn't enforce uniqueness because
    Phase 1 hasn't established whether deliberate dual-stack
    overlap (e.g. one row in IPv4 view + one in IPv6 view tagged
    on the same logical stream) is a pattern operators want;
    this conformity rule surfaces the cases as a soft warning so
    the operator decides per-incident.
    """
    if target is None or not isinstance(target, MulticastGroup):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for no_multicast_collision"
        )
    siblings = (
        await db.execute(
            select(MulticastGroup.id, MulticastGroup.name).where(
                MulticastGroup.space_id == target.space_id,
                MulticastGroup.address == target.address,
                MulticastGroup.id != target.id,
            )
        )
    ).all()
    if not siblings:
        return CheckOutcome.passed(f"Address {target.address} is unique within space")
    sibling_summary = ", ".join(f"{r._mapping['name']} ({r._mapping['id']})" for r in siblings)
    return CheckOutcome.fail(
        detail=(
            f"Address {target.address} collides with "
            f"{len(siblings)} other group(s) in the same IPSpace: "
            f"{sibling_summary}"
        ),
        diagnostic={
            "address": str(target.address),
            "space_id": str(target.space_id),
            "colliding_group_ids": [str(r._mapping["id"]) for r in siblings],
        },
    )


# ── Catalog (frontend uses to render the policy editor) ──────────────


# ── Check: no_lanwide_control_plane_ports (platform-level, #285) ────


@register("no_lanwide_control_plane_ports")
async def check_no_lanwide_control_plane_ports(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """No appliance node exposes the k3s control-plane ports LAN-wide.

    Platform-level (PCI-DSS Req 1 / HIPAA network-segmentation). The
    appliance base ``/etc/nftables.conf`` historically accepted etcd
    (2379/2380) + kubelet (10250) from ANY source; #285 cut that so the
    supervisor's peer-scoped drop-in is authoritative. Each node reports
    ``base_lanwide_k3s`` (True = still on the legacy LAN-wide base).

    Verdict policy (#2259) — an unverified node is not a compliant node:

    * FAIL only on a CONFIRMED LAN-wide node (``base_lanwide_k3s is True``).
    * WARN when any node is stale (no heartbeat inside
      ``args["stale_minutes"]`` — default 30) or unverified
      (``base_lanwide_k3s is None``): "we don't know yet", the same
      outcome ``no_open_ports`` uses. Never FAIL for lost contact, but
      never PASS either — a PASS counts in ``pass_count`` and the PDF
      pass percentage, and nothing was verified.
    * NOT_APPLICABLE when no appliance node reports a base-conf marker
      (Compose / plain k8s have none; there is nothing to assess).
    * PASS only when every reporting node is hardened and fresh.
    """
    if target_kind != "platform":
        return CheckOutcome.not_applicable(
            f"requires target_kind=platform (got {target_kind})",
        )
    stale_minutes = int(args.get("stale_minutes", 30))
    rows = list(
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.deployment_kind == "appliance",
                    Appliance.base_conf_marker.isnot(None),
                )
            )
        )
        .scalars()
        .all()
    )
    lanwide = [r for r in rows if r.base_lanwide_k3s is True]
    if lanwide:
        return CheckOutcome.fail(
            f"{len(lanwide)} appliance node(s) still expose LAN-wide k3s "
            "control-plane ports (etcd 2379/2380, kubelet 10250)",
            {"lanwide_hosts": sorted(r.hostname for r in lanwide)},
        )
    if not rows:
        return CheckOutcome.not_applicable(
            "no appliance node has reported a base-conf marker — nothing to assess",
            {"reported": 0},
        )
    cutoff = now - timedelta(minutes=stale_minutes)

    def _stale(r: Appliance) -> bool:
        return r.last_seen_at is None or r.last_seen_at < cutoff

    unknown = [r for r in rows if r.base_lanwide_k3s is None]
    stale = [r for r in rows if r.base_lanwide_k3s is False and _stale(r)]
    fresh = [r for r in rows if r.base_lanwide_k3s is False and not _stale(r)]
    if unknown or stale:
        return CheckOutcome.warn(
            f"{len(fresh)} node(s) confirmed hardened; {len(stale)} stale + "
            f"{len(unknown)} unverified — LAN-wide control-plane ports not confirmed absent",
            {
                "hardened_fresh": sorted(r.hostname for r in fresh),
                "stale": sorted(r.hostname for r in stale),
                "unverified": sorted(r.hostname for r in unknown),
                "stale_minutes": stale_minutes,
            },
        )
    return CheckOutcome.passed(
        f"all {len(fresh)} appliance node(s) hardened — no LAN-wide control-plane ports",
        {"hardened": sorted(r.hostname for r in fresh)},
    )


# ── Checks: AV / Audio-Video-over-IP (#540) ─────────────────────────


@register("av_flow_outside_reserved_range")
async def check_av_flow_outside_reserved_range(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """An AV flow lives inside a range declared for its protocol.

    Dante ships transmit flows in ``239.69.0.0/16``; AES67 and
    RAVENNA plants pick a block inside the administratively-scoped
    ``239.0.0.0/8``; SMPTE 2110 studios hand-carve their own. Static
    multicast assignment is the AoIP best practice precisely because
    address drift is what breaks a plant, so a flow that has wandered
    outside its declared range is worth surfacing.

    Absence of policy is deliberately NOT a violation: when the
    operator has declared no range for that protocol there is nothing
    to check against, and failing every flow in that situation would
    train operators to ignore the check. Same for a group carrying no
    AV descriptor — that is a plain multicast group, not an AV flow.
    """
    _ = args, now
    if target is None or not isinstance(target, MulticastGroup):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for av_flow_outside_reserved_range"
        )
    profile = (
        await db.execute(select(AVFlowProfile).where(AVFlowProfile.group_id == target.id))
    ).scalar_one_or_none()
    if profile is None:
        return CheckOutcome.not_applicable("Group carries no AV descriptor")

    # Delegates to the same service the REST allocation-preview calls, so
    # the conformity verdict and the preview an operator saw before
    # allocating cannot disagree about one flow. That also picks up the
    # longest-prefix rule (a Dante /16 carved out of an exclusive AES67
    # /8 resolves to Dante) and the asyncpg CIDR-vs-str coercion, both of
    # which a second hand-rolled containment loop would miss.
    report = await check_allocation_conflict(
        db, target.space_id, str(target.address), profile.av_protocol
    )

    if report.own_ranges:
        matched = report.own_ranges[0]
        return CheckOutcome.passed(
            f"{profile.av_protocol} flow {target.address} is inside " f"{matched.cidr} as declared",
            {
                "address": str(target.address),
                "av_protocol": profile.av_protocol,
                "matched_range": matched.cidr,
            },
        )

    if not report.outside_declared_range:
        return CheckOutcome.not_applicable(
            f"No reserved range declared for {profile.av_protocol} in this IPSpace"
        )

    # Only on the failure path: name the ranges the flow *should* have
    # landed in. That is the actionable half of the finding, and it is
    # one extra query on the rare branch rather than on every group.
    declared = [
        str(c)
        for c in (
            await db.execute(
                select(AVReservedRange.cidr).where(
                    AVReservedRange.space_id == target.space_id,
                    AVReservedRange.av_protocol == profile.av_protocol,
                )
            )
        )
        .scalars()
        .all()
    ]
    return CheckOutcome.fail(
        detail=(
            f"{profile.av_protocol} flow {target.address} sits outside every "
            f"declared {profile.av_protocol} range "
            f"({', '.join(declared[:20])})"
        ),
        diagnostic={
            "address": str(target.address),
            "av_protocol": profile.av_protocol,
            "declared_ranges": declared[:20],
            "suggested_range": report.suggested_range,
        },
    )


@register("av_flow_no_ptp_domain")
async def check_av_flow_no_ptp_domain(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """An AV flow records the PTP clock domain it rides.

    Advisory (warn, never fail). PTP misconfiguration is the most
    common AoIP failure mode, and "which clock domain is this flow
    on?" is the first question asked when audio drops — but a missing
    value is undocumented state, not a broken network, so it does not
    warrant a compliance failure.

    Applied uniformly across AV protocols. NDI is the arguable
    exception (it is not PTP-locked the way AES67/2110 are), but the
    module records the domain as documentation rather than asserting
    the flow is clocked, and special-casing one protocol here would
    encode a claim about NDI's timing model that this registry has no
    way to verify.
    """
    _ = args, now
    if target is None or not isinstance(target, MulticastGroup):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for av_flow_no_ptp_domain"
        )
    profile = (
        await db.execute(select(AVFlowProfile).where(AVFlowProfile.group_id == target.id))
    ).scalar_one_or_none()
    if profile is None:
        return CheckOutcome.not_applicable("Group carries no AV descriptor")
    if profile.ptp_domain is not None:
        return CheckOutcome.passed(
            f"{profile.av_protocol} flow records PTP domain {profile.ptp_domain}",
            {"av_protocol": profile.av_protocol, "ptp_domain": profile.ptp_domain},
        )
    return CheckOutcome.warn(
        detail=(f"{profile.av_protocol} flow {target.address} has no PTP clock " "domain recorded"),
        diagnostic={"address": str(target.address), "av_protocol": profile.av_protocol},
    )


# ── Checks: BACnet/IP building automation (#541) ────────────────────


@register("bbmd_one_per_subnet")
async def check_bbmd_one_per_subnet(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Each BACnet-bearing subnet has exactly one BBMD.

    BACnet broadcasts (``Who-Is`` / ``I-Am``) do not cross IP routers,
    so every IP subnet in a multi-subnet BACnet/IP internetwork needs
    exactly one BACnet Broadcast Management Device. Zero leaves the
    subnet's devices invisible to the rest of the internetwork; two or
    more produces duplicated broadcast traffic and duplicate ``I-Am``
    responses. "Exactly one" is the rule every BAS integration guide
    states, and it is cheaply checkable from the registry.

    A subnet with no BACnet devices at all is NOT_APPLICABLE rather
    than a failure — most subnets in a mixed estate are not BACnet
    subnets, and flagging them would bury the real findings.
    """
    _ = args, now
    if target is None or not isinstance(target, Subnet):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for bbmd_one_per_subnet"
        )
    rows = list(
        (
            await db.execute(
                select(BACnetDevice.device_instance, BACnetDevice.is_bbmd).where(
                    BACnetDevice.subnet_id == target.id
                )
            )
        ).all()
    )
    if not rows:
        return CheckOutcome.not_applicable("Subnet carries no BACnet devices")

    bbmds = [r._mapping["device_instance"] for r in rows if r._mapping["is_bbmd"]]
    if len(bbmds) == 1:
        return CheckOutcome.passed(
            f"Exactly one BBMD (device instance {bbmds[0]}) on this subnet",
            {"bbmd_instances": bbmds, "bacnet_device_count": len(rows)},
        )
    if not bbmds:
        return CheckOutcome.fail(
            detail=(
                f"No BBMD on a subnet with {len(rows)} BACnet device(s) — "
                "its devices cannot be reached across IP routers"
            ),
            diagnostic={"bbmd_count": 0, "bacnet_device_count": len(rows)},
        )
    return CheckOutcome.fail(
        detail=(
            f"{len(bbmds)} BBMDs on one subnet (device instances "
            f"{', '.join(str(i) for i in sorted(bbmds)[:20])}) — expected exactly one; "
            "multiple BBMDs duplicate broadcast traffic"
        ),
        diagnostic={
            "bbmd_count": len(bbmds),
            "bbmd_instances": sorted(bbmds)[:20],
            "bacnet_device_count": len(rows),
        },
    )


@register("bacnet_duplicate_device_instance")
async def check_bacnet_duplicate_device_instance(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """No two BACnet devices share a device instance number.

    Platform-level, because instance uniqueness is an
    internetwork-wide property rather than a per-row one.

    ``uq_bacnet_device_instance`` should make a duplicate impossible,
    so a finding here means data arrived by a path that bypassed the
    ORM — a direct SQL load, a restore from a backup taken before the
    constraint existed, or a future bulk importer that disables
    constraints. That is exactly when an operator most needs to be
    told, which is why the check exists despite the constraint.
    """
    _ = target, args, now
    if target_kind != "platform":
        return CheckOutcome.not_applicable(f"requires target_kind=platform (got {target_kind})")
    dupes = list(
        (
            await db.execute(
                select(BACnetDevice.device_instance, func.count(BACnetDevice.id).label("n"))
                .group_by(BACnetDevice.device_instance)
                .having(func.count(BACnetDevice.id) > 1)
            )
        ).all()
    )
    if not dupes:
        return CheckOutcome.passed("Every BACnet device instance is unique")
    return CheckOutcome.fail(
        detail=(
            f"{len(dupes)} BACnet device instance(s) are held by more than one "
            f"device: {', '.join(str(r._mapping['device_instance']) for r in dupes[:20])}"
        ),
        diagnostic={
            "duplicate_instances": [int(r._mapping["device_instance"]) for r in dupes[:20]],
        },
    )


@register("bacnet_vendor_id_unknown")
async def check_bacnet_vendor_id_unknown(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """BACnet devices report a plausible ASHRAE vendor id.

    Advisory. Vendor id 0 is legitimately ASHRAE itself, but on a real
    plant a device reporting 0 — or reporting nothing at all — is
    almost always a misconfigured, cloned, or counterfeit controller.
    Warn rather than fail: this is a "go look at these" signal, not a
    compliance breach.
    """
    _ = target, args, now
    if target_kind != "platform":
        return CheckOutcome.not_applicable(f"requires target_kind=platform (got {target_kind})")
    rows = list(
        (
            await db.execute(
                select(BACnetDevice.device_instance, BACnetDevice.vendor_id).where(
                    (BACnetDevice.vendor_id.is_(None)) | (BACnetDevice.vendor_id == 0)
                )
            )
        ).all()
    )
    if not rows:
        return CheckOutcome.passed("Every BACnet device reports a non-zero vendor id")
    return CheckOutcome.warn(
        detail=(
            f"{len(rows)} BACnet device(s) report vendor id 0 or none — "
            "commonly a misconfigured or cloned controller"
        ),
        diagnostic={
            "device_instances": [int(r._mapping["device_instance"]) for r in rows[:20]],
        },
    )


# ── Checks: Industrial / OT (#542) ──────────────────────────────────


@register("ot_device_crosses_purdue_boundary")
async def check_ot_device_crosses_purdue_boundary(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """An OT device sits at the Purdue level its subnet is zoned for.

    OT networks are organised by the Purdue model, and the whole point
    of that segmentation is that a Level-1 controller does not live in
    a Level-4 enterprise subnet. A mismatch is the finding an auditor
    asks for and that nobody can produce today without a spreadsheet.

    NOT_APPLICABLE when either side is unset: an unrecorded level is
    missing documentation, not a segmentation violation, and treating
    unknown as guilty would make the check unusable during rollout.
    """
    _ = args, now
    if target is None or not isinstance(target, IPAddress):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for ot_device_crosses_purdue_boundary"
        )
    device = (
        await db.execute(select(OTDevice).where(OTDevice.ip_address_id == target.id))
    ).scalar_one_or_none()
    if device is None:
        return CheckOutcome.not_applicable("Address carries no OT descriptor")

    # Zone resolution and the level comparison both live in
    # ``services.ot.zones`` — the by-address REST endpoint calls the same
    # pair, so the conformity verdict and what an operator sees on the IP
    # detail panel cannot disagree about the same device.
    zone = await effective_zone_for_address(db, target.id)
    mismatch = purdue_mismatch(device, zone)
    device_level = purdue_to_str(device.purdue_level)
    zone_level = purdue_to_str(zone.purdue_level) if zone is not None else None

    if mismatch is None:
        # Tri-state: an unrecorded level on either side is missing
        # documentation, not a segmentation violation.
        if zone is None:
            return CheckOutcome.not_applicable("Subnet has no OT zone declared")
        return CheckOutcome.not_applicable("OT device has no Purdue level recorded")

    if not mismatch:
        return CheckOutcome.passed(
            f"Device and subnet agree at Purdue level {zone_level}",
            {"device_purdue_level": device_level, "zone_purdue_level": zone_level},
        )
    cell = zone.cell_area if zone is not None else ""
    return CheckOutcome.fail(
        detail=(
            f"OT device is Purdue level {device_level} but its subnet is "
            f"zoned level {zone_level}"
            f"{f' ({cell})' if cell else ''}"
        ),
        diagnostic={
            "device_purdue_level": device_level,
            "zone_purdue_level": zone_level,
            "ot_protocol": device.ot_protocol,
            "ot_role": device.ot_role,
            "cell_area": cell,
        },
    )


@register("ot_zone_missing_purdue_level")
async def check_ot_zone_missing_purdue_level(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """A subnet carrying OT devices declares an OT zone.

    Advisory. Without a zone row the Purdue-boundary check above has
    nothing to compare against, so this is the check that tells an
    operator why their segmentation report is empty.
    """
    _ = args, now
    if target is None or not isinstance(target, Subnet):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for ot_zone_missing_purdue_level"
        )
    device_count = (
        await db.execute(
            select(func.count(OTDevice.id))
            .select_from(OTDevice)
            .join(IPAddress, IPAddress.id == OTDevice.ip_address_id)
            .where(IPAddress.subnet_id == target.id)
        )
    ).scalar_one()
    if not device_count:
        return CheckOutcome.not_applicable("Subnet carries no OT devices")
    zone = (
        await db.execute(select(OTZone).where(OTZone.subnet_id == target.id))
    ).scalar_one_or_none()
    if zone is not None:
        return CheckOutcome.passed(
            f"Subnet is zoned at Purdue level {zone.purdue_level}",
            {"purdue_level": str(zone.purdue_level), "ot_device_count": int(device_count)},
        )
    return CheckOutcome.warn(
        detail=(
            f"Subnet carries {device_count} OT device(s) but declares no OT zone, "
            "so Purdue-boundary conformity cannot be evaluated for it"
        ),
        diagnostic={"ot_device_count": int(device_count)},
    )


# ── Check: fragile-device probe safety (#722) ───────────────────────


@register("fragile_subnet_probed")
async def check_fragile_subnet_probed(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """A subnet full of fragile gear is marked do-not-probe.

    The ``do_not_probe`` flag (#722) is opt-in, which means the failure
    mode it exists to prevent — SpatiumDDI sweeping a VLAN whose vendor
    explicitly said not to — survives right up until somebody remembers
    to set it. This check closes that gap by working backwards from the
    registries: if an operator has told us a subnet holds OT devices,
    DICOM modalities, or BMC / IPMI endpoints, they have already told us
    it is fragile. Being asked "should this be do-not-probe?" beats
    finding out from a stalled infusion pump.

    Three signals, any one of which makes the subnet in scope:

    * ``ot_device`` rows (#542) — PLCs, RTUs, HMIs. The class that
      motivated the flag.
    * ``dicom_ae`` rows (#723) — imaging modalities and PACS nodes. A CT
      console that drops its network stack mid-study is a clinical
      incident, not an inconvenience.
    * ``IPAddress.role == "bmc"`` — management-plane controllers on
      embedded stacks, and a routine casualty of nmap.

    A subnet with none of those is NOT_APPLICABLE rather than a pass:
    most subnets in a mixed estate are ordinary, and flagging them all
    would bury the handful that matter. Suppression inherited from a
    parent block or space counts — the check asks whether probes are
    actually withheld, not whether this particular row holds the flag.
    """
    _ = args, now, target_kind
    if target is None or not isinstance(target, Subnet):
        return CheckOutcome.not_applicable(
            "Target row missing or wrong kind for fragile_subnet_probed"
        )

    ot_count = (
        await db.execute(
            select(func.count(OTDevice.id))
            .select_from(OTDevice)
            .join(IPAddress, IPAddress.id == OTDevice.ip_address_id)
            .where(IPAddress.subnet_id == target.id)
        )
    ).scalar_one()
    dicom_count = (
        await db.execute(
            select(func.count(DICOMApplicationEntity.id))
            .select_from(DICOMApplicationEntity)
            .join(IPAddress, IPAddress.id == DICOMApplicationEntity.ip_address_id)
            .where(IPAddress.subnet_id == target.id)
        )
    ).scalar_one()
    bmc_count = (
        await db.execute(
            select(func.count(IPAddress.id)).where(
                IPAddress.subnet_id == target.id,
                IPAddress.role == "bmc",
            )
        )
    ).scalar_one()

    signals = {
        "ot_devices": int(ot_count),
        "dicom_aes": int(dicom_count),
        "bmc_addresses": int(bmc_count),
    }
    if not any(signals.values()):
        return CheckOutcome.not_applicable(
            "Subnet carries no registered fragile devices (OT / DICOM / BMC)"
        )

    verdict = await resolve_probe_policy(db, target)
    if verdict.blocked:
        return CheckOutcome.passed(
            f"Subnet is marked do-not-probe ({verdict.source})",
            {**signals, "source": verdict.source, "reason": verdict.reason},
        )

    present = ", ".join(f"{count} {label}" for label, count in signals.items() if count)
    return CheckOutcome.fail(
        detail=(
            f"Subnet carries fragile devices ({present}) but is not marked "
            "do-not-probe — discovery sweeps, nmap and the reachability tools "
            "will target it"
        ),
        diagnostic=signals,
    )


# ── Checks: DICOM AE registry (#723) ────────────────────────────────


@register("dicom_ae_default_title")
async def check_dicom_ae_default_title(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """No AE is still using a vendor default title.

    Platform-level, because the harm is estate-wide: two vendors' factory
    defaults collide long before an institution runs out of names, and a
    duplicate AE Title breaks C-MOVE, Storage Commitment and Modality
    Worklist in ways that take days to trace. ``uq_dicom_ae_title``
    prevents two rows sharing ``DCM4CHEE``, but it cannot prevent the
    *devices* from doing so — which is why "has anyone changed this from
    the box" is a check rather than a constraint.

    Warns rather than fails: a default title is not invalid, and an
    institution mid-migration may legitimately still have some.
    """
    _ = args, now, target, target_kind
    rows = list(
        (await db.execute(select(DICOMApplicationEntity.id, DICOMApplicationEntity.ae_title))).all()
    )
    if not rows:
        return CheckOutcome.not_applicable("No DICOM application entities registered")

    offenders = [title for _id, title in rows if is_vendor_default(title)]
    if not offenders:
        return CheckOutcome.passed(
            f"All {len(rows)} AE Titles have been changed from vendor defaults",
            {"ae_count": len(rows)},
        )
    return CheckOutcome.warn(
        detail=(
            f"{len(offenders)} AE Title(s) are still vendor defaults "
            f"({', '.join(sorted(offenders)[:20])}) — defaults are the most "
            "common cause of institution-wide AE Title collisions"
        ),
        diagnostic={"default_titles": sorted(offenders)[:20], "ae_count": len(rows)},
    )


@register("dicom_ae_title_convention")
async def check_dicom_ae_title_convention(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """AE Titles match the institution's naming convention.

    The convention arrives as a **check argument** (``pattern``), not as
    a table. Every institution has a different one — ``SITE_MODALITY_NN``
    here, ``DEPT-VENDOR-N`` there — and modelling a convention registry
    would be a schema for a value that is one regular expression per
    site. Supplying it per-policy also lets an estate run two policies at
    once during a rename programme, scoped by whatever ``target_filter``
    the operator sets.

    Not applicable when no pattern is configured — a policy with no
    convention has nothing to assert, and failing it would just teach
    operators to disable the check.
    """
    _ = now, target, target_kind
    pattern = str(args.get("pattern") or "").strip()
    if not pattern:
        return CheckOutcome.not_applicable(
            "No naming convention configured — set the 'pattern' check argument"
        )
    try:
        matcher = re.compile(pattern)
    except re.error as exc:
        # A bad pattern is a policy configuration error, not an estate
        # finding. Warn so it surfaces on the dashboard instead of
        # silently passing every AE.
        return CheckOutcome.warn(
            detail=f"AE Title convention pattern is not a valid regular expression: {exc}",
            diagnostic={"pattern": pattern},
        )

    titles = list((await db.execute(select(DICOMApplicationEntity.ae_title))).scalars().all())
    if not titles:
        return CheckOutcome.not_applicable("No DICOM application entities registered")

    # ``search`` rather than ``fullmatch``: operators write conventions
    # with their own anchors (``^CT\\d{2}$``), and silently anchoring for
    # them would make a deliberately-unanchored pattern behave
    # differently here than everywhere else they test it.
    offenders = [t for t in titles if not matcher.search(t)]
    if not offenders:
        return CheckOutcome.passed(
            f"All {len(titles)} AE Titles match {pattern!r}",
            {"pattern": pattern, "ae_count": len(titles)},
        )
    return CheckOutcome.fail(
        detail=(
            f"{len(offenders)} of {len(titles)} AE Title(s) do not match the "
            f"convention {pattern!r} ({', '.join(sorted(offenders)[:20])})"
        ),
        diagnostic={
            "pattern": pattern,
            "non_conforming": sorted(offenders)[:20],
            "ae_count": len(titles),
        },
    )


@register("dicom_ae_outside_hipaa_scope")
async def check_dicom_ae_outside_hipaa_scope(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Every bound AE sits in a subnet flagged ``hipaa_scope``.

    DICOM associations carry ePHI. If an imaging device is addressable
    from a subnet nobody has declared in scope, then either the scope
    declaration is wrong or the device is somewhere it should not be —
    both are findings, and neither is visible without cross-referencing
    the two registries, which is what this does.

    Unbound reservations are excluded rather than counted as failures: a
    title with no host is not carrying anything. Rows whose subnet is
    unknown are excluded for the same reason — an unknown is an unknown,
    and treating it as a violation would flood the report with missing
    data (the same tri-state discipline as ``purdue_mismatch``).
    """
    _ = args, now, target, target_kind
    rows = list(
        (
            await db.execute(
                select(
                    DICOMApplicationEntity.ae_title,
                    Subnet.network,
                    Subnet.hipaa_scope,
                ).join(Subnet, Subnet.id == DICOMApplicationEntity.subnet_id)
            )
        ).all()
    )
    if not rows:
        return CheckOutcome.not_applicable(
            "No DICOM application entities are bound to a known subnet"
        )

    offenders = [
        {"ae_title": title, "subnet": str(network)}
        for title, network, in_scope in rows
        if not in_scope
    ]
    if not offenders:
        return CheckOutcome.passed(
            f"All {len(rows)} bound AE(s) sit in HIPAA-scope subnets",
            {"bound_ae_count": len(rows)},
        )
    return CheckOutcome.fail(
        detail=(
            f"{len(offenders)} AE(s) are bound to subnets not flagged hipaa_scope "
            f"({', '.join(o['ae_title'] for o in offenders[:20])}) — DICOM "
            "associations carry ePHI, so either the scope flag or the device "
            "placement is wrong"
        ),
        diagnostic={"out_of_scope": offenders[:20], "bound_ae_count": len(rows)},
    )


@register("dicom_ae_no_tls")
async def check_dicom_ae_no_tls(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """AEs are recorded as using TLS.

    Plaintext DICOM puts ePHI on the wire in the clear. This reports what
    the *registry* records, not what the wire does — nothing here probes
    an association, and it never will without going through the
    do-not-probe gate (#722) first. That distinction matters when reading
    the result: a fail here means "nobody has recorded this AE as
    encrypted", which in practice is how an un-encrypted estate looks,
    but the evidence is documentation rather than observation.

    Warns by default because remediating this is a device-by-device
    project with real clinical downtime, and a hard fail on day one would
    put every hospital's dashboard permanently red. Operators who have
    finished that project can raise the policy's severity.
    """
    _ = args, now, target, target_kind
    rows = list(
        (
            await db.execute(
                select(DICOMApplicationEntity.ae_title, DICOMApplicationEntity.tls_enabled)
            )
        ).all()
    )
    if not rows:
        return CheckOutcome.not_applicable("No DICOM application entities registered")

    plaintext = [title for title, tls in rows if not tls]
    if not plaintext:
        return CheckOutcome.passed(
            f"All {len(rows)} AE(s) are recorded as TLS-enabled",
            {"ae_count": len(rows)},
        )
    return CheckOutcome.warn(
        detail=(
            f"{len(plaintext)} of {len(rows)} AE(s) are not recorded as TLS-enabled "
            f"({', '.join(sorted(plaintext)[:20])}) — plaintext DICOM carries ePHI "
            "in the clear"
        ),
        diagnostic={"plaintext_aes": sorted(plaintext)[:20], "ae_count": len(rows)},
    )


# ── E911 dispatchable location (#972) ───────────────────────────────
#
# Three checks answering the three questions an auditor actually asks: is
# there a location for this network at all, has anybody confirmed the
# address, and is the evidence behind the precise answers still arriving.


@register("e911_voice_subnet_unbound")
async def check_e911_voice_subnet_unbound(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when a voice subnet can reach an ERL by SOME rule.

    This is the RAY BAUM'S §506 gap, findable before the audit rather than
    after an incident: a voice segment with no Emergency Response Location
    at any level means a 911 call from it carries no dispatchable location.

    "Some rule" deliberately includes the site default. The front door is a
    poor answer and it is still a dispatchable location; a check demanding
    room-level bindings would fail every site on day one and get turned
    off, which is how a compliance signal becomes noise.
    """
    _ = args, now, target_kind
    if not isinstance(target, Subnet):
        return CheckOutcome.not_applicable("requires target_kind=subnet")
    if target.subnet_role != "voice":
        return CheckOutcome.not_applicable(
            "subnet is not tagged as a voice segment",
            {"subnet_role": target.subnet_role},
        )

    # The subnet's own rule, its VLAN's, or its site's default — the three
    # levels the resolver can reach for a device here with no port-level
    # evidence. A `mac` or `ip` pin is deliberately NOT counted: pinning one
    # handset says nothing about the segment.
    conditions = [ERLBinding.subnet_id == target.id]
    if target.vlan_ref_id is not None:
        conditions.append(ERLBinding.vlan_ref_id == target.vlan_ref_id)
    if target.site_id is not None:
        conditions.append(ERLBinding.site_id == target.site_id)

    rule = (
        await db.execute(
            select(ERLBinding.rule_kind)
            .join(
                EmergencyResponseLocation,
                EmergencyResponseLocation.id == ERLBinding.erl_id,
            )
            .where(
                or_(*conditions),
                ERLBinding.is_active.is_(True),
                EmergencyResponseLocation.is_active.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if rule is None:
        return CheckOutcome.fail(
            "voice subnet has no ERL binding at subnet, VLAN or site level",
            {
                "subnet": str(target.network),
                "vlan_ref_id": str(target.vlan_ref_id) if target.vlan_ref_id else None,
                "site_id": str(target.site_id) if target.site_id else None,
            },
        )
    return CheckOutcome.passed(
        f"voice subnet reaches an ERL via its {rule} binding",
        {"rule_kind": rule},
    )


@register("e911_erl_validated")
async def check_e911_erl_validated(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when every ERL in use carries a recent validation verdict.

    SpatiumDDI never decides this — the verdict comes from the operator's
    E911 provider against the MSAG / NG911 LVF and is recorded here. So the
    check asks whether anybody has confirmed the addresses, which is exactly
    the question nobody asks until a call fails to route.

    An ERL with no bindings is skipped: an address nothing points at
    dispatches nobody, and failing on drafts would bury the ones in use.
    """
    _ = target_kind
    if target is not None:
        return CheckOutcome.not_applicable("requires target_kind=platform")
    max_age_days = int(args.get("max_age_days") or 365)

    rows = list(
        (
            await db.execute(
                select(EmergencyResponseLocation)
                .join(ERLBinding, ERLBinding.erl_id == EmergencyResponseLocation.id)
                .where(
                    EmergencyResponseLocation.is_active.is_(True),
                    ERLBinding.is_active.is_(True),
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return CheckOutcome.not_applicable("no ERL is currently bound to anything")

    cutoff = now - timedelta(days=max_age_days)
    never: list[str] = []
    rejected: list[str] = []
    stale: list[str] = []
    for erl in rows:
        if erl.validation_state == "rejected":
            rejected.append(erl.name)
        elif erl.validation_state != "validated" or erl.validated_at is None:
            never.append(erl.name)
        elif erl.validated_at < cutoff:
            stale.append(erl.name)

    if rejected:
        # A REJECTED verdict is a stronger signal than one never sought:
        # somebody checked, and the answer was no.
        return CheckOutcome.fail(
            f"{len(rejected)} in-use ERL(s) carry a REJECTED address verdict",
            {"rejected": sorted(rejected)[:20], "never_validated": sorted(never)[:20]},
        )
    if never:
        return CheckOutcome.fail(
            f"{len(never)} in-use ERL(s) have never been validated",
            {"never_validated": sorted(never)[:20], "total_in_use": len(rows)},
        )
    if stale:
        # Warn, not fail: the address is almost certainly still right, and
        # the re-validation cadence is the operator's policy, not ours.
        return CheckOutcome.warn(
            f"{len(stale)} in-use ERL(s) were last validated over {max_age_days} days ago",
            {"stale": sorted(stale)[:20], "max_age_days": max_age_days},
        )
    return CheckOutcome.passed(
        f"all {len(rows)} in-use ERL(s) carry a verdict inside {max_age_days} days",
        {"total_in_use": len(rows)},
    )


@register("e911_port_binding_evidence_fresh")
async def check_e911_port_binding_evidence_fresh(
    db: AsyncSession,
    *,
    target: object | None,
    target_kind: str,
    args: dict[str, Any],
    now: datetime,
) -> CheckOutcome:
    """Pass when every switch-port ERL binding sits on a polled device.

    A port-level binding is only as good as the FDB/LLDP data behind it. If
    the device stopped being polled, the resolver is ALREADY degrading every
    lookup for that port to a coarser answer — silently, from the operator's
    point of view. This says so out loud, which is the difference between
    "our room-level locations work" and "they stopped working in March".

    Keyed on the device's own poll state rather than on the evidence rows:
    an unpolled switch eventually has no FDB rows at all, so a check that
    looked for stale rows would PASS on the worst case.
    """
    _ = target_kind
    if target is not None:
        return CheckOutcome.not_applicable("requires target_kind=platform")

    rows = (
        await db.execute(
            select(
                NetworkDevice.name,
                NetworkDevice.last_poll_at,
                NetworkDevice.last_poll_status,
                NetworkDevice.poll_interval_seconds,
                NetworkDevice.is_active,
                NetworkDevice.poll_fdb,
                NetworkDevice.poll_lldp,
                func.count(ERLBinding.id),
            )
            .select_from(ERLBinding)
            .join(
                NetworkInterface,
                NetworkInterface.id == ERLBinding.network_interface_id,
            )
            .join(NetworkDevice, NetworkDevice.id == NetworkInterface.device_id)
            .where(
                ERLBinding.rule_kind == "switch_port",
                ERLBinding.is_active.is_(True),
            )
            .group_by(
                NetworkDevice.id,
                NetworkDevice.name,
                NetworkDevice.last_poll_at,
                NetworkDevice.last_poll_status,
                NetworkDevice.poll_interval_seconds,
                NetworkDevice.is_active,
                NetworkDevice.poll_fdb,
                NetworkDevice.poll_lldp,
            )
        )
    ).all()
    if not rows:
        return CheckOutcome.not_applicable("no switch-port ERL bindings exist")

    broken: list[dict[str, Any]] = []
    for name, last_poll, poll_status, interval, is_active, poll_fdb, poll_lldp, count in rows:
        window = (int(interval) if interval else 300) * 2
        why: str | None = None
        if not is_active:
            why = "device is not active"
        elif not poll_fdb and not poll_lldp:
            # The hole the first version of this check left open, and it is
            # precisely the silent degradation the check claims to catch: a
            # switch polled perfectly on schedule but collecting NEITHER the
            # forwarding table nor LLDP can never produce port evidence, so
            # every lookup for its ports degrades forever while the device
            # reports a healthy poll.
            why = "neither poll_fdb nor poll_lldp is enabled — no port evidence can exist"
        elif last_poll is None:
            # Covers `pending` with no completed poll too, which is why there
            # is no separate branch for it — an earlier draft had one below
            # and it was unreachable. `pending` WITH a last_poll is a poll in
            # flight over data that is still current, so it is healthy.
            why = "device has never been polled"
        elif (now - last_poll).total_seconds() > window:
            age = int((now - last_poll).total_seconds())
            why = f"last polled {age}s ago (window {window}s)"
        elif poll_status == "failed" or poll_status == "timeout":
            # The real vocabulary is pending | success | partial | failed |
            # timeout (``app.models.network``). The first version tested
            # ``not in ("ok", "success")`` — "ok" is not a value any poller
            # writes, and the test therefore reported a ``partial`` poll,
            # where perhaps only the unrelated IGMP leg failed, as "not
            # polled at all".
            why = f"last poll {poll_status}"
        if why:
            broken.append({"device": name, "bindings": int(count), "reason": why})

    if broken:
        return CheckOutcome.fail(
            f"{len(broken)} device(s) carrying switch-port ERL bindings are not polled",
            {"devices": broken[:20]},
        )
    return CheckOutcome.passed(
        f"all {len(rows)} device(s) with switch-port ERL bindings are polling normally",
        {"device_count": len(rows)},
    )


CHECK_CATALOG: list[dict[str, Any]] = [
    {
        "name": "has_field",
        "label": "Field is set",
        "supports": ["subnet", "ip_address", "dns_zone", "dhcp_scope"],
        "args": [
            {
                "name": "field",
                "type": "string",
                "required": True,
                "label": "Field name on the target row (e.g. customer_id)",
            }
        ],
    },
    {
        "name": "in_separate_vrf",
        "label": "Subnet is in an isolated VRF",
        "supports": ["subnet"],
        "args": [
            {
                "name": "classification",
                "type": "enum",
                "required": True,
                "options": ["pci_scope", "hipaa_scope", "internet_facing"],
                "label": "Classification flag",
            }
        ],
    },
    {
        "name": "no_open_ports",
        "label": "No forbidden ports open (per latest nmap scan)",
        "supports": ["ip_address"],
        "args": [
            {
                "name": "ports",
                "type": "int_list",
                "required": True,
                "label": "Forbidden ports (e.g. 22, 23, 3389)",
            },
            {
                "name": "max_age_days",
                "type": "int",
                "required": False,
                "default": 30,
                "label": "Latest scan must be within N days",
            },
        ],
    },
    {
        "name": "alert_rule_covers",
        "label": "An enabled alert rule covers this scope",
        "supports": ["platform"],
        "args": [
            {
                "name": "rule_type",
                "type": "string",
                "required": True,
                "label": "Alert rule type to look for",
            },
            {
                "name": "classification",
                "type": "string",
                "required": False,
                "label": "Optional classification filter (compliance_change rules)",
            },
        ],
    },
    {
        "name": "last_seen_within",
        "label": "Resource has been seen recently",
        "supports": ["ip_address", "subnet"],
        "args": [
            {
                "name": "max_age_days",
                "type": "int",
                "required": True,
                "label": "Freshness window in days",
            }
        ],
    },
    {
        "name": "audit_log_immutable",
        "label": "Audit log is reachable and append-only",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "voice_segment_not_internet_facing",
        "label": "Voice subnet is not flagged internet_facing",
        "supports": ["subnet"],
        "args": [],
    },
    {
        "name": "no_multicast_collision",
        "label": "Multicast group address is unique within its IPSpace",
        "supports": ["multicast_group"],
        "args": [],
    },
    {
        "name": "no_lanwide_control_plane_ports",
        "label": "No appliance exposes LAN-wide k3s control-plane ports",
        "supports": ["platform"],
        "args": [
            {
                "name": "stale_minutes",
                "type": "int",
                "required": False,
                "default": 30,
                "label": "Treat a node's report as stale after N minutes (warn, never FAIL)",
            }
        ],
    },
    {
        "name": "av_flow_outside_reserved_range",
        "label": "AV flow sits inside a declared range for its protocol",
        "supports": ["multicast_group"],
        "args": [],
    },
    {
        "name": "av_flow_no_ptp_domain",
        "label": "AV flow records a PTP clock domain (advisory)",
        "supports": ["multicast_group"],
        "args": [],
    },
    {
        "name": "bbmd_one_per_subnet",
        "label": "Exactly one BACnet BBMD per subnet",
        "supports": ["subnet"],
        "args": [],
    },
    {
        "name": "bacnet_duplicate_device_instance",
        "label": "BACnet device instance numbers are unique internetwork-wide",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "bacnet_vendor_id_unknown",
        "label": "BACnet devices report a plausible vendor id (advisory)",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "ot_device_crosses_purdue_boundary",
        "label": "OT device matches its subnet's Purdue level",
        "supports": ["ip_address"],
        "args": [],
    },
    {
        "name": "ot_zone_missing_purdue_level",
        "label": "Subnet with OT devices declares an OT zone (advisory)",
        "supports": ["subnet"],
        "args": [],
    },
    {
        "name": "fragile_subnet_probed",
        "label": "Subnet with fragile devices is marked do-not-probe",
        "supports": ["subnet"],
        "args": [],
    },
    {
        "name": "dicom_ae_default_title",
        "label": "No DICOM AE is still on a vendor default title",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "dicom_ae_title_convention",
        "label": "DICOM AE Titles match the institution naming convention",
        "supports": ["platform"],
        "args": [
            {
                "name": "pattern",
                "type": "string",
                "required": True,
                "label": "Regular expression every AE Title must match",
            }
        ],
    },
    {
        "name": "dicom_ae_outside_hipaa_scope",
        "label": "DICOM AEs sit in subnets flagged hipaa_scope",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "dicom_ae_no_tls",
        "label": "DICOM AEs are recorded as TLS-enabled",
        "supports": ["platform"],
        "args": [],
    },
    {
        "name": "e911_voice_subnet_unbound",
        "label": "Voice subnet can reach an Emergency Response Location",
        "supports": ["subnet"],
        "args": [],
    },
    {
        "name": "e911_erl_validated",
        "label": "Every in-use ERL carries a provider validation verdict",
        "supports": ["platform"],
        "args": [
            {
                "name": "max_age_days",
                "type": "int",
                "required": False,
                "default": 365,
                "label": "Warn when a verdict is older than N days",
            }
        ],
    },
    {
        "name": "e911_port_binding_evidence_fresh",
        "label": "Switch-port ERL bindings sit on devices that are still polled",
        "supports": ["platform"],
        "args": [],
    },
]


__all__ = [
    "CHECK_REGISTRY",
    "CHECK_CATALOG",
    "CheckOutcome",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_WARN",
    "STATUS_NOT_APPLICABLE",
    "register",
]
