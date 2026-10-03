"""Copilot write operations — preview / apply pattern.

A write tool the LLM fires never executes directly. Instead, the
``propose_*`` tool calls the operation's :func:`preview` (read-only)
and persists an ``ai_operation_proposal`` row. The chat surface
renders the proposal as an Apply / Discard card; the actual mutation
runs only after an explicit POST to ``/api/v1/ai/proposals/{id}/apply``.

This module owns the registry of operations + their preview / apply
implementations. The ``propose_*`` tools live in
``services/ai/tools/`` and import :func:`get_operation` to do the
preview + persist dance; the API router lives in
``api/v1/ai/proposals.py`` and imports the same registry to do the
apply / discard dance.

CLAUDE.md non-negotiables that apply here:
* #4 (audit everything) — apply functions MUST go through the
  service layer paths that already audit, OR write their own audit
  row before commit. The proposal row itself is *not* a substitute
  for an audit-log row.
* #2 (async throughout) — preview + apply are both async; they
  receive the calling user's DB session and User row.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import bind_check_names_error
from app.models.address_set import AddressSet, validate_address_set_shape
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.ipam.probe_policy import check_probe_target
from app.services.nmap import NmapArgError, build_argv
from app.services.pcap import (
    PcapArgError,
    build_pcap_argv,
    clamp_caps,
    validate_bpf_filter,
    validate_interface,
)

# Per-proposal TTL. 30 minutes is a generous window for a thoughtful
# review without keeping yesterday's proposals lying around — the
# cleanup task drops expired+unapplied rows on the next sweep.
PROPOSAL_TTL = timedelta(minutes=30)


@dataclass(frozen=True)
class Operation:
    """One write operation. ``preview`` produces the human-readable
    description (no side effects); ``apply`` performs the mutation
    and returns a JSON-serialisable result.

    The third argument on the callables is typed ``Any`` rather than
    ``BaseModel`` so concrete operations can declare their args
    Pydantic subclass directly (mypy treats function args as
    contravariant — a function that requires
    ``CreateIPAddressArgs`` is not assignable where ``BaseModel`` is
    expected). The registry validates against ``args_model`` on
    dispatch, so the contract is preserved at runtime. Mirrors how
    ``ToolExecutor`` in ``tools/base.py`` solves the same shape.
    """

    name: str
    description: str
    args_model: type[BaseModel]
    preview: Callable[[AsyncSession, User, Any], Awaitable[PreviewResult]]
    apply: Callable[[AsyncSession, User, Any], Awaitable[dict[str, Any]]]
    # Free-form category for grouping in the admin UI — same vocabulary
    # as the read-only tool registry ("ipam", "dns", "dhcp").
    category: str = "ops"
    # SECURITY (#400, C2): the RBAC gate the apply endpoint enforces
    # before dispatching this operation. An ``(action, resource_type)``
    # tuple matching the equivalent REST route's ``require_*_permission``
    # — e.g. ``("write", "ip_address")``. ``apply_proposal`` calls
    # ``user_has_permission(user, action, resource_type)`` and raises 403
    # when the caller lacks it, so the AI propose→apply flow can never
    # write a row the operator couldn't write through the REST API. The
    # field is the authoritative backstop; declaring it on every write
    # operation is mandatory. ``None`` is reserved for self-scoped ops
    # (e.g. archiving your own chat session) that gate on ownership
    # inside their own apply rather than on a coarse RBAC permission.
    required_permission: tuple[str, str] | None = None


@dataclass(frozen=True)
class PreviewResult:
    """Outcome of an operation's :func:`preview` step.

    ``ok=False`` means the preview itself rejected the args (e.g.
    subnet doesn't exist, address out of range) — surface ``detail``
    to the operator and don't even create a proposal row. ``ok=True``
    proceeds to persist the proposal with ``preview_text``.

    ``idempotent=True`` (only meaningful when ``ok=True``) signals the
    target is ALREADY in the desired end-state at approve time — the
    effect this change requested was achieved by some other path (e.g. a
    concurrent break-glass) between request and approval. The approve spine
    resolves such a request as IDEMPOTENT SUCCESS (``executed`` with an
    "already in desired state" note) WITHOUT re-running ``apply()`` and
    WITHOUT the scope-drift guard 409'ing — so a change_request whose effect
    already landed resolves cleanly instead of stranding ``pending`` / failing
    (#62 concurrent break-glass). Defaults False so no existing op changes
    behaviour.
    """

    ok: bool
    detail: str
    preview_text: str = ""
    idempotent: bool = False


_OPERATIONS: dict[str, Operation] = {}


def register(op: Operation) -> None:
    if op.name in _OPERATIONS:
        raise ValueError(f"Operation {op.name!r} already registered")
    _OPERATIONS[op.name] = op


def get_operation(name: str) -> Operation | None:
    return _OPERATIONS.get(name)


def all_operations() -> list[Operation]:
    return sorted(_OPERATIONS.values(), key=lambda o: o.name)


class OperationPermissionError(PermissionError):
    """Raised when the calling user lacks the RBAC permission an
    operation declares. ``apply_proposal`` translates this into a 403.

    SECURITY (#400, C2): the AI propose→apply flow has no router-level
    ``require_*_permission`` dependency, so the operation layer is the
    authoritative authorization gate — without it an authenticated
    Viewer could apply a proposal that writes IPAM/DNS/DHCP/multicast/
    alert rows the equivalent REST route would 403.
    """

    def __init__(self, action: str, resource_type: str) -> None:
        super().__init__(f"Permission denied: need '{action}' on '{resource_type}'")
        self.action = action
        self.resource_type = resource_type


def enforce_operation_permission(user: User, op: Operation) -> None:
    """Backstop an operation's declared RBAC gate (#400, C2).

    Called both by ``apply_proposal`` (the authoritative gate) and by
    each ``_apply_*`` (defense in depth, so the gate holds even if the
    op is ever dispatched outside the apply endpoint). No-op when the
    operation declares ``required_permission=None`` (self-scoped ops).
    """
    from app.core.permissions import user_has_permission  # noqa: PLC0415 — avoid cycle

    if op.required_permission is None:
        return
    action, resource_type = op.required_permission
    if not user_has_permission(user, action, resource_type):
        raise OperationPermissionError(action, resource_type)


def expires_at_default() -> datetime:
    """Stamp every new proposal with ``now + PROPOSAL_TTL``."""
    return datetime.now(UTC) + PROPOSAL_TTL


# ── create_ip_address operation (issue #90 Phase 2 first write tool) ─────────


class CreateIPAddressArgs(BaseModel):
    """Args for the ``create_ip_address`` operation."""

    subnet_id: str = Field(
        description="UUID of the subnet to create the address in",
        # #759 — marks this as a resource reference. The requests portal
        # renders a permission-filtered picker off this annotation (the value
        # is the RBAC resource_type), and MCP clients learn it's a reference,
        # not an opaque string.
        json_schema_extra={"x-resource": "subnet"},
    )
    address: str = Field(description="The IP address as a string (e.g. 10.0.5.10)")
    status: str = Field(
        default="allocated",
        description=(
            "IP status: 'allocated' (default), 'reserved', or "
            "'static_dhcp'. Static_dhcp requires mac_address."
        ),
    )
    hostname: str | None = Field(default=None, description="Hostname (e.g. web01)")
    fqdn: str | None = Field(
        default=None, description="Fully-qualified domain name (e.g. web01.prod.example.com)"
    )
    mac_address: str | None = Field(default=None, description="MAC address in any standard format")
    description: str = Field(default="", description="Free-form description")


async def _preview_create_ip_address(
    db: AsyncSession, user: User, args: CreateIPAddressArgs
) -> PreviewResult:
    # Resolve the subnet so the preview can name it.
    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        return PreviewResult(ok=False, detail=f"Subnet {args.subnet_id} not found")

    try:
        addr_obj = ipaddress.ip_address(args.address)
    except ValueError:
        return PreviewResult(ok=False, detail=f"Invalid IP address: {args.address!r}")

    try:
        net = ipaddress.ip_network(str(subnet.network), strict=False)
    except ValueError:
        return PreviewResult(ok=False, detail=f"Subnet network {subnet.network!r} is unparseable")
    if addr_obj not in net:
        return PreviewResult(
            ok=False,
            detail=(
                f"Address {args.address} is not within subnet {subnet.network} "
                f"({subnet.name or 'unnamed'})"
            ),
        )

    # Check for existing allocation — a non-blocking cue that apply
    # will likely 409. The preview deliberately doesn't reject; the
    # operator might be replacing a stale row.
    existing = (
        await db.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet.id,
                IPAddress.address == args.address,
            )
        )
    ).scalar_one_or_none()
    suffix = ""
    if existing is not None:
        suffix = (
            f" — note: address is already recorded with status "
            f"{existing.status!r}; apply will fail unless you delete it first"
        )

    parts = [
        f"Create IP {args.address}",
        f"in subnet {subnet.network}{f' ({subnet.name})' if subnet.name else ''}",
        f"status={args.status}",
    ]
    if args.hostname:
        parts.append(f"hostname={args.hostname}")
    if args.fqdn:
        parts.append(f"fqdn={args.fqdn}")
    if args.mac_address:
        parts.append(f"mac={args.mac_address}")
    if args.description:
        # Truncate to keep the preview readable.
        d = args.description if len(args.description) < 80 else args.description[:77] + "..."
        parts.append(f"desc={d!r}")
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts) + suffix)


async def _apply_create_ip_address(
    db: AsyncSession, user: User, args: CreateIPAddressArgs
) -> dict[str, Any]:
    """Re-validate at apply time + insert the row.

    Mirrors the conflict checks from the IPAM router's create_address
    handler. We don't import that handler directly (it's bound to a
    FastAPI request shape) — duplicating the few-line conflict check
    is the simpler alternative until the apply set grows.
    """
    from app.api.v1.dhcp._audit import write_audit  # local import to avoid cycle

    # SECURITY (#400, C2): RBAC backstop — the apply path has no
    # router-level permission dependency.
    enforce_operation_permission(user, _OPERATIONS["create_ip_address"])

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        raise ValueError(f"Subnet {args.subnet_id} not found")

    try:
        addr_obj = ipaddress.ip_address(args.address)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {args.address!r}") from exc

    net = ipaddress.ip_network(str(subnet.network), strict=False)
    if addr_obj not in net:
        raise ValueError(f"Address {args.address} is not within subnet {subnet.network}")

    # Re-check for existing allocation under the apply transaction.
    existing = (
        await db.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet.id,
                IPAddress.address == args.address,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(
            f"Address {args.address} is already allocated in subnet {subnet.network} "
            f"(status={existing.status})"
        )

    if args.status == "static_dhcp" and not args.mac_address:
        raise ValueError("mac_address is required when status is 'static_dhcp'")

    row = IPAddress(
        subnet_id=subnet.id,
        address=args.address,
        status=args.status,
        hostname=args.hostname,
        fqdn=args.fqdn,
        mac_address=args.mac_address,
        description=args.description or "",
    )
    db.add(row)
    await db.flush()

    # Audit the apply path so the audit log captures the outcome (the
    # propose step doesn't audit — proposals can be discarded). The
    # event ties the AI to the mutation via the user_display_name +
    # action="ai_apply".
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="ipam.ip_address",
        resource_id=str(row.id),
        resource_display=str(args.address),
        new_value={
            "subnet_id": str(subnet.id),
            "subnet": str(subnet.network),
            "address": args.address,
            "status": args.status,
            "hostname": args.hostname,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "address": args.address,
        "subnet_id": str(subnet.id),
        "status": args.status,
        "hostname": args.hostname,
    }


# ── run_nmap_scan operation ────────────────────────────────────────────


class RunNmapScanArgs(BaseModel):
    """Args for the ``run_nmap_scan`` operation.

    Mirrors :class:`app.api.v1.nmap.schemas.NmapScanCreate` but typed
    looser (``preset`` as plain str so the LLM can supply any of the
    documented presets without a Literal-of-Literals headache for
    JSON-Schema generation in older clients).
    """

    target_ip: str = Field(
        description=(
            "IP address, hostname, or CIDR to scan. CIDR scans use the "
            "``subnet_sweep`` preset by default and are capped on the "
            "backend at /16 worth of hosts."
        ),
    )
    preset: str = Field(
        default="quick",
        description=(
            "Nmap preset: quick | service_version | service_and_os | "
            "os_fingerprint | subnet_sweep | default_scripts | "
            "udp_top1000 | aggressive | custom. ``service_and_os`` is "
            "the right pick for device profiling. ``subnet_sweep`` "
            "(-sn) for ping-sweep across a CIDR. Stick to ``quick`` "
            "or ``service_version`` for routine port checks."
        ),
    )
    port_spec: str | None = Field(
        default=None,
        description="Optional ``-p`` value (e.g. '22,80,443' or 'T:1-1024').",
    )
    extra_args: str | None = Field(
        default=None,
        description=(
            "Optional extra nmap flags, checked against an allowlist: scan "
            "type, host discovery, ports, timing, service / OS detection, and "
            "--script with named non-intrusive scripts (no categories). "
            "Options that read or write files, add targets, or spoof are refused."
        ),
    )


async def _preview_run_nmap_scan(
    db: AsyncSession, user: User, args: RunNmapScanArgs
) -> PreviewResult:
    target = (args.target_ip or "").strip()
    if not target:
        return PreviewResult(ok=False, detail="target_ip is required")

    try:
        argv = build_argv(target, args.preset, args.port_spec, args.extra_args)
    except NmapArgError as exc:
        return PreviewResult(
            ok=False,
            detail=f"nmap arg validation failed: {exc}",
        )

    parts = [
        f"Run nmap **{args.preset}** scan against `{target}`",
    ]
    if args.port_spec:
        parts.append(f"ports={args.port_spec}")
    if args.extra_args:
        parts.append(f"extra={args.extra_args!r}")
    parts.append(f"argv: `{' '.join(argv)}`")
    parts.append(
        "This will issue real network probes from the SpatiumDDI host. "
        "Apply only if you're authorised to scan this target."
    )
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(parts))


async def _apply_run_nmap_scan(
    db: AsyncSession, user: User, args: RunNmapScanArgs
) -> dict[str, Any]:
    """Persist a queued nmap_scan row + dispatch the Celery task.

    Mirrors the create_scan handler in
    :mod:`app.api.v1.nmap.router` but skips the ip_address_id branch
    (the AI surface always passes ``target_ip``). Audit row uses the
    same ``resource_type='nmap_scan'`` shape.
    """
    from app.models.audit import AuditLog  # local import to avoid cycle
    from app.models.nmap import NmapScan  # local import to avoid cycle

    # SECURITY (#400, C2): RBAC backstop — matches the REST route's
    # require_permission("write", "manage_nmap_scans").
    enforce_operation_permission(user, _OPERATIONS["run_nmap_scan"])

    target = args.target_ip.strip()
    # Fragile-device suppression (#722). The REST route refuses these
    # targets, so this path has to as well — a proposal the operator
    # approved is still a scan, and the flag is a statement about the
    # devices, not about which surface asked. Deliberately no override
    # here: clearing the flag is a superadmin action taken deliberately
    # on the tools page, not something to slip through an approval.
    probe = await check_probe_target(db, target)
    if probe.blocked:
        raise ValueError(probe.message(action="Port scanning"))

    # Re-validate at apply time too — argv builder gates dangerous flags.
    try:
        build_argv(target, args.preset, args.port_spec, args.extra_args)
    except NmapArgError as exc:
        raise ValueError(f"nmap arg validation failed: {exc}") from exc

    scan = NmapScan(
        target_ip=target,
        preset=args.preset,
        port_spec=args.port_spec,
        extra_args=args.extra_args,
        status="queued",
        created_by_user_id=user.id,
    )
    db.add(scan)
    await db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="create",
            resource_type="nmap_scan",
            resource_id=str(scan.id),
            resource_display=f"nmap:{target}",
            new_value={
                "preset": args.preset,
                "port_spec": args.port_spec,
                "extra_args": args.extra_args,
                "target_ip": target,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    await db.refresh(scan)

    # Dispatch — broker outage shouldn't fail the apply (mirror
    # router behaviour). The row is queued; operator can re-trigger.
    try:
        from app.tasks.nmap import run_scan_task  # noqa: PLC0415

        run_scan_task.delay(str(scan.id))
    except Exception:  # noqa: BLE001 — broker down
        pass

    return {
        "id": str(scan.id),
        "target_ip": target,
        "preset": args.preset,
        "status": "queued",
        "hint": (
            "Scan dispatched. Poll get_nmap_scan_results until "
            "status == 'completed' to read the open ports / OS guess."
        ),
    }


register(
    Operation(
        name="run_nmap_scan",
        description=(
            "Trigger an on-demand nmap scan. Always go through "
            "propose_run_nmap_scan — never call this directly. The "
            "scan touches the network, so operator approval is "
            "required before each apply."
        ),
        args_model=RunNmapScanArgs,
        preview=_preview_run_nmap_scan,
        apply=_apply_run_nmap_scan,
        category="network",
        required_permission=("write", "manage_nmap_scans"),
    )
)


# ── wake_host operation (issue #533) ───────────────────────────────────


class WakeHostArgs(BaseModel):
    """Args for ``wake_host`` — send a Wake-on-LAN magic packet to an IP."""

    address_id: str = Field(
        description=(
            "UUID of the ip_address row to wake. The MAC + subnet broadcast "
            "are resolved server-side, so resolve the IP first with find_ip "
            "and pass its id."
        ),
    )
    port: int = Field(
        default=9,
        ge=1,
        le=65535,
        description="UDP port for the magic packet (default 9).",
    )


async def _load_wake_target(db: AsyncSession, args: WakeHostArgs) -> tuple[Any, str, str]:
    """Resolve (ip_row, mac, broadcast) or raise ValueError. Delegates to the
    shared ``wol.resolve_wake_params`` so this path can't drift from the REST
    endpoint; only the UUID parse is operation-specific."""
    import uuid as _uuid  # noqa: PLC0415

    from app.services import wol  # noqa: PLC0415

    try:
        aid = _uuid.UUID(args.address_id)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"address_id is not a valid UUID: {args.address_id!r}") from exc
    return await wol.resolve_wake_params(db, aid)


async def _preview_wake_host(db: AsyncSession, user: User, args: WakeHostArgs) -> PreviewResult:
    try:
        ip, mac, broadcast = await _load_wake_target(db, args)
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Send a Wake-on-LAN magic packet to `{mac}` for `{ip.address}` "
            f"(broadcast `{broadcast}:{args.port}`). This wakes the host only "
            "if the packet reaches its L2 segment."
        ),
    )


async def _apply_wake_host(db: AsyncSession, user: User, args: WakeHostArgs) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.services import wol  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["wake_host"])
    ip, mac, broadcast = await _load_wake_target(db, args)
    # AI proposals always send from the control-plane (server) vantage.
    try:
        await wol.wake_from_server(wol.WolWireRequest(mac=mac, broadcast=broadcast, port=args.port))
    except wol.WolDispatchError as exc:
        raise ValueError(str(exc)) from exc
    write_audit(
        db,
        user=user,
        action="wake_on_lan",
        resource_type="ip_address",
        resource_id=str(ip.id),
        resource_display=str(ip.address),
        new_value={
            "mac": mac,
            "broadcast": broadcast,
            "port": args.port,
            "ran_from": "server",
            "via": "ai_proposal",
        },
    )
    await db.commit()
    return {
        "address": str(ip.address),
        "mac": mac,
        "broadcast": broadcast,
        "port": args.port,
        "sent": True,
        "hint": "Magic packet broadcast from the control plane.",
    }


register(
    Operation(
        name="wake_host",
        description=(
            "Send a Wake-on-LAN magic packet to an IP's MAC. Always go "
            "through propose_wake_host — never call this directly."
        ),
        args_model=WakeHostArgs,
        preview=_preview_wake_host,
        apply=_apply_wake_host,
        category="network",
        # ``read`` matches the rest of the network-tools surface.
        required_permission=("read", "use_network_tools"),
    )
)


# ── Scheduled Wake-on-LAN operations (issue #586, Phase 1) ─────────────
#
# Three write operations backing the propose_* tools in
# ``services/ai/tools/wol_scheduler.py``: create a schedule, fire one now,
# and toggle enabled. The resolver + runner + #533 send path are reused
# verbatim from the shipped Phase-1 service layer
# (``app.services.wol_scheduler`` + ``app.services.wol``); these ops add
# only the preview / apply proposal glue. Every mutation audits via the
# shared ``write_audit`` helper (or the runner's own audit) before commit
# (non-negotiable #4). Phase-1 gate is built-in blackout dates + term
# range only — NO external calendar.


class WolSelectorArgs(BaseModel):
    """Target selector for a Wake-on-LAN schedule (resolver storage shape)."""

    mode: Literal["address_tags", "subnet", "subnet_tags", "hosts"] = Field(
        description=(
            "How targets are matched: 'address_tags' (IPs carrying the given "
            "tags), 'subnet' (every host in the given subnet_ids), "
            "'subnet_tags' (hosts in subnets carrying the tags), or 'hosts' "
            "(the explicit address_ids)."
        )
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tag filters (key or key:value, ANDed) for the tag modes.",
    )
    subnet_ids: list[str] = Field(
        default_factory=list,
        description="Subnet UUIDs for the 'subnet' / 'subnet_tags' modes.",
    )
    address_ids: list[str] = Field(
        default_factory=list,
        description="IP-address UUIDs for the 'hosts' mode.",
    )

    def to_jsonb(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "tags": list(self.tags),
            "subnet_ids": [str(s) for s in self.subnet_ids],
            "address_ids": [str(a) for a in self.address_ids],
        }


class CreateWolScheduleArgs(BaseModel):
    """Args for ``create_wol_schedule``."""

    name: str = Field(min_length=1, max_length=255, description="Schedule name.")
    description: str | None = Field(default=None, description="Optional free-text note.")
    enabled: bool = Field(
        default=True, description="Whether the schedule is active (swept by the beat task)."
    )
    selector: WolSelectorArgs
    schedule_cron: str | None = Field(
        default=None,
        description=(
            "5-field cron expression (minute hour dom month dow) evaluated in "
            "the given timezone. Omit / null for a manual-only schedule that "
            "never fires automatically (run it via propose_run_wol_schedule_now)."
        ),
    )
    timezone: str = Field(
        default="UTC",
        description="IANA timezone the cron walks (DST-safe), e.g. 'America/New_York'.",
    )
    blackout_dates: list[str] | None = Field(
        default=None,
        description="ISO YYYY-MM-DD dates that suppress the scheduled wake (holidays).",
    )
    active_from: str | None = Field(
        default=None, description="ISO date — schedule is inactive before this day."
    )
    active_until: str | None = Field(
        default=None, description="ISO date — schedule is inactive after this day."
    )
    calendar_id: str | None = Field(
        default=None,
        description=(
            "Optional UUID of a wol_calendar (iCal/CalDAV subscription) to gate "
            "the wake on. Required when calendar_mode is not 'none'."
        ),
    )
    calendar_mode: Literal["none", "skip_on_event", "only_on_event"] = Field(
        default="none",
        description=(
            "External-calendar gate polarity: 'none' (ignore), 'skip_on_event' "
            "(skip the wake when a matching event covers the fire date — holiday "
            "calendar), or 'only_on_event' (only fire when a matching event "
            "covers it — term/school-day calendar)."
        ),
    )
    calendar_match: str | None = Field(
        default=None,
        description="Optional regex filtering which calendar events count (summary/categories).",
    )
    vantage_kind: Literal["server", "appliance"] = Field(
        default="server",
        description=(
            "Where the magic packet originates: control-plane 'server' or a "
            "Fleet 'appliance' NIC (prefer an on-segment appliance)."
        ),
    )
    vantage_appliance_id: str | None = Field(
        default=None,
        description="Appliance UUID — required when vantage_kind is 'appliance'.",
    )
    repeat_count: int = Field(
        default=2, ge=1, le=10, description="How many identical packets per host."
    )
    repeat_interval_ms: int = Field(default=100, ge=0, le=10_000)
    stagger_ms: int = Field(default=0, ge=0, le=60_000)
    port: int = Field(default=9, ge=1, le=65535)

    @field_validator("calendar_match")
    @classmethod
    def _check_calendar_match(cls, v: str | None) -> str | None:
        # Reject a malformed regex at propose time — mirror the REST
        # WakeScheduleCreate 422 so it can't be persisted then silently
        # degrade to "match every event" in ``_compile_match``.
        from app.api.v1.wol_schedules.schemas import (  # noqa: PLC0415
            _validate_calendar_match,
        )

        return _validate_calendar_match(v)


class RunWolScheduleNowArgs(BaseModel):
    """Args for ``run_wol_schedule_now``."""

    schedule_id: str = Field(description="UUID of the wol_schedule to fire immediately.")


class SetWolScheduleEnabledArgs(BaseModel):
    """Args for ``set_wol_schedule_enabled``."""

    schedule_id: str = Field(description="UUID of the wol_schedule to enable/disable.")
    enabled: bool = Field(description="True to enable (resume sweeping), False to pause.")


async def _load_scoped_wol_user(db: AsyncSession, user_id: UUID) -> User | None:
    """Load a user with groups → roles eager-loaded for the resolver's sync
    RBAC walk (mirrors the REST router's ``_load_scoped_user``)."""
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from app.models.auth import Group  # noqa: PLC0415

    return (
        await db.execute(
            select(User)
            .options(selectinload(User.groups).selectinload(Group.roles))
            .where(User.id == user_id)
        )
    ).scalar_one_or_none()


def _normalise_blackouts(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    out: list[str] = []
    for raw in values:
        try:
            out.append(date.fromisoformat(str(raw).strip()).isoformat())
        except ValueError as exc:
            raise ValueError(f"blackout date {raw!r} is not an ISO YYYY-MM-DD date") from exc
    return out


def _parse_iso_date(value: str | None, field_name: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"{field_name} {value!r} is not an ISO YYYY-MM-DD date") from exc


async def _resolve_wol_count(
    db: AsyncSession, user: User, selector: dict[str, Any]
) -> tuple[int, int]:
    """Best-effort (wake_count, mac_less_count) for a selector — scoped to the
    caller's read permission. Raises ValueError on an invalid selector."""
    from app.services.wol_scheduler import (  # noqa: PLC0415
        SKIP_NO_MAC,
        InvalidSelector,
        resolve_wol_targets,
    )

    principal = await _load_scoped_wol_user(db, user.id) or user
    try:
        resolved = await resolve_wol_targets(db, principal, selector)
    except InvalidSelector as exc:
        raise ValueError(str(exc)) from exc
    mac_less = sum(1 for s in resolved.skipped if s.reason == SKIP_NO_MAC)
    return len(resolved.wakes), mac_less


async def _preview_create_wol_schedule(
    db: AsyncSession, user: User, args: CreateWolScheduleArgs
) -> PreviewResult:
    from app.services.wol_scheduler import (  # noqa: PLC0415
        InvalidCronExpression,
        InvalidTimezone,
        validate_cron,
        validate_timezone,
    )

    try:
        validate_timezone(args.timezone)
    except InvalidTimezone as exc:
        return PreviewResult(ok=False, detail=str(exc))

    cron = args.schedule_cron.strip() if args.schedule_cron else None
    if cron:
        try:
            validate_cron(cron)
        except InvalidCronExpression as exc:
            return PreviewResult(ok=False, detail=str(exc))

    try:
        blackouts = _normalise_blackouts(args.blackout_dates)
        active_from = _parse_iso_date(args.active_from, "active_from")
        active_until = _parse_iso_date(args.active_until, "active_until")
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))

    if active_from is not None and active_until is not None and active_from > active_until:
        return PreviewResult(ok=False, detail="active_from must be on or before active_until")
    if args.vantage_kind == "appliance" and not args.vantage_appliance_id:
        return PreviewResult(
            ok=False, detail="vantage_appliance_id is required when vantage_kind is 'appliance'"
        )

    try:
        wake_count, mac_less = await _resolve_wol_count(db, user, args.selector.to_jsonb())
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))

    cadence = f"cron `{cron}` ({args.timezone})" if cron else "manual-only (no automatic fire)"
    vantage_desc = args.vantage_kind + (
        f" `{args.vantage_appliance_id}`" if args.vantage_kind == "appliance" else ""
    )
    lines = [
        f"Create Wake-on-LAN schedule **{args.name}** — {cadence}.",
        f"Targets ({args.selector.mode}): **{wake_count}** host(s) would wake"
        + (f", {mac_less} skipped (no known MAC)" if mac_less else "")
        + ".",
        f"Vantage: {vantage_desc}; {args.repeat_count}× packet(s), port {args.port}.",
    ]
    if blackouts:
        lines.append(f"Blackout dates: {', '.join(blackouts)}.")
    if active_from is not None or active_until is not None:
        lines.append(
            f"Active term: {active_from or '—'} … {active_until or '—'} "
            "(fires only inside this range)."
        )
    lines.append(
        "Nothing fires until you Apply this proposal"
        + ("" if args.enabled else " and enable the schedule")
        + "."
    )
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(lines))


async def _apply_create_wol_schedule(
    db: AsyncSession, user: User, args: CreateWolScheduleArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.models.wol_schedule import WolCalendar, WolSchedule  # noqa: PLC0415
    from app.services.wol_scheduler import (  # noqa: PLC0415
        InvalidCronExpression,
        InvalidTimezone,
        compute_next_run,
    )

    enforce_operation_permission(user, _OPERATIONS["create_wol_schedule"])

    cron = args.schedule_cron.strip() if args.schedule_cron else None
    try:
        blackouts = _normalise_blackouts(args.blackout_dates)
        active_from = _parse_iso_date(args.active_from, "active_from")
        active_until = _parse_iso_date(args.active_until, "active_until")
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    # Calendar gate (Phase 2) — validate mode/id consistency + existence.
    calendar_uuid: UUID | None = None
    if args.calendar_id:
        try:
            calendar_uuid = UUID(str(args.calendar_id))
        except ValueError as exc:
            raise ValueError(f"calendar_id {args.calendar_id!r} is not a valid UUID") from exc
        if await db.get(WolCalendar, calendar_uuid) is None:
            raise ValueError(f"calendar {calendar_uuid} not found")
    if args.calendar_mode != "none" and calendar_uuid is None:
        raise ValueError(f"calendar_id is required when calendar_mode is {args.calendar_mode!r}")

    vantage = {
        "kind": args.vantage_kind,
        "id": args.vantage_appliance_id if args.vantage_kind == "appliance" else None,
    }
    row = WolSchedule(
        name=args.name,
        description=args.description,
        enabled=args.enabled,
        target_selector=args.selector.to_jsonb(),
        schedule_cron=cron,
        timezone=args.timezone,
        blackout_dates=blackouts,
        active_from=active_from,
        active_until=active_until,
        calendar_id=calendar_uuid,
        calendar_mode=args.calendar_mode,
        calendar_match=args.calendar_match,
        vantage=vantage,
        repeat_count=args.repeat_count,
        repeat_interval_ms=args.repeat_interval_ms,
        stagger_ms=args.stagger_ms,
        port=args.port,
        created_by_user_id=user.id,
    )
    if cron:
        try:
            row.next_run_at = compute_next_run(cron, args.timezone, after=datetime.now(UTC))
        except (InvalidCronExpression, InvalidTimezone) as exc:
            raise ValueError(str(exc)) from exc

    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="wol_schedule",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={
            "name": row.name,
            "enabled": row.enabled,
            "target_selector": row.target_selector,
            "schedule_cron": row.schedule_cron,
            "timezone": row.timezone,
            "vantage": row.vantage,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "name": row.name,
        "enabled": row.enabled,
        "schedule_cron": row.schedule_cron,
        "timezone": row.timezone,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "hint": "Schedule created." + ("" if row.enabled else " It is disabled until enabled."),
    }


async def _preview_run_wol_schedule_now(
    db: AsyncSession, user: User, args: RunWolScheduleNowArgs
) -> PreviewResult:
    from app.models.wol_schedule import WolSchedule  # noqa: PLC0415

    try:
        sid = UUID(args.schedule_id)
    except ValueError:
        return PreviewResult(ok=False, detail=f"invalid schedule_id {args.schedule_id!r}")
    sched = await db.get(WolSchedule, sid)
    if sched is None:
        return PreviewResult(ok=False, detail=f"schedule {args.schedule_id} not found")

    try:
        wake_count, mac_less = await _resolve_wol_count(db, user, sched.target_selector or {})
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))

    vantage_kind = (sched.vantage or {}).get("kind", "server")
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Fire Wake-on-LAN schedule **{sched.name}** now — the built-in "
            f"holiday gate is bypassed for a manual run. **{wake_count}** host(s) "
            f"would be sent a magic packet"
            + (f", {mac_less} skipped (no known MAC)" if mac_less else "")
            + f" from the {vantage_kind} vantage."
        ),
    )


async def _apply_run_wol_schedule_now(
    db: AsyncSession, user: User, args: RunWolScheduleNowArgs
) -> dict[str, Any]:
    enforce_operation_permission(user, _OPERATIONS["run_wol_schedule_now"])
    try:
        sid = UUID(args.schedule_id)
    except ValueError as exc:
        raise ValueError(f"invalid schedule_id {args.schedule_id!r}") from exc

    # Scope the manual run against the caller's read permission (matches the
    # REST run-now); the shared runner writes its own wol_run + audit + commit.
    principal = await _load_scoped_wol_user(db, user.id) or user
    from app.tasks.wol_scheduler import run_schedule_now  # noqa: PLC0415

    try:
        summary = await run_schedule_now(
            sid,
            trigger="manual",
            actor_id=user.id,
            actor_display=user.display_name,
            apply_gate=False,
            resolve_user=principal,
            db=db,
        )
    except KeyError as exc:
        raise ValueError(f"schedule {args.schedule_id} not found") from exc
    return summary


async def _preview_set_wol_schedule_enabled(
    db: AsyncSession, user: User, args: SetWolScheduleEnabledArgs
) -> PreviewResult:
    from app.models.wol_schedule import WolSchedule  # noqa: PLC0415

    try:
        sid = UUID(args.schedule_id)
    except ValueError:
        return PreviewResult(ok=False, detail=f"invalid schedule_id {args.schedule_id!r}")
    sched = await db.get(WolSchedule, sid)
    if sched is None:
        return PreviewResult(ok=False, detail=f"schedule {args.schedule_id} not found")

    state = "enabled" if args.enabled else "disabled"
    if sched.enabled == args.enabled:
        return PreviewResult(
            ok=True,
            detail="ready",
            preview_text=f"Schedule **{sched.name}** is already {state} — no change.",
            idempotent=True,
        )
    verb = "Enable" if args.enabled else "Disable"
    tail = (
        " Its next fire is recomputed from the cron on enable."
        if args.enabled and sched.schedule_cron
        else " It will no longer be swept by the scheduler." if not args.enabled else ""
    )
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=f"{verb} Wake-on-LAN schedule **{sched.name}**.{tail}",
    )


async def _apply_set_wol_schedule_enabled(
    db: AsyncSession, user: User, args: SetWolScheduleEnabledArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.models.wol_schedule import WolSchedule  # noqa: PLC0415
    from app.services.wol_scheduler import (  # noqa: PLC0415
        InvalidCronExpression,
        InvalidTimezone,
        compute_next_run,
    )

    enforce_operation_permission(user, _OPERATIONS["set_wol_schedule_enabled"])
    try:
        sid = UUID(args.schedule_id)
    except ValueError as exc:
        raise ValueError(f"invalid schedule_id {args.schedule_id!r}") from exc
    sched = await db.get(WolSchedule, sid)
    if sched is None:
        raise ValueError(f"schedule {args.schedule_id} not found")

    old = sched.enabled
    sched.enabled = args.enabled
    # Re-enabling with a cron re-derives the next fire so it resumes on cadence.
    if args.enabled and sched.schedule_cron:
        try:
            sched.next_run_at = compute_next_run(
                sched.schedule_cron, sched.timezone, after=datetime.now(UTC)
            )
        except (InvalidCronExpression, InvalidTimezone):
            sched.next_run_at = None

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="wol_schedule",
        resource_id=str(sched.id),
        resource_display=sched.name,
        changed_fields=["enabled"],
        old_value={"enabled": old},
        new_value={"enabled": args.enabled, "via": "ai_proposal"},
    )
    await db.commit()
    await db.refresh(sched)
    return {
        "id": str(sched.id),
        "name": sched.name,
        "enabled": sched.enabled,
        "next_run_at": sched.next_run_at.isoformat() if sched.next_run_at else None,
    }


register(
    Operation(
        name="create_wol_schedule",
        description=(
            "Create a scheduled Wake-on-LAN job. Always go through "
            "propose_create_wol_schedule — never call this directly."
        ),
        args_model=CreateWolScheduleArgs,
        preview=_preview_create_wol_schedule,
        apply=_apply_create_wol_schedule,
        category="network",
        required_permission=("write", "use_network_tools"),
    )
)

register(
    Operation(
        name="run_wol_schedule_now",
        description=(
            "Fire a Wake-on-LAN schedule immediately (holiday gate bypassed). "
            "Always go through propose_run_wol_schedule_now."
        ),
        args_model=RunWolScheduleNowArgs,
        preview=_preview_run_wol_schedule_now,
        apply=_apply_run_wol_schedule_now,
        category="network",
        required_permission=("write", "use_network_tools"),
    )
)

register(
    Operation(
        name="set_wol_schedule_enabled",
        description=(
            "Enable or disable a Wake-on-LAN schedule. Always go through "
            "propose_set_wol_schedule_enabled."
        ),
        args_model=SetWolScheduleEnabledArgs,
        preview=_preview_set_wol_schedule_enabled,
        apply=_apply_set_wol_schedule_enabled,
        category="network",
        required_permission=("write", "use_network_tools"),
    )
)


# ── run_cert_probe operation (issue #118) ──────────────────────────────


class RunCertProbeArgs(BaseModel):
    """Args for ``run_cert_probe`` — probe one existing TLS cert target."""

    target_id: str = Field(description="UUID of the tls_cert_target to probe now")


async def _preview_run_cert_probe(
    db: AsyncSession, user: User, args: RunCertProbeArgs
) -> PreviewResult:
    from app.models.tls_cert import TLSCertTarget  # noqa: PLC0415

    try:
        tid = UUID(args.target_id)
    except ValueError:
        return PreviewResult(ok=False, detail=f"invalid target_id {args.target_id!r}")
    t = await db.get(TLSCertTarget, tid)
    if t is None:
        return PreviewResult(ok=False, detail=f"target {args.target_id} not found")
    label = t.display_name or t.host
    parts = [
        f"Probe TLS endpoint **{label}** (`{t.host}:{t.port}`) now.",
        "This opens a real TLS connection from the SpatiumDDI host and "
        "refreshes the captured certificate + chain validity.",
    ]
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(parts))


async def _apply_run_cert_probe(
    db: AsyncSession, user: User, args: RunCertProbeArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.models.tls_cert import TLSCertTarget  # noqa: PLC0415
    from app.services.tls_cert.probe import probe_one  # noqa: PLC0415

    # SECURITY (#400, C2): matches the REST route's write/tls_cert gate.
    enforce_operation_permission(user, _OPERATIONS["run_cert_probe"])

    t = await db.get(TLSCertTarget, UUID(args.target_id))
    if t is None:
        raise ValueError(f"target {args.target_id} not found")
    ps = await db.get(PlatformSettings, 1)
    interval = max(1, min(168, (ps.tls_cert_check_interval_hours if ps else 6) or 6))
    result = await probe_one(db, t, default_interval_hours=interval)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="probe",
            resource_type="tls_cert",
            resource_id=str(t.id),
            resource_display=t.display_name or t.host,
            result="success" if result.ok else "error",
            new_value={"state": result.state, "ok": result.ok, "via": "ai_proposal"},
        )
    )
    await db.commit()
    return {
        "id": str(t.id),
        "state": result.state,
        "ok": result.ok,
        "error": result.error,
    }


register(
    Operation(
        name="run_cert_probe",
        description=(
            "Probe an existing TLS cert target now. Always go through "
            "propose_run_cert_probe — never call this directly. The probe "
            "opens a real TLS connection, so operator approval is required."
        ),
        args_model=RunCertProbeArgs,
        preview=_preview_run_cert_probe,
        apply=_apply_run_cert_probe,
        category="security",
        required_permission=("write", "tls_cert"),
    )
)


# ── pin_ip_for_dnsbl operation (issue #528) ────────────────────────────


class PinIPForDNSBLArgs(BaseModel):
    """Args for ``pin_ip_for_dnsbl`` — pin one IP for reputation monitoring."""

    ip: str = Field(description="IPv4 address to pin for DNSBL/RBL monitoring")
    note: str = Field(default="", description="Optional operator note for the pin")


async def _preview_pin_ip_for_dnsbl(
    db: AsyncSession, user: User, args: PinIPForDNSBLArgs
) -> PreviewResult:
    from app.models.dnsbl import DNSBLPinnedIP  # noqa: PLC0415

    bare = str(args.ip).split("/")[0].strip()
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return PreviewResult(ok=False, detail=f"invalid IP {args.ip!r}")
    if not isinstance(addr, ipaddress.IPv4Address):
        return PreviewResult(ok=False, detail="DNSBL monitoring is IPv4-only in v1")
    existing = await db.scalar(select(DNSBLPinnedIP).where(DNSBLPinnedIP.ip == str(addr)))
    if existing is not None:
        return PreviewResult(ok=False, detail=f"{addr} is already pinned")
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Pin **{addr}** for DNSBL / RBL reputation monitoring. The next "
            "daily sweep (and any on-demand check) will test it against every "
            "enabled blocklist."
        ),
    )


async def _apply_pin_ip_for_dnsbl(
    db: AsyncSession, user: User, args: PinIPForDNSBLArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.dnsbl import DNSBLPinnedIP  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["pin_ip_for_dnsbl"])

    addr = str(ipaddress.ip_address(str(args.ip).split("/")[0].strip()))
    existing = await db.scalar(select(DNSBLPinnedIP).where(DNSBLPinnedIP.ip == addr))
    if existing is not None:
        return {"id": str(existing.id), "ip": addr, "already_pinned": True}
    row = DNSBLPinnedIP(ip=addr, note=args.note)
    db.add(row)
    await db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="create",
            resource_type="dnsbl",
            resource_id=str(row.id),
            resource_display=addr,
            result="success",
            new_value={"ip": addr, "via": "ai_proposal"},
        )
    )
    await db.commit()
    return {"id": str(row.id), "ip": addr, "already_pinned": False}


register(
    Operation(
        name="pin_ip_for_dnsbl",
        description=(
            "Pin an IP for DNSBL / RBL reputation monitoring. Always go "
            "through propose_pin_ip_for_dnsbl — never call this directly."
        ),
        args_model=PinIPForDNSBLArgs,
        preview=_preview_pin_ip_for_dnsbl,
        apply=_apply_pin_ip_for_dnsbl,
        category="security",
        required_permission=("write", "dnsbl"),
    )
)


# ── run_packet_capture operation (issue #59) ───────────────────────────


class RunPacketCaptureArgs(BaseModel):
    """Args for ``run_packet_capture`` — server vantage only (Phase 1)."""

    interface: str | None = Field(
        default=None,
        description=(
            "Interface to capture on (control-plane container network). "
            "Omit for 'any'. Must be a real interface on the vantage."
        ),
    )
    bpf_filter: str | None = Field(
        default=None,
        description=(
            "Optional tcpdump BPF expression (e.g. 'port 53', "
            "'host 10.0.0.1 and tcp'). Passed to tcpdump as a single "
            "argv element; shell metacharacters are rejected."
        ),
    )
    max_duration_s: int | None = Field(
        default=60,
        description="Stop after N seconds (≤1800). At least one stop condition required.",
    )
    max_packets: int | None = Field(default=None, description="Stop after N packets (≤1,000,000).")
    max_bytes: int | None = Field(default=None, description="Stop near N bytes (≤100 MiB).")
    snaplen: int | None = Field(default=256, description="Bytes captured per packet (default 256).")


async def _preview_run_packet_capture(
    db: AsyncSession, user: User, args: RunPacketCaptureArgs
) -> PreviewResult:
    try:
        interface = validate_interface(args.interface)
        bpf = validate_bpf_filter(args.bpf_filter)
        mp, md, mb, sl = clamp_caps(
            max_packets=args.max_packets,
            max_duration_s=args.max_duration_s,
            max_bytes=args.max_bytes,
            snaplen=args.snaplen,
        )
        argv = build_pcap_argv(
            interface=interface,
            bpf_filter=bpf,
            snaplen=sl,
            promiscuous=False,
            max_packets=mp,
            output_path="<file>",
        )
    except PcapArgError as exc:
        return PreviewResult(ok=False, detail=f"capture arg validation failed: {exc}")

    parts = [
        f"Run a packet capture on `{interface}` (control-plane vantage)",
        f"filter: `{bpf}`" if bpf else "filter: (none — all traffic)",
        f"stop: {md or '—'}s / {mp or '—'} pkts / {mb or '—'} bytes, snaplen {sl}",
        f"argv: `{' '.join(argv)}`",
        "This captures raw traffic (may include credentials/PII). Apply "
        "only if you're authorised; the .pcap is downloadable + audited.",
    ]
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(parts))


async def _apply_run_packet_capture(
    db: AsyncSession, user: User, args: RunPacketCaptureArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # local import to avoid cycle
    from app.models.pcap import PacketCapture  # local import to avoid cycle

    # RBAC backstop — matches the REST route's
    # require_permission("write", "manage_packet_capture").
    enforce_operation_permission(user, _OPERATIONS["run_packet_capture"])

    try:
        interface = validate_interface(args.interface)
        bpf = validate_bpf_filter(args.bpf_filter)
        mp, md, mb, sl = clamp_caps(
            max_packets=args.max_packets,
            max_duration_s=args.max_duration_s,
            max_bytes=args.max_bytes,
            snaplen=args.snaplen,
        )
    except PcapArgError as exc:
        raise ValueError(f"capture arg validation failed: {exc}") from exc

    cap = PacketCapture(
        vantage_kind="server",
        vantage_label="control plane",
        interface=interface,
        bpf_filter=bpf,
        snaplen=sl,
        promiscuous=False,
        max_packets=mp,
        max_duration_s=md,
        max_bytes=mb,
        status="queued",
        created_by_user_id=user.id,
    )
    db.add(cap)
    await db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="create",
            resource_type="packet_capture",
            resource_id=str(cap.id),
            resource_display=f"pcap:{interface}",
            new_value={
                "vantage_kind": "server",
                "interface": interface,
                "bpf_filter": bpf,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    await db.refresh(cap)

    try:
        from app.tasks.pcap import run_capture_task  # noqa: PLC0415

        run_capture_task.delay(str(cap.id))
    except Exception:  # noqa: BLE001 — broker down
        pass

    return {
        "id": str(cap.id),
        "vantage_kind": "server",
        "interface": interface,
        "status": "queued",
        "hint": (
            "Capture dispatched. Poll get_packet_capture until status == "
            "'completed', then download the .pcap from the UI."
        ),
    }


register(
    Operation(
        name="run_packet_capture",
        description=(
            "Start an on-demand packet capture (tcpdump) on the "
            "control-plane vantage. Always go through "
            "propose_run_packet_capture — never call this directly. "
            "Capturing raw traffic is sensitive, so operator approval is "
            "required before each apply."
        ),
        args_model=RunPacketCaptureArgs,
        preview=_preview_run_packet_capture,
        apply=_apply_run_packet_capture,
        category="network",
        required_permission=("write", "manage_packet_capture"),
    )
)


# ── allocate_subnet operation (issue #372) ─────────────────────────────
#
# The carve-and-create counterpart to create_ip_address — picks the
# lowest free child CIDR of the requested prefix from a block and
# creates the subnet atomically. Unblocks the previously-deferred
# create_subnet AI write (no operator-supplied CIDR to get wrong; the
# free-space scan picks it). Apply delegates to the IPAM router's
# allocate_subnet handler so all create_subnet side effects + the audit
# row + the block row-lock are reused verbatim.


class AllocateSubnetArgs(BaseModel):
    """Args for the ``allocate_subnet`` operation."""

    block_id: str = Field(
        description="UUID of the parent IP block to carve the subnet from",
        # #759 — resource reference; see CreateIPAddressArgs.subnet_id.
        json_schema_extra={"x-resource": "ip_block"},
    )
    prefix_len: int = Field(
        ge=1,
        le=128,
        description="Prefix length of the subnet to carve (e.g. 24 for a /24, 64 for a v6 /64)",
    )
    name: str = Field(default="", description="Optional name for the new subnet")
    description: str = Field(default="", description="Optional free-form description")
    template_id: str | None = Field(
        default=None, description="Optional IPAM template UUID to stamp onto the new subnet"
    )


def _carve_candidate(
    block: IPBlock, prefix_len: int, occupied: list[str]
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Pick the lowest free child CIDR of ``prefix_len`` (read-only).

    Shared by preview + the router endpoint's logic. ``_compute_free_cidrs``
    returns maximal aligned free CIDRs sorted by address, so the first one
    large enough to hold a /prefix_len yields the globally-lowest free CIDR.
    """
    from app.api.v1.ipam.router import _compute_free_cidrs  # local import — avoid cycle

    free = _compute_free_cidrs(str(block.network), occupied, max_results=100_000)
    chosen: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    for fr in free:
        fnet = ipaddress.ip_network(fr["network"], strict=False)
        if fnet.prefixlen <= prefix_len:
            chosen = next(fnet.subnets(new_prefix=prefix_len))
            break
    return chosen


async def _preview_allocate_subnet(
    db: AsyncSession, user: User, args: AllocateSubnetArgs
) -> PreviewResult:
    block = await db.get(IPBlock, args.block_id)
    if block is None:
        return PreviewResult(ok=False, detail=f"Block {args.block_id} not found")

    block_net = ipaddress.ip_network(str(block.network), strict=False)
    family_max = 32 if block_net.version == 4 else 128
    if args.prefix_len > family_max:
        return PreviewResult(
            ok=False,
            detail=(
                f"prefix_len {args.prefix_len} exceeds max {family_max} for "
                f"IPv{block_net.version} block {block.network}"
            ),
        )
    if args.prefix_len <= block_net.prefixlen:
        return PreviewResult(
            ok=False,
            detail=(
                f"prefix_len {args.prefix_len} must be greater than block "
                f"prefix length {block_net.prefixlen}"
            ),
        )

    child_blocks = (
        await db.execute(select(IPBlock.network).where(IPBlock.parent_block_id == block.id))
    ).all()
    child_subnets = (
        await db.execute(select(Subnet.network).where(Subnet.block_id == block.id))
    ).all()
    occupied = [str(n) for (n,) in child_blocks] + [str(n) for (n,) in child_subnets]
    chosen = _carve_candidate(block, args.prefix_len, occupied)
    if chosen is None:
        return PreviewResult(
            ok=False,
            detail=f"No free /{args.prefix_len} subnet available in block {block.network}",
        )

    parts = [
        f"Carve `{chosen}` (a /{args.prefix_len}) from block {block.network}",
    ]
    if args.name:
        parts.append(f"name={args.name}")
    parts.append(
        "this is the lowest free CIDR now; the actual allocation is re-checked "
        "under a block lock at apply, so a concurrent carve may shift it"
    )
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts))


async def _apply_allocate_subnet(
    db: AsyncSession, user: User, args: AllocateSubnetArgs
) -> dict[str, Any]:
    """Delegate to the IPAM router's atomic allocate-subnet handler.

    Reuses the block row-lock + full create_subnet side effects + audit
    row, so the AI apply path is identical to the REST/Terraform path.
    """
    from app.api.v1.ipam.router import (  # local import — avoid cycle
        SubnetAllocate,
        allocate_subnet,
    )

    # SECURITY (#400, C2): RBAC backstop — matches the IPAM router's
    # require_any_resource_permission("subnet", ...) write gate.
    enforce_operation_permission(user, _OPERATIONS["allocate_subnet"])

    alloc = SubnetAllocate(
        prefix_len=args.prefix_len,
        name=args.name or "",
        description=args.description or "",
        template_id=UUID(args.template_id) if args.template_id else None,
    )
    subnet = await allocate_subnet(UUID(args.block_id), alloc, user, db)
    return {
        "id": str(subnet.id),
        "network": str(subnet.network),
        "name": subnet.name,
        "block_id": args.block_id,
    }


register(
    Operation(
        name="allocate_subnet",
        description=(
            "Carve the next free child subnet of a given prefix length out "
            "of an IP block and create it atomically. Use this when the "
            "operator asks to 'allocate a /24 from block X' or 'give me a "
            "free /26'. Always go through propose_allocate_subnet — never "
            "call this directly without an explicit operator approval step."
        ),
        args_model=AllocateSubnetArgs,
        preview=_preview_allocate_subnet,
        apply=_apply_allocate_subnet,
        category="ipam",
        required_permission=("write", "subnet"),
    )
)


register(
    Operation(
        name="create_ip_address",
        description=(
            "Allocate a new IP address inside a subnet. Use this when "
            "the operator asks you to create / allocate / assign an "
            "IP. Pass subnet_id (UUID), address, status, and optional "
            "hostname / fqdn / mac_address / description. Always go "
            "through propose_create_ip_address — never call this "
            "directly without an explicit operator approval step."
        ),
        args_model=CreateIPAddressArgs,
        preview=_preview_create_ip_address,
        apply=_apply_create_ip_address,
        category="ipam",
        required_permission=("write", "ip_address"),
    )
)


# ── create_address_set operation (issue #103) ───────────────────────────────


class CreateAddressSetArgs(BaseModel):
    """Args for the ``create_address_set`` operation."""

    name: str = Field(description="Name of the address set (unique within the subnet)")
    subnet_id: UUID = Field(description="UUID of the subnet to create the set in")
    description: str = Field(default="", description="Free-form description")
    range_kind: str = Field(
        default="contiguous",
        description="'contiguous' (start..end span) or 'explicit' (list of host IPs)",
    )
    start_address: str | None = Field(
        default=None, description="First address of a contiguous range"
    )
    end_address: str | None = Field(default=None, description="Last address of a contiguous range")
    explicit_addresses: list[str] = Field(
        default_factory=list, description="Host addresses for an explicit set"
    )


def _validate_address_set_shape(args: CreateAddressSetArgs) -> str | None:
    """Return an error string if the contiguous/explicit shape is invalid.

    Thin adapter over the shared ``validate_address_set_shape`` validator
    in ``app.models.address_set`` — the rules live there once so the AI
    operation and the REST router can't diverge.
    """
    return validate_address_set_shape(
        args.range_kind,
        args.start_address,
        args.end_address,
        list(args.explicit_addresses),
    )


def _address_set_targets(args: CreateAddressSetArgs) -> list[str]:
    if args.range_kind == "contiguous":
        return [a for a in (args.start_address, args.end_address) if a]
    return list(args.explicit_addresses)


async def _preview_create_address_set(
    db: AsyncSession, user: User, args: CreateAddressSetArgs
) -> PreviewResult:
    from app.core.permissions import user_has_permission  # noqa: PLC0415 — avoid cycle

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        return PreviewResult(ok=False, detail=f"Subnet {args.subnet_id} not found")

    # Carving a delegation slice is a subnet-owner operation — require write/admin
    # on the PARENT SUBNET so the operator isn't shown a false "ready" preview
    # they can't actually apply (#103, finding #3; mirrors the REST create gate).
    if not user_has_permission(user, "write", "subnet", args.subnet_id):
        return PreviewResult(
            ok=False,
            detail="You need write on the parent subnet to create an address set in it.",
        )

    shape_err = _validate_address_set_shape(args)
    if shape_err is not None:
        return PreviewResult(ok=False, detail=shape_err)

    try:
        net = ipaddress.ip_network(str(subnet.network), strict=False)
    except ValueError:
        return PreviewResult(ok=False, detail=f"Subnet network {subnet.network!r} is unparseable")
    for raw in _address_set_targets(args):
        if ipaddress.ip_address(raw) not in net:
            return PreviewResult(
                ok=False, detail=f"address {raw} is outside subnet {subnet.network}"
            )

    if args.range_kind == "contiguous":
        scope = f"{args.start_address}–{args.end_address}"
    else:
        scope = f"{len(args.explicit_addresses)} explicit address(es)"
    parts = [
        f"Create address set {args.name!r}",
        f"in subnet {subnet.network}{f' ({subnet.name})' if subnet.name else ''}",
        f"kind={args.range_kind}",
        scope,
    ]
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts))


async def _apply_create_address_set(
    db: AsyncSession, user: User, args: CreateAddressSetArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # local import to avoid cycle
    from app.core.permissions import user_has_permission  # noqa: PLC0415 — avoid cycle

    enforce_operation_permission(user, _OPERATIONS["create_address_set"])

    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None:
        raise ValueError(f"Subnet {args.subnet_id} not found")

    # Subnet-owner gate — same wording as the REST create path (#103, finding #3).
    # ``enforce_operation_permission`` already proved type-wide admin:address_set;
    # this additionally requires write/admin on the PARENT SUBNET so a delegate
    # can't self-escalate by carving a slice out of a subnet they don't control.
    if not user_has_permission(user, "write", "subnet", args.subnet_id):
        raise ValueError("You need write on the parent subnet to create an address set in it.")

    shape_err = _validate_address_set_shape(args)
    if shape_err is not None:
        raise ValueError(shape_err)

    net = ipaddress.ip_network(str(subnet.network), strict=False)
    for raw in _address_set_targets(args):
        if ipaddress.ip_address(raw) not in net:
            raise ValueError(f"address {raw} is outside subnet {subnet.network}")

    existing = (
        await db.execute(
            select(AddressSet.id).where(
                AddressSet.subnet_id == subnet.id,
                AddressSet.name == args.name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"An address set named {args.name!r} already exists on this subnet")

    row = AddressSet(
        name=args.name,
        description=args.description or "",
        subnet_id=subnet.id,
        range_kind=args.range_kind,
        start_address=args.start_address if args.range_kind == "contiguous" else None,
        end_address=args.end_address if args.range_kind == "contiguous" else None,
        explicit_addresses=(list(args.explicit_addresses) if args.range_kind == "explicit" else []),
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        # Bare RBAC type — the audit→event mapping in event_publisher keys
        # on "address_set" (→ "ipam.address_set"); using the namespaced
        # string here would silence the webhook event for AI-created sets.
        resource_type="address_set",
        resource_id=str(row.id),
        resource_display=args.name,
        new_value={
            "subnet_id": str(subnet.id),
            "subnet": str(subnet.network),
            "name": args.name,
            "range_kind": args.range_kind,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "name": row.name,
        "subnet_id": str(subnet.id),
        "range_kind": row.range_kind,
    }


register(
    Operation(
        name="create_address_set",
        description=(
            "Create a named, RBAC-scoped address set (a slice of a subnet's "
            "address space) so edit of that slice can be delegated without "
            "subnet-wide write. Pass name, subnet_id, range_kind "
            "('contiguous' with start/end, or 'explicit' with a host list). "
            "Always go through propose_create_address_set — never call this "
            "directly without an explicit operator approval step."
        ),
        args_model=CreateAddressSetArgs,
        preview=_preview_create_address_set,
        apply=_apply_create_address_set,
        category="ipam",
        required_permission=("admin", "address_set"),
    )
)


# ── Tier 5 (issue #101) — DNS record / DHCP static / alert rule / chat archive ──
#
# Each operation follows the same preview / apply / register pattern
# as ``create_ip_address`` above. ``create_subnet`` was deliberately
# deferred — subnet creation has too many edge cases (auto-allocate
# network/broadcast rows, parent-block overlap checks, allocation
# policy) to ship without a dedicated design pass.


# ── create_dns_record ─────────────────────────────────────────────────


_DNS_RECORD_TYPES = {
    "A",
    "AAAA",
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
}


class CreateDNSRecordArgs(BaseModel):
    """Args for the ``create_dns_record`` operation."""

    zone_id: str = Field(
        description="UUID of the parent DNS zone.",
        # #759 — resource reference; see CreateIPAddressArgs.subnet_id.
        json_schema_extra={"x-resource": "dns_zone"},
    )
    name: str = Field(
        description=(
            "Relative record name. Use ``@`` for the zone apex. Do NOT "
            "include the trailing zone (use ``host1`` not "
            "``host1.example.com``)."
        )
    )
    record_type: str = Field(
        description=(
            "Record type — A / AAAA / CNAME / MX / TXT / NS / PTR / "
            "SRV / CAA / TLSA / SSHFP / NAPTR / LOC."
        )
    )
    value: str = Field(
        description=(
            "Right-hand-side value. For A/AAAA an IP; for CNAME / NS "
            "a target FQDN; for TXT the quoted text; for MX the "
            "target host (priority is a separate arg); for SRV the "
            "target host (priority/weight/port are separate args)."
        )
    )
    ttl: int | None = Field(
        default=None,
        description=(
            "Override TTL in seconds. None inherits the zone's "
            "default. Range 60 – 604800 when supplied."
        ),
        ge=60,
        le=604_800,
    )
    priority: int | None = Field(
        default=None,
        description="MX/SRV priority. Required for MX and SRV records.",
        ge=0,
        le=65_535,
    )
    weight: int | None = Field(
        default=None,
        description="SRV weight. Required for SRV records (not used elsewhere).",
        ge=0,
        le=65_535,
    )
    port: int | None = Field(
        default=None,
        description="SRV port. Required for SRV records (not used elsewhere).",
        ge=0,
        le=65_535,
    )


async def _preview_create_dns_record(
    db: AsyncSession, user: User, args: CreateDNSRecordArgs
) -> PreviewResult:
    from app.models.dns import DNSRecord, DNSZone  # local import — avoid cycle
    from app.services.dns.cname_conflict import (
        APEX_CNAME_DETAIL,
        describe_cname_conflict,
        find_cname_conflict,
        is_apex,
    )

    rtype = args.record_type.strip().upper()
    if rtype not in _DNS_RECORD_TYPES:
        return PreviewResult(ok=False, detail=f"Unsupported record type {rtype!r}.")
    if rtype == "MX" and args.priority is None:
        return PreviewResult(ok=False, detail="MX records require a priority.")
    if rtype == "SRV":
        missing = [
            n
            for n, v in (
                ("priority", args.priority),
                ("weight", args.weight),
                ("port", args.port),
            )
            if v is None
        ]
        if missing:
            return PreviewResult(
                ok=False,
                detail="SRV records require " + ", ".join(missing) + ".",
            )

    zone = await db.get(DNSZone, args.zone_id)
    if zone is None:
        return PreviewResult(ok=False, detail=f"Zone {args.zone_id} not found.")
    if getattr(zone, "deleted_at", None) is not None:
        return PreviewResult(ok=False, detail=f"Zone {args.zone_id} is deleted.")

    name = args.name.strip()
    if not name:
        return PreviewResult(ok=False, detail="name is required (use ``@`` for apex).")

    # #1378 — never propose what the group's BIND would refuse; apply
    # refuses it too.
    owner = zone.name if name == "@" else f"{name}.{zone.name}"
    names_err = bind_check_names_error(rtype, owner, args.value, origin=zone.name)
    if names_err is not None:
        return PreviewResult(ok=False, detail=names_err)
    # #1381 — nor a CNAME beside other data; apply refuses it too.
    if rtype == "CNAME" and is_apex(name):
        return PreviewResult(ok=False, detail=APEX_CNAME_DETAIL)
    clash = await find_cname_conflict(db, zone.id, view_id=None, name=name, record_type=rtype)
    if clash is not None:
        return PreviewResult(ok=False, detail=describe_cname_conflict(rtype, owner, clash))

    # Surface a heads-up if a row with the same (zone, name, type, value)
    # already exists; preview doesn't reject — operator may want a parallel
    # row (e.g. multiple A records for round-robin).
    existing = (
        await db.execute(
            select(DNSRecord).where(
                DNSRecord.zone_id == zone.id,
                DNSRecord.name == name,
                DNSRecord.record_type == rtype,
                DNSRecord.value == args.value,
                DNSRecord.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    suffix = " — note: an identical record already exists" if existing else ""

    parts = [
        f"Create **{rtype}** record `{name}` in zone `{zone.name}`",
        f"value=`{args.value}`",
    ]
    if args.ttl is not None:
        parts.append(f"ttl={args.ttl}")
    if args.priority is not None:
        parts.append(f"priority={args.priority}")
    if args.weight is not None:
        parts.append(f"weight={args.weight}")
    if args.port is not None:
        parts.append(f"port={args.port}")
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts) + suffix)


async def _apply_create_dns_record(
    db: AsyncSession, user: User, args: CreateDNSRecordArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # local import to avoid cycle
    from app.core.agent_wake import dns_group_channel, publish_wake
    from app.models.dns import DNSRecord, DNSZone
    from app.services.dns.cname_conflict import (
        APEX_CNAME_DETAIL,
        describe_cname_conflict,
        find_cname_conflict,
        is_apex,
    )
    from app.services.dns.record_identity import describe_identical, find_identical_record
    from app.services.dns.record_ops import enqueue_record_op
    from app.services.dns.serial import bump_zone_serial

    # SECURITY (#400, C2): RBAC backstop — matches the DNS router's
    # require_any_resource_permission("dns_record", ...) write gate.
    enforce_operation_permission(user, _OPERATIONS["create_dns_record"])

    rtype = args.record_type.strip().upper()
    if rtype not in _DNS_RECORD_TYPES:
        raise ValueError(f"Unsupported record type {rtype!r}.")
    if rtype == "MX" and args.priority is None:
        raise ValueError("MX records require a priority.")
    if rtype == "SRV" and (args.priority is None or args.weight is None or args.port is None):
        raise ValueError("SRV records require priority, weight, and port.")

    zone = await db.get(DNSZone, args.zone_id)
    if zone is None:
        raise ValueError(f"Zone {args.zone_id} not found.")

    name = args.name.strip()
    fqdn = (
        zone.name
        if name in ("@", "")
        else f"{name}.{zone.name}".rstrip(".") + ("." if zone.name.endswith(".") else "")
    )

    # #1378 — the same check-names refusal as the REST create path.
    names_err = bind_check_names_error(rtype, fqdn, args.value, origin=zone.name)
    if names_err is not None:
        raise ValueError(names_err)

    # #1230 — never store the same RR twice; see app.services.dns.record_identity.
    existing = await find_identical_record(
        db,
        zone.id,
        view_id=None,
        name=name,
        record_type=rtype,
        value=args.value,
        priority=args.priority,
        weight=args.weight if rtype == "SRV" else None,
        port=args.port if rtype == "SRV" else None,
    )
    if existing is not None:
        raise ValueError(describe_identical(existing))
    # #1381 — a CNAME stands alone at its name, as on the REST path.
    if rtype == "CNAME" and is_apex(name):
        raise ValueError(APEX_CNAME_DETAIL)
    clash = await find_cname_conflict(db, zone.id, view_id=None, name=name, record_type=rtype)
    if clash is not None:
        raise ValueError(describe_cname_conflict(rtype, fqdn, clash))

    row = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=fqdn,
        record_type=rtype,
        value=args.value,
        ttl=args.ttl,
        priority=args.priority,
        weight=args.weight if rtype == "SRV" else None,
        port=args.port if rtype == "SRV" else None,
        created_by_user_id=user.id,
    )
    db.add(row)
    # Mirror the REST create path so a Copilot-created record actually
    # propagates: bump the zone serial and queue a record op for every
    # agent in the group. Without this the row lands in the DB but never
    # reaches BIND9/PowerDNS (the agent only converges on the next ETag
    # shift). enqueue_record_op collects a Redis wake; flush it explicitly
    # here since this runs outside the router's wake_publishing dependency.
    target_serial = bump_zone_serial(zone)
    await db.flush()
    await enqueue_record_op(
        db,
        zone,
        "create",
        {
            "name": row.name,
            "type": row.record_type,
            "value": row.value,
            "ttl": row.ttl,
            "priority": row.priority,
            "weight": row.weight,
            "port": row.port,
        },
        target_serial=target_serial,
    )

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dns.record",
        resource_id=str(row.id),
        resource_display=f"{name} {rtype} {args.value}",
        new_value={
            "zone_id": str(zone.id),
            "zone": zone.name,
            "name": name,
            "type": rtype,
            "value": args.value,
            "ttl": args.ttl,
            "priority": args.priority,
            "weight": args.weight if rtype == "SRV" else None,
            "port": args.port if rtype == "SRV" else None,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    # Instant wake (advisory — the ETag compare is still the source of
    # truth; if Redis is down the agent converges on its poll/safety tick).
    await publish_wake(dns_group_channel(zone.group_id))
    return {
        "id": str(row.id),
        "zone_id": str(zone.id),
        "fqdn": fqdn,
        "record_type": rtype,
        "value": args.value,
    }


register(
    Operation(
        name="create_dns_record",
        description=(
            "Create a DNS resource record inside a zone. Always route "
            "via propose_create_dns_record — DNS edits propagate to "
            "live servers, so operator approval per-apply is required."
        ),
        args_model=CreateDNSRecordArgs,
        preview=_preview_create_dns_record,
        apply=_apply_create_dns_record,
        category="dns",
        required_permission=("write", "dns_record"),
    )
)


# ── create_dns_zone (issue #127 Phase 4e) ─────────────────────────────


_DNS_DRIVER_HINTS = {
    "bind9",
    "powerdns",
    "technitium",
    # Agentless Technitium against an install the operator already runs
    # (#810). Distinct from ``technitium``, which is the agent-managed
    # container — a group is single-driver, so the hint has to be able to
    # tell them apart.
    "technitium_api",
    "windows_dns",
}

# ``CreateDNSZoneArgs`` fields only some drivers can honour, mapped to
# ``(REST operation whose driver gate governs them, operator-facing label)``.
#
# The driver set is NOT restated here — it is read from the DNS router's
# ``_DRIVER_GATED_OPERATIONS`` at preview time. Issue #798: this used to be a
# hardcoded ``_POWERDNS_ONLY_FEATURES = ("dnssec_enabled",)`` tuple tested with
# ``"powerdns" not in drivers``, written when PowerDNS was the only online
# signer. BIND9 inline-signing (#49) and Technitium online signing (#740)
# widened the REST gate; this constant was not widened with it, so the Copilot
# spent two releases refusing work the REST API accepted. Seeding from the
# single source of truth is the fix — do not inline the driver names again.
_DRIVER_GATED_ZONE_ARGS: dict[str, tuple[str, str]] = {
    "dnssec_enabled": ("dnssec_sign", "online DNSSEC signing"),
}


def _drivers_for_gated_arg(arg: str) -> frozenset[str]:
    """Return the drivers allowed to use ``arg``, read from the REST gate."""
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS  # noqa: PLC0415

    op, _label = _DRIVER_GATED_ZONE_ARGS[arg]
    return _DRIVER_GATED_OPERATIONS[op]


def _gated_zone_arg_conflict(
    args: CreateDNSZoneArgs, drivers: set[str], group_name: str
) -> str | None:
    """Driver-gated zone features (currently DNSSEC). Semantics are copied
    from ``_check_driver_gated_operation`` in the DNS router, deliberately
    and exactly:

    * SUBSET, not intersection — EVERY server in the group has to support
      the feature, not merely one of them. An "any member matches" test
      would pass a bind9 + windows_dns group here, land a zone flagged
      dnssec_enabled, and then the sign endpoint would 422 it: signed
      according to the UI, unsigned on the wire.
    * Empty groups fail SOFT — a group with no servers yet has nobody to
      disagree, and the REST gate re-runs once a driver is known.

    Shared by preview AND apply (#811): apply re-checks because servers can
    join the group between proposal and approval, and an unsignable zone
    must not land just because the preview predates the new member.
    ``group_name`` matters for the message: when the group was auto-picked
    via driver_hint the caller never named it, so an error that doesn't
    name it either is unactionable.
    """
    if not drivers:
        return None
    for feat, (_op, label) in _DRIVER_GATED_ZONE_ARGS.items():
        if not getattr(args, feat):
            continue
        allowed = sorted(_drivers_for_gated_arg(feat))
        incompatible = sorted(drivers - set(allowed))
        if incompatible:
            return (
                f"{feat}=true requires every server in the group to support "
                f"{label} ({', '.join(allowed)}), but {group_name!r} also "
                f"has {incompatible}. Move those servers to their own "
                f"group, pick a different group, or set driver_hint to one "
                f"of {allowed} without group_id."
            )
    return None


class CreateDNSZoneArgs(BaseModel):
    """Args for the ``create_dns_zone`` operation.

    ``driver_hint`` (issue #127 Phase 4e) lets the model express the
    operator's intent — "I need DNSSEC online signing, so this zone
    has to land on a group that can sign" — without forcing it to know
    the exact group UUID. When supplied, the preview either:

    * uses ``driver_hint`` to select a matching group when
      ``group_id`` is omitted, OR
    * cross-checks ``driver_hint`` against an explicit ``group_id``
      and rejects on driver mismatch (e.g. operator picked a BIND9
      group but asked for ``driver_hint="powerdns"``).
    """

    name: str = Field(
        description=(
            "Zone name (FQDN). Trailing dot is added automatically if "
            "not present (e.g. ``example.com`` becomes ``example.com.``)."
        )
    )
    group_id: str | None = Field(
        default=None,
        description=(
            "UUID of the DNS server group that should own this zone. "
            "Optional — when omitted, ``driver_hint`` (if supplied) "
            "selects a matching group automatically; if neither is "
            "supplied the preview returns the available groups so the "
            "operator can pick."
        ),
    )
    driver_hint: str | None = Field(
        default=None,
        description=(
            "Preferred backend driver — one of ``bind9``, "
            "``powerdns``, ``technitium`` (agent-managed), "
            "``technitium_api`` (agentless, an install the operator "
            "already runs), or ``windows_dns``. Pair it with "
            "``dnssec_enabled=true`` to auto-select a group whose driver "
            "can sign online (``bind9``, ``powerdns`` and ``technitium`` "
            "all can; ``windows_dns`` and ``technitium_api`` cannot). "
            "When ``group_id`` is set, this is validated against the "
            "group's actual driver mix."
        ),
    )
    zone_type: str = Field(
        default="primary",
        description="Zone type — ``primary``, ``secondary``, ``forward``, or ``stub``.",
    )
    kind: str | None = Field(
        default=None,
        description=(
            "``forward`` (a normal name → record zone) or ``reverse`` (PTR zone). "
            "Omit it to take it from the name: a primary zone under in-addr.arpa / "
            "ip6.arpa is ``reverse`` (and cannot be ``forward``); any other zone "
            "defaults to ``forward``."
        ),
    )
    primary_ns: str = Field(
        default="",
        description="Primary nameserver FQDN (e.g. ``ns1.example.com.``). Recommended.",
    )
    admin_email: str = Field(
        default="",
        description="Zone admin email rendered into SOA RNAME (e.g. ``hostmaster@example.com``).",
    )
    dnssec_enabled: bool = Field(
        default=False,
        description=(
            "Turn on DNSSEC for this zone. Requires a group with a "
            "server whose driver signs online — ``bind9`` "
            "(inline-signing), ``powerdns`` or ``technitium``. "
            "``windows_dns`` and the cloud drivers cannot. Pair with a "
            "matching ``driver_hint`` to auto-select a compatible group."
        ),
    )
    ttl: int = Field(
        default=3600,
        description="Default record TTL in seconds.",
        ge=60,
        le=604_800,
    )


def _normalize_zone_name(raw: str) -> str:
    name = raw.strip()
    if not name:
        return ""
    return name if name.endswith(".") else name + "."


async def _resolve_group_for_zone(
    db: AsyncSession,
    *,
    group_id: str | None,
    driver_hint: str | None,
):
    """Return ``(group, drivers_set, error_text)``. On success
    ``error_text`` is empty; on failure ``group`` is ``None`` and
    ``error_text`` is the operator-facing reason.
    """
    from app.models.dns import DNSServer, DNSServerGroup  # noqa: PLC0415

    # Fetch every group + the distinct driver set so the preview can
    # pick by hint or validate explicit selections in one round trip.
    rows = (
        await db.execute(
            select(DNSServerGroup, DNSServer.driver)
            .outerjoin(DNSServer, DNSServer.group_id == DNSServerGroup.id)
            .order_by(DNSServerGroup.name)
        )
    ).all()
    by_id: dict[str, tuple[Any, set[str]]] = {}
    for grp, drv in rows:
        slot = by_id.setdefault(str(grp.id), (grp, set()))
        if drv:
            slot[1].add(drv)

    if group_id:
        slot = by_id.get(str(group_id))
        if slot is None:
            return None, set(), f"DNS server group {group_id!r} not found."
        grp, drivers = slot
        if driver_hint and drivers and driver_hint not in drivers:
            return (
                None,
                drivers,
                (
                    f"Group {grp.name!r} has drivers {sorted(drivers)} "
                    f"which doesn't include the requested "
                    f"driver_hint={driver_hint!r}. Pick a different "
                    f"group or drop the hint."
                ),
            )
        return grp, drivers, ""

    if driver_hint:
        candidates = [(grp, drivers) for grp, drivers in by_id.values() if driver_hint in drivers]
        if not candidates:
            available = sorted({d for _, ds in by_id.values() for d in ds})
            return (
                None,
                set(),
                (
                    f"No DNS server group has any {driver_hint!r} "
                    f"member. Available drivers: {available or '(none)'}."
                ),
            )
        # Tie-break by name so picks are deterministic.
        candidates.sort(key=lambda gd: gd[0].name)
        grp, drivers = candidates[0]
        return grp, drivers, ""

    # Neither group_id nor hint — surface the inventory so the LLM can
    # ask the operator for a pick instead of guessing.
    listing = ", ".join(
        f"{grp.name} ({sorted(ds) or ['no servers']})" for grp, ds in by_id.values()
    )
    return (
        None,
        set(),
        (
            "group_id or driver_hint is required. Available groups: "
            f"{listing or '(none configured)'}."
        ),
    )


async def _preview_create_dns_zone(
    db: AsyncSession, user: User, args: CreateDNSZoneArgs
) -> PreviewResult:
    from app.api.v1.dns.router import VALID_ZONE_TYPES, resolved_zone_kind  # noqa: PLC0415
    from app.models.dns import DNSZone  # noqa: PLC0415

    name = _normalize_zone_name(args.name)
    if not name:
        return PreviewResult(ok=False, detail="Zone name is required.")

    if args.zone_type not in VALID_ZONE_TYPES:
        return PreviewResult(
            ok=False, detail=f"zone_type must be one of {sorted(VALID_ZONE_TYPES)}."
        )

    # #1310 — the kind follows the name, as on the REST create.
    try:
        kind = resolved_zone_kind(name, args.kind, args.zone_type)
    except ValueError as exc:
        return PreviewResult(ok=False, detail=str(exc))

    if args.driver_hint is not None and args.driver_hint not in _DNS_DRIVER_HINTS:
        return PreviewResult(
            ok=False,
            detail=f"driver_hint must be one of {sorted(_DNS_DRIVER_HINTS)}.",
        )

    grp, drivers, err = await _resolve_group_for_zone(
        db, group_id=args.group_id, driver_hint=args.driver_hint
    )
    if grp is None:
        return PreviewResult(ok=False, detail=err)

    # Driver-gated zone features (currently DNSSEC) — see
    # ``_gated_zone_arg_conflict`` for the subset / fail-soft semantics.
    conflict = _gated_zone_arg_conflict(args, drivers, grp.name)
    if conflict is not None:
        return PreviewResult(ok=False, detail=conflict)

    existing = (
        await db.execute(
            select(DNSZone).where(
                DNSZone.group_id == grp.id,
                DNSZone.view_id.is_(None),
                DNSZone.name == name,
                DNSZone.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return PreviewResult(
            ok=False,
            detail=f"A zone named {name!r} already exists in group {grp.name!r}.",
        )

    parts = [f"Create zone `{name}` in group `{grp.name}`"]
    parts.append(f"drivers={sorted(drivers) or ['(none)']}")
    parts.append(f"type={args.zone_type}/{kind}")
    if args.dnssec_enabled:
        # #811: create now enqueues the ``dnssec_sign`` op itself, so the
        # preview no longer has to warn about a flag-only zone. BIND9
        # ignores the op (it signs inline from the rendered config bundle);
        # PowerDNS and Technitium consume it. The one caveat left is an
        # empty group — no server means no primary to queue against, so the
        # op is dropped and signing starts from a manual Sign later.
        if not drivers:
            parts.append(
                "DNSSEC=on (no servers in the group yet — run the zone's "
                "DNSSEC Sign action once servers join)"
            )
        elif drivers == {"bind9"}:
            parts.append("DNSSEC=on (bind9 signs inline from the config bundle)")
        else:
            parts.append("DNSSEC=on (sign op enqueued at create)")
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts))


async def _apply_create_dns_zone(
    db: AsyncSession, user: User, args: CreateDNSZoneArgs
) -> dict[str, Any]:
    from app.api.v1.dns.router import resolved_zone_kind  # noqa: PLC0415
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.dns import DNSZone  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — matches the DNS router's
    # require_any_resource_permission("dns_zone", ...) write gate.
    enforce_operation_permission(user, _OPERATIONS["create_dns_zone"])

    name = _normalize_zone_name(args.name)
    # #1310 — re-checked at apply, like the driver gate below.
    kind = resolved_zone_kind(name, args.kind, args.zone_type)
    grp, drivers, err = await _resolve_group_for_zone(
        db, group_id=args.group_id, driver_hint=args.driver_hint
    )
    if grp is None:
        raise ValueError(err)

    # Re-run the driver gate at apply time (#811) — servers can join the
    # group between proposal and approval, and an unsignable zone must not
    # land just because the preview predates the new member.
    conflict = _gated_zone_arg_conflict(args, drivers, grp.name)
    if conflict is not None:
        raise ValueError(conflict)

    zone = DNSZone(
        group_id=grp.id,
        name=name,
        zone_type=args.zone_type,
        kind=kind,
        ttl=args.ttl,
        primary_ns=args.primary_ns,
        admin_email=args.admin_email,
        dnssec_enabled=args.dnssec_enabled,
    )
    db.add(zone)
    await db.flush()

    # #811: enqueue the sign op the same way the REST create does — the
    # Copilot fronts the REST API and the two must stay in lockstep (#798).
    # BIND9 ignores the op (signs inline from the config bundle); PowerDNS
    # and Technitium sign in response to it.
    if args.dnssec_enabled:
        from app.services.dns.record_ops import enqueue_dnssec_op

        await enqueue_dnssec_op(db, zone, "dnssec_sign")

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="create",
            resource_type="dns_zone",
            resource_id=str(zone.id),
            resource_display=zone.name,
            result="success",
            new_value={
                "group_id": str(grp.id),
                "group": grp.name,
                "zone_type": args.zone_type,
                "kind": kind,
                "dnssec_enabled": args.dnssec_enabled,
                "driver_hint": args.driver_hint,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    # The /ai router mounts WITHOUT the wake_publishing dependency, so the
    # wake collect_wake buffered during the enqueue never flushes on this
    # path — publish directly after commit, like _apply_create_dns_record
    # above, or agents converge only on the 12 s WAKE_TICK safety tick.
    from app.core.agent_wake import dns_group_channel, publish_wake

    await publish_wake(dns_group_channel(grp.id))
    await db.refresh(zone)
    return {
        "id": str(zone.id),
        "group_id": str(grp.id),
        "name": name,
        "zone_type": args.zone_type,
        "kind": kind,
        "dnssec_enabled": args.dnssec_enabled,
    }


register(
    Operation(
        name="create_dns_zone",
        description=(
            "Create a new DNS zone. Honors driver_hint to route the "
            "zone onto a BIND9 / PowerDNS / Technitium / Windows DNS "
            "group; DNSSEC zones require a group whose driver signs "
            "online (bind9, powerdns or technitium)."
        ),
        args_model=CreateDNSZoneArgs,
        preview=_preview_create_dns_zone,
        apply=_apply_create_dns_zone,
        category="dns",
        required_permission=("write", "dns_zone"),
    )
)


# ── create_dhcp_static ────────────────────────────────────────────────


class CreateDHCPStaticArgs(BaseModel):
    """Args for the ``create_dhcp_static`` operation."""

    scope_id: str = Field(
        description="UUID of the parent DHCP scope.",
        # #759 — resource reference; see CreateIPAddressArgs.subnet_id.
        json_schema_extra={"x-resource": "dhcp_scope"},
    )
    ip_address: str = Field(description="IP to reserve (must fall inside the scope).")
    mac_address: str = Field(description="MAC address (any standard format).")
    hostname: str | None = Field(default=None, description="Optional hostname.")
    description: str = Field(default="", description="Free-form description.")


async def _preview_create_dhcp_static(
    db: AsyncSession, user: User, args: CreateDHCPStaticArgs
) -> PreviewResult:
    from app.models.dhcp import DHCPScope, DHCPStaticAssignment
    from app.models.ipam import Subnet

    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        return PreviewResult(ok=False, detail=f"DHCP scope {args.scope_id} not found.")

    # #923: the CIDR is on the related Subnet, not on DHCPScope — the scope
    # carries only ``subnet_id``. Reading ``scope.subnet`` raised
    # AttributeError, so this operation's preview AND apply both 500'd on
    # every call and creating a reservation from the copilot never worked.
    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        return PreviewResult(
            ok=False, detail=f"DHCP scope {args.scope_id} has no subnet to validate against."
        )

    try:
        addr_obj = ipaddress.ip_address(args.ip_address)
    except ValueError:
        return PreviewResult(ok=False, detail=f"Invalid IP {args.ip_address!r}.")

    try:
        net = ipaddress.ip_network(str(subnet.network), strict=False)
    except ValueError:
        return PreviewResult(ok=False, detail=f"Scope subnet {subnet.network!r} is unparseable.")
    if addr_obj not in net:
        return PreviewResult(
            ok=False,
            detail=(f"IP {args.ip_address} is outside scope subnet {subnet.network}."),
        )

    # Conflict probe — do NOT reject in preview; surface as a hint so
    # the operator can decide whether to abort or replace.
    existing = (
        await db.execute(
            select(DHCPStaticAssignment).where(
                DHCPStaticAssignment.scope_id == scope.id,
                or_(
                    DHCPStaticAssignment.ip_address == args.ip_address,
                    DHCPStaticAssignment.mac_address == args.mac_address.lower(),
                ),
            )
        )
    ).scalar_one_or_none()
    suffix = ""
    if existing is not None:
        suffix = " — note: a static for this IP or MAC already exists; apply will fail"

    parts = [
        f"Create DHCP static reservation in scope `{scope.name or subnet.network}`",
        f"ip={args.ip_address}",
        f"mac={args.mac_address}",
    ]
    if args.hostname:
        parts.append(f"hostname={args.hostname}")
    if args.description:
        d = args.description if len(args.description) < 80 else args.description[:77] + "..."
        parts.append(f"desc={d!r}")
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts) + suffix)


async def _apply_create_dhcp_static(
    db: AsyncSession, user: User, args: CreateDHCPStaticArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit
    from app.models.dhcp import DHCPScope, DHCPStaticAssignment
    from app.models.ipam import Subnet

    # SECURITY (#400, C2): RBAC backstop — matches the DHCP statics
    # router's require_resource_permission("dhcp_static") write gate.
    enforce_operation_permission(user, _OPERATIONS["create_dhcp_static"])

    scope = await db.get(DHCPScope, args.scope_id)
    if scope is None:
        raise ValueError(f"DHCP scope {args.scope_id} not found.")

    # #923 — see the preview above: the prefix lives on the related Subnet.
    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        raise ValueError(f"DHCP scope {args.scope_id} has no subnet to validate against.")

    addr_obj = ipaddress.ip_address(args.ip_address)
    net = ipaddress.ip_network(str(subnet.network), strict=False)
    if addr_obj not in net:
        raise ValueError(f"IP {args.ip_address} is outside scope subnet {subnet.network}.")

    row = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address=args.ip_address,
        mac_address=args.mac_address.lower(),
        hostname=args.hostname or "",
        description=args.description or "",
        created_by_user_id=user.id,
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp.static_assignment",
        resource_id=str(row.id),
        resource_display=f"{args.ip_address} ({args.mac_address})",
        new_value={
            "scope_id": str(scope.id),
            "ip_address": args.ip_address,
            "mac_address": args.mac_address.lower(),
            "hostname": args.hostname,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "scope_id": str(scope.id),
        "ip_address": args.ip_address,
        "mac_address": args.mac_address.lower(),
    }


register(
    Operation(
        name="create_dhcp_static",
        description=(
            "Create a DHCP static reservation (MAC → IP) inside a "
            "scope. Always route via propose_create_dhcp_static — the "
            "reservation propagates to the Kea / Windows DHCP backend "
            "on apply, so operator approval is required."
        ),
        args_model=CreateDHCPStaticArgs,
        preview=_preview_create_dhcp_static,
        apply=_apply_create_dhcp_static,
        category="dhcp",
        required_permission=("write", "dhcp_static"),
    )
)


# ── create_alert_rule ─────────────────────────────────────────────────
#
# Scoped to the simplest rule_type — ``subnet_utilization`` — so the
# tool is useful out of the box. Operators authoring the more complex
# ``compliance_change`` / ``domain_*`` types can keep doing it via the
# Alerts UI; we'd add per-rule_type proposers if the operator demand
# materialises.


class CreateAlertRuleArgs(BaseModel):
    """Args for the ``create_alert_rule`` operation (subnet_utilization)."""

    name: str = Field(description="Human-readable rule name.")
    threshold_percent: int = Field(
        description=(
            "Subnet utilization percent at which the rule fires. "
            "Range 1 – 100. Typical values: 80 (warning), 95 "
            "(critical)."
        ),
        ge=1,
        le=100,
    )
    severity: Literal["info", "warning", "critical"] = Field(
        default="warning",
        description="Alert severity assigned to events fired by this rule.",
    )
    description: str = Field(default="", description="Free-form description.")


async def _preview_create_alert_rule(
    db: AsyncSession, user: User, args: CreateAlertRuleArgs
) -> PreviewResult:
    parts = [
        f"Create alert rule **{args.name}**",
        "type=subnet_utilization",
        f"threshold={args.threshold_percent}%",
        f"severity={args.severity}",
    ]
    return PreviewResult(ok=True, detail="ready", preview_text=", ".join(parts))


async def _apply_create_alert_rule(
    db: AsyncSession, user: User, args: CreateAlertRuleArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit
    from app.core.permissions import is_effective_superadmin  # noqa: PLC0415
    from app.models.alerts import AlertRule

    # SECURITY (#400, C2): RBAC backstop — the REST POST /alerts/rules
    # route gates on _require_superadmin, so the AI apply does too.
    if not is_effective_superadmin(user):
        raise OperationPermissionError("admin", "alert_rule")

    row = AlertRule(
        name=args.name,
        description=args.description,
        rule_type="subnet_utilization",
        severity=args.severity,
        threshold_percent=args.threshold_percent,
        enabled=True,
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="alert.rule",
        resource_id=str(row.id),
        resource_display=args.name,
        new_value={
            "name": args.name,
            "rule_type": "subnet_utilization",
            "threshold_percent": args.threshold_percent,
            "severity": args.severity,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "name": args.name,
        "rule_type": "subnet_utilization",
        "threshold_percent": args.threshold_percent,
        "severity": args.severity,
    }


register(
    Operation(
        name="create_alert_rule",
        description=(
            "Create a subnet-utilization alert rule. Always route via "
            "propose_create_alert_rule. Other rule_type values (domain "
            "expiring, compliance_change, …) keep their UI authoring "
            "path; this proposer is scoped to the simplest case."
        ),
        args_model=CreateAlertRuleArgs,
        preview=_preview_create_alert_rule,
        apply=_apply_create_alert_rule,
        category="ops",
    )
)


# ── archive_session ───────────────────────────────────────────────────
#
# Quality-of-life write — sets ``AIChatSession.archived_at = now()`` so
# the session disappears from the History panel's default view without
# being permanently deleted. Restorable via the unarchive flow on the
# History panel.


class ArchiveSessionArgs(BaseModel):
    """Args for the ``archive_session`` operation."""

    session_id: str = Field(description="UUID of the AI chat session to archive.")


async def _preview_archive_session(
    db: AsyncSession, user: User, args: ArchiveSessionArgs
) -> PreviewResult:
    from app.models.ai import AIChatSession

    sess = await db.get(AIChatSession, args.session_id)
    if sess is None:
        return PreviewResult(ok=False, detail=f"Session {args.session_id} not found.")
    if sess.user_id != user.id:
        return PreviewResult(ok=False, detail="You can only archive your own chat sessions.")
    if sess.archived_at is not None:
        return PreviewResult(ok=False, detail=f"Session {args.session_id} is already archived.")
    label = sess.name or "Untitled"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=f"Archive chat session **{label}** (id `{sess.id}`)",
    )


async def _apply_archive_session(
    db: AsyncSession, user: User, args: ArchiveSessionArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit
    from app.models.ai import AIChatSession

    sess = await db.get(AIChatSession, args.session_id)
    if sess is None:
        raise ValueError(f"Session {args.session_id} not found.")
    if sess.user_id != user.id:
        raise ValueError("You can only archive your own chat sessions.")
    if sess.archived_at is not None:
        raise ValueError(f"Session {args.session_id} is already archived.")
    sess.archived_at = datetime.now(UTC)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="ai.chat_session",
        resource_id=str(sess.id),
        resource_display=sess.name or "Untitled",
        new_value={"archived_at": sess.archived_at.isoformat(), "via": "ai_proposal"},
    )
    await db.commit()
    return {"id": str(sess.id), "archived_at": sess.archived_at.isoformat()}


register(
    Operation(
        name="archive_session",
        description=(
            "Archive an AI chat session (your own only). Hides it from "
            "the default History view but keeps the data. Always route "
            "via propose_archive_session."
        ),
        args_model=ArchiveSessionArgs,
        preview=_preview_archive_session,
        apply=_apply_archive_session,
        category="ops",
    )
)


# ── create_multicast_group (issue #126 Phase 4) ─────────────────────


_IPV4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")


class CreateMulticastGroupArgs(BaseModel):
    """Args for the ``create_multicast_group`` operation.

    The address must sit inside ``224.0.0.0/4`` (IPv4) or
    ``ff00::/8`` (IPv6) — same CHECK constraint the DB layer
    enforces, surfaced here for clean preview rejection.
    """

    space_id: str = Field(description="UUID of the parent IPSpace that hosts this group.")
    address: str = Field(
        description=(
            "Multicast address. IPv4 inside 224.0.0.0/4 (e.g. "
            "239.5.7.42) or IPv6 inside ff00::/8 (e.g. ff05::1:3)."
        )
    )
    name: str = Field(description="Human-friendly name (e.g. 'Cam7 Studio-B HD').")
    application: str = Field(
        default="",
        description=(
            "Free-text application label — what's flowing on the "
            "wire. Examples: 'SMPTE 2110-20 video', 'Dante audio', "
            "'AAPL options L2'."
        ),
    )
    domain_id: str | None = Field(
        default=None,
        description=(
            "Optional PIM domain UUID. When supplied, the group "
            "binds to the domain's routing context."
        ),
    )
    rtp_payload_type: int | None = Field(
        default=None, ge=0, le=127, description="RTP payload type for media flows."
    )


def _validate_multicast_address(addr: str) -> str | None:
    """Returns an error string when ``addr`` isn't inside the IANA
    multicast ranges. ``None`` on success."""
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError as exc:
        return f"Invalid IP literal: {exc}"
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in _IPV4_MULTICAST:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed in _IPV6_MULTICAST:
        return None
    return (
        "Address must be inside 224.0.0.0/4 (IPv4) or ff00::/8 "
        "(IPv6) — the multicast registry only accepts addresses in "
        "those ranges."
    )


async def _preview_create_multicast_group(
    db: AsyncSession, user: User, args: CreateMulticastGroupArgs
) -> PreviewResult:
    from app.models.ipam import IPSpace  # noqa: PLC0415
    from app.models.multicast import (  # noqa: PLC0415
        MulticastDomain,
        MulticastGroup,
    )

    space = await db.get(IPSpace, args.space_id)
    if space is None:
        return PreviewResult(ok=False, detail=f"IPSpace {args.space_id!r} not found.")

    err = _validate_multicast_address(args.address)
    if err is not None:
        return PreviewResult(ok=False, detail=err)

    if args.domain_id is not None:
        if (await db.get(MulticastDomain, args.domain_id)) is None:
            return PreviewResult(ok=False, detail=f"Multicast domain {args.domain_id!r} not found.")

    # Soft-warn on duplicates (the registry doesn't enforce
    # uniqueness — the conformity check does — but a stale
    # MulticastGroup at the same address is almost always an
    # operator error).
    dup = (
        await db.execute(
            select(MulticastGroup.id, MulticastGroup.name).where(
                MulticastGroup.space_id == args.space_id,
                MulticastGroup.address == args.address,
            )
        )
    ).first()
    dup_note = ""
    if dup is not None:
        dup_note = (
            f"\n  - WARNING: address {args.address} is already used by "
            f"group {dup[1]!r} ({dup[0]}) in this space — the "
            "no_multicast_collision conformity rule will fire."
        )

    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Create multicast group:\n"
            f"  - address: {args.address}\n"
            f"  - name: {args.name}\n"
            f"  - application: {args.application or '(none)'}\n"
            f"  - space: {space.name} ({args.space_id})\n"
            f"  - domain_id: {args.domain_id or '(none)'}"
            f"{dup_note}"
        ),
    )


async def _apply_create_multicast_group(
    db: AsyncSession, user: User, args: CreateMulticastGroupArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.multicast import MulticastGroup  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — matches the multicast
    # router's require_resource_permission("multicast") write gate.
    enforce_operation_permission(user, _OPERATIONS["create_multicast_group"])

    err = _validate_multicast_address(args.address)
    if err is not None:
        raise ValueError(err)

    row = MulticastGroup(
        space_id=args.space_id,
        address=args.address,
        name=args.name,
        application=args.application,
        domain_id=args.domain_id,
        rtp_payload_type=args.rtp_payload_type,
    )
    db.add(row)
    await db.flush()

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="create",
            resource_type="multicast_group",
            resource_id=str(row.id),
            resource_display=f"{row.name} ({row.address})",
            result="success",
            new_value={
                "space_id": args.space_id,
                "address": args.address,
                "name": args.name,
                "application": args.application,
                "domain_id": args.domain_id,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "address": str(row.address),
        "name": row.name,
        "application": row.application,
        "space_id": str(row.space_id),
        "domain_id": str(row.domain_id) if row.domain_id else None,
    }


register(
    Operation(
        name="create_multicast_group",
        description=(
            "Create a multicast group registry entry. Address must "
            "be inside the IANA multicast ranges; the operator can "
            "rename / re-tag from the UI after the LLM-driven create."
        ),
        args_model=CreateMulticastGroupArgs,
        preview=_preview_create_multicast_group,
        apply=_apply_create_multicast_group,
        category="multicast",
        required_permission=("write", "multicast"),
    )
)


# ── allocate_multicast_groups (issue #126 Phase 4 Wave 2) ────────────


_MULTICAST_BULK_MAX = 256


class AllocateMulticastGroupsArgs(BaseModel):
    """Args for the ``allocate_multicast_groups`` bulk-stamp
    operation. Mirrors the shape of the existing
    ``POST /multicast/groups/bulk-allocate`` endpoint so the LLM
    learns one grammar that maps cleanly onto operator muscle
    memory."""

    space_id: str = Field(description="UUID of the parent IPSpace.")
    count: int = Field(
        ge=1,
        le=_MULTICAST_BULK_MAX,
        description=(
            f"Number of contiguous addresses to stamp (1..{_MULTICAST_BULK_MAX}). "
            "The cap matches the underlying REST endpoint — multicast "
            "registries are curated, not swept."
        ),
    )
    name_template: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Name template using the standard token set: ``{n}`` (counter), "
            "``{n:03d}`` (zero-padded), ``{n:x}`` (hex), and "
            "``{oct1}``-``{oct4}`` (octets of the rendered IP). Example: "
            "``cam-{n:02d}`` -> ``cam-01``, ``cam-02``..."
        ),
    )
    start_address: str = Field(
        description=(
            "First address in the run. Must sit inside 224.0.0.0/4 "
            "(IPv4) or ff00::/8 (IPv6); the run walks forward from "
            "here and 422s if it would exit the multicast range."
        ),
    )
    template_start: int = Field(
        default=1,
        ge=0,
        description="Initial value for the ``{n}`` token (default 1).",
    )
    application: str = Field(
        default="",
        description="Free-text application label applied to every group (e.g. 'SMPTE 2110 video').",
    )
    domain_id: str | None = Field(
        default=None,
        description="Optional PIM domain UUID to bind every new group to.",
    )


async def _bulk_allocate_helper(
    db: AsyncSession, args: AllocateMulticastGroupsArgs
) -> tuple[list[Any], int, str | None]:
    """Re-runs the same candidate builder the REST bulk-allocate
    endpoint uses (``api.v1.multicast.router._build_bulk_candidates``)
    so the LLM-driven flow shares one validation path with the UI.

    Returns ``(items, conflict_count, error_message)``. ``error_message``
    is non-None when a hard validation fails (bad address class, run
    walks past the multicast range, etc) — the operation surfaces it
    as a preview rejection.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from app.api.v1.multicast.router import (  # noqa: PLC0415
        MulticastBulkAllocateRequest,
        _build_bulk_candidates,
    )

    try:
        body = MulticastBulkAllocateRequest(
            space_id=args.space_id,  # type: ignore[arg-type]
            count=args.count,
            name_template=args.name_template,
            start_address=args.start_address,
            template_start=args.template_start,
            application=args.application,
            domain_id=args.domain_id,  # type: ignore[arg-type]
        )
    except Exception as exc:  # pydantic ValidationError or similar
        return [], 0, str(exc)

    try:
        items = await _build_bulk_candidates(db, body)
    except HTTPException as exc:
        # ``_build_bulk_candidates`` raises 422 when the run would
        # walk past the multicast range. Surface the operator-
        # friendly detail rather than the HTTP shape.
        return [], 0, str(exc.detail)

    conflicts = sum(1 for it in items if it.conflict is not None)
    return items, conflicts, None


async def _preview_allocate_multicast_groups(
    db: AsyncSession, user: User, args: AllocateMulticastGroupsArgs
) -> PreviewResult:
    from app.models.ipam import IPSpace  # noqa: PLC0415
    from app.models.multicast import MulticastDomain  # noqa: PLC0415

    if (await db.get(IPSpace, args.space_id)) is None:
        return PreviewResult(ok=False, detail=f"IPSpace {args.space_id!r} not found.")
    if args.domain_id is not None:
        if (await db.get(MulticastDomain, args.domain_id)) is None:
            return PreviewResult(
                ok=False,
                detail=f"Multicast domain {args.domain_id!r} not found.",
            )

    items, conflict_count, err = await _bulk_allocate_helper(db, args)
    if err is not None:
        return PreviewResult(ok=False, detail=err)

    if conflict_count > 0:
        # Render the colliding addresses inline so the operator sees
        # what to renumber. The chat surface clips long previews
        # gracefully; the proposal can still be applied if the LLM
        # presents it (the apply layer re-runs the candidate
        # builder + 409s cleanly).
        conflict_lines = "\n".join(f"    - {it.address} (in use)" for it in items if it.conflict)[
            :1000
        ]
        return PreviewResult(
            ok=False,
            detail=(
                f"{conflict_count} of {len(items)} addresses are already "
                f"taken — adjust ``start_address`` or ``count``:\n"
                f"{conflict_lines}"
            ),
        )

    sample = ", ".join(f"{it.address}={it.name}" for it in items[:3])
    if len(items) > 3:
        sample += f", … (+{len(items) - 3} more)"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Bulk-allocate {len(items)} multicast group(s) starting at "
            f"{args.start_address}:\n"
            f"  - template: {args.name_template} (start {args.template_start})\n"
            f"  - application: {args.application or '(none)'}\n"
            f"  - domain_id: {args.domain_id or '(none)'}\n"
            f"  - sample: {sample}"
        ),
    )


async def _apply_allocate_multicast_groups(
    db: AsyncSession, user: User, args: AllocateMulticastGroupsArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.multicast import MulticastGroup  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — matches the multicast
    # router's require_resource_permission("multicast") write gate.
    enforce_operation_permission(user, _OPERATIONS["allocate_multicast_groups"])

    items, conflict_count, err = await _bulk_allocate_helper(db, args)
    if err is not None:
        raise ValueError(err)
    if conflict_count > 0:
        raise ValueError(
            f"{conflict_count} address(es) already in use; re-run preview "
            "after adjusting start_address or count."
        )

    created_ids: list[str] = []
    for item in items:
        row = MulticastGroup(
            space_id=args.space_id,
            address=item.address,
            name=item.name,
            application=args.application,
            domain_id=args.domain_id,
        )
        db.add(row)
        await db.flush()
        created_ids.append(str(row.id))

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="bulk_allocate",
            resource_type="multicast_group",
            resource_id=str(args.space_id),
            resource_display=(f"{len(created_ids)} group(s) starting at {args.start_address}"),
            result="success",
            new_value={
                "count": len(created_ids),
                "start_address": args.start_address,
                "name_template": args.name_template,
                "space_id": args.space_id,
                "domain_id": args.domain_id,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    return {
        "created": len(created_ids),
        "group_ids": created_ids,
        "start_address": args.start_address,
    }


register(
    Operation(
        name="allocate_multicast_groups",
        description=(
            "Bulk-stamp N sequential multicast groups with a name "
            "template. Capped at 256. Refuses if any candidate "
            "address already has a group in the same space; "
            "operator must re-preview after adjusting start / count."
        ),
        args_model=AllocateMulticastGroupsArgs,
        preview=_preview_allocate_multicast_groups,
        apply=_apply_allocate_multicast_groups,
        category="multicast",
        required_permission=("write", "multicast"),
    )
)


# ── approve_appliance operation (#170 Wave D2) ────────────────────


class ApproveApplianceArgs(BaseModel):
    """Args for the ``approve_appliance`` operation. The LLM passes the
    appliance_id as a string; we resolve to UUID inside preview/apply."""

    appliance_id: str = Field(description="UUID of the pending appliance row.")


async def _preview_approve_appliance(
    db: AsyncSession, user: User, args: ApproveApplianceArgs
) -> PreviewResult:
    from app.models.appliance import (  # noqa: PLC0415 — avoid cycle
        APPLIANCE_STATE_APPROVED,
        APPLIANCE_STATE_PENDING_APPROVAL,
        Appliance,
    )

    try:
        appliance_uuid = UUID(args.appliance_id)
    except ValueError:
        return PreviewResult(
            ok=False, detail=f"appliance_id must be a UUID, got {args.appliance_id!r}"
        )
    row = await db.get(Appliance, appliance_uuid)
    if row is None:
        return PreviewResult(ok=False, detail=f"No appliance with id {args.appliance_id}.")
    if row.state == APPLIANCE_STATE_APPROVED:
        return PreviewResult(
            ok=False,
            detail=(
                f"Appliance {row.hostname!r} is already approved. Use "
                "the Re-key action (UI: Fleet tab drilldown) if you "
                "need a fresh cert."
            ),
        )
    if row.state != APPLIANCE_STATE_PENDING_APPROVAL:
        return PreviewResult(
            ok=False,
            detail=f"Appliance {row.hostname!r} is in state {row.state!r}; only pending appliances can be approved.",
        )

    caps = row.capabilities or {}
    cap_summary = ", ".join(sorted(k for k, v in caps.items() if k.startswith("can_run_") and v))
    preview_lines = [
        f"Approve **{row.hostname}** ({appliance_uuid})",
        f"fingerprint: `{row.public_key_fingerprint[:12]}…`",
        f"supervisor_version: {row.supervisor_version or '(unknown)'}",
        f"paired_from_ip: {row.paired_from_ip or '(unknown)'}",
        f"capabilities: {cap_summary or '(none advertised)'}",
        "",
        # Explicit ``+`` concatenation rather than implicit
        # adjacent-string-literal joining — CodeQL flags the latter
        # in list literals as a possible missing-comma bug.
        "This will sign an X.509 cert against the supervisor's "
        + "Ed25519 pubkey using the control plane's internal CA. "
        + "The serial is recorded in the audit log; the cert is "
        + "valid for 90 days. The supervisor picks it up on its "
        + "next /supervisor/poll and switches from session-token "
        + "auth to mTLS.",
    ]
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(preview_lines))


async def _apply_approve_appliance(
    db: AsyncSession, user: User, args: ApproveApplianceArgs
) -> dict[str, Any]:
    """Mirror the ``approve_appliance`` REST endpoint. Lazy CA
    bootstrap on first approve; signs a cert against the existing
    pubkey; writes the cert columns + audit row."""
    from app.models.appliance import (  # noqa: PLC0415
        APPLIANCE_STATE_APPROVED,
        Appliance,
    )
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.services.appliance.ca import (  # noqa: PLC0415
        ensure_ca,
        sign_supervisor_cert,
    )

    # SECURITY (#400, C2): RBAC backstop — matches the REST approve
    # route's require_permission("admin", "appliance"). High-blast-
    # radius (mints a cert), so the gate is mandatory at apply.
    enforce_operation_permission(user, _OPERATIONS["approve_appliance"])

    appliance_uuid = UUID(args.appliance_id)
    row = await db.get(Appliance, appliance_uuid)
    if row is None:
        raise ValueError(f"Appliance {args.appliance_id} not found.")
    if row.state == APPLIANCE_STATE_APPROVED:
        # Apply is idempotent on the rare race where the operator
        # clicked Approve in the UI between preview + apply.
        return {"appliance_id": str(row.id), "already_approved": True}

    ca = await ensure_ca(db)
    cert_pem, serial_hex, issued_at, expires_at = sign_supervisor_cert(
        ca=ca,
        appliance_id=row.id,
        public_key_der=row.public_key_der,
        public_key_fingerprint=row.public_key_fingerprint,
        hostname=row.hostname,
    )
    row.cert_pem = cert_pem
    row.cert_serial = serial_hex
    row.cert_issued_at = issued_at
    row.cert_expires_at = expires_at
    row.state = APPLIANCE_STATE_APPROVED
    row.approved_at = issued_at
    row.approved_by_user_id = user.id
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="appliance.approved",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "hostname": row.hostname,
                "fingerprint": row.public_key_fingerprint,
                "cert_serial": serial_hex,
                "cert_expires_at": expires_at.isoformat(),
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    return {
        "appliance_id": str(row.id),
        "hostname": row.hostname,
        "cert_serial": serial_hex,
        "cert_expires_at": expires_at.isoformat(),
    }


register(
    Operation(
        name="approve_appliance",
        description=(
            "Approve a pending Application appliance. Signs an X.509 "
            "cert against the supervisor's Ed25519 pubkey using the "
            "control plane's internal CA."
        ),
        args_model=ApproveApplianceArgs,
        preview=_preview_approve_appliance,
        apply=_apply_approve_appliance,
        category="admin",
        required_permission=("admin", "appliance"),
    )
)


# ── assign_appliance_role operation ───────────────────────────────


class AssignApplianceRoleArgs(BaseModel):
    """Args for the ``assign_appliance_role`` operation. Mirrors the
    REST endpoint's body shape but typed looser (string UUIDs)."""

    appliance_id: str = Field(description="UUID of the approved appliance row.")
    roles: list[str] = Field(
        description=(
            "Subset of dns-bind9 / dns-powerdns / dns-technitium / dhcp / "
            "observer / custom. The three dns-* roles are mutually exclusive."
        )
    )
    dns_group_id: str | None = None
    dhcp_group_id: str | None = None


_APPL_VALID_ROLES = {
    "dns-bind9",
    "dns-powerdns",
    "dns-technitium",
    "dhcp",
    "observer",
    "custom",
}
_APPL_DNS_ROLES = {"dns-bind9", "dns-powerdns", "dns-technitium"}


async def _preview_assign_appliance_role(
    db: AsyncSession, user: User, args: AssignApplianceRoleArgs
) -> PreviewResult:
    from app.models.appliance import (  # noqa: PLC0415
        APPLIANCE_STATE_APPROVED,
        Appliance,
    )

    try:
        appliance_uuid = UUID(args.appliance_id)
    except ValueError:
        return PreviewResult(
            ok=False, detail=f"appliance_id must be a UUID, got {args.appliance_id!r}"
        )
    row = await db.get(Appliance, appliance_uuid)
    if row is None:
        return PreviewResult(ok=False, detail=f"No appliance with id {args.appliance_id}.")
    if row.state != APPLIANCE_STATE_APPROVED:
        return PreviewResult(
            ok=False,
            detail=f"Appliance is in state {row.state!r}; only approved appliances can be assigned roles.",
        )
    for r in args.roles:
        if r not in _APPL_VALID_ROLES:
            return PreviewResult(
                ok=False, detail=f"Unknown role {r!r}. Valid: {sorted(_APPL_VALID_ROLES)}."
            )
    dns_engines = _APPL_DNS_ROLES.intersection(args.roles)
    if len(dns_engines) > 1:
        return PreviewResult(
            ok=False,
            detail=f"{sorted(dns_engines)} are mutually exclusive — one DNS engine per appliance.",
        )
    caps = row.capabilities or {}
    for r in args.roles:
        cap_key = {
            "dns-bind9": "can_run_dns_bind9",
            "dns-powerdns": "can_run_dns_powerdns",
            "dhcp": "can_run_dhcp",
            "observer": "can_run_observer",
        }.get(r)
        if cap_key is not None and not caps.get(cap_key, False):
            return PreviewResult(
                ok=False,
                detail=(
                    f"Appliance {row.hostname!r} doesn't advertise "
                    f"{cap_key}=true; cannot assign role {r!r}."
                ),
            )
    group_problem = await _assign_role_group_problem(db, args)
    if group_problem is not None:
        return PreviewResult(ok=False, detail=group_problem)

    preview_lines = [
        f"Assign roles to **{row.hostname}** ({appliance_uuid})",
        f"roles: {', '.join(args.roles) if args.roles else '(idle)'}",
    ]
    if args.dns_group_id:
        preview_lines.append(f"dns_group_id: {args.dns_group_id}")
    if args.dhcp_group_id:
        preview_lines.append(f"dhcp_group_id: {args.dhcp_group_id}")
    preview_lines.append(
        "The supervisor's next heartbeat reads the new role set + "
        "starts / stops service containers accordingly."
    )
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(preview_lines))


async def _assign_role_group_problem(db: AsyncSession, args: AssignApplianceRoleArgs) -> str | None:
    """Why a group in ``args`` can't be assigned, or None (#1468).

    Same rule as the REST role-assign route: the supervisor drops a group
    name it won't put in the role env, so refuse it here instead.
    """
    from app.models.dhcp import DHCPServerGroup  # noqa: PLC0415
    from app.models.dns import DNSServerGroup  # noqa: PLC0415
    from app.services.appliance.group_names import group_name_problem  # noqa: PLC0415

    if args.dns_group_id:
        try:
            dns_group = await db.get(DNSServerGroup, UUID(args.dns_group_id))
        except ValueError:
            return f"dns_group_id must be a UUID, got {args.dns_group_id!r}"
        if dns_group is None:
            return f"DNS group {args.dns_group_id} not found."
        problem = group_name_problem("dns", dns_group.name)
        if problem is not None:
            return problem
    if args.dhcp_group_id:
        try:
            dhcp_group = await db.get(DHCPServerGroup, UUID(args.dhcp_group_id))
        except ValueError:
            return f"dhcp_group_id must be a UUID, got {args.dhcp_group_id!r}"
        if dhcp_group is None:
            return f"DHCP group {args.dhcp_group_id} not found."
        return group_name_problem("dhcp", dhcp_group.name)
    return None


async def _apply_assign_appliance_role(
    db: AsyncSession, user: User, args: AssignApplianceRoleArgs
) -> dict[str, Any]:
    from app.models.appliance import Appliance  # noqa: PLC0415
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.dhcp import DHCPServerGroup  # noqa: PLC0415
    from app.models.dns import DNSServerGroup  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — matches the REST role-assign
    # route's require_permission("admin", "appliance").
    enforce_operation_permission(user, _OPERATIONS["assign_appliance_role"])

    appliance_uuid = UUID(args.appliance_id)
    row = await db.get(Appliance, appliance_uuid)
    if row is None:
        raise ValueError(f"Appliance {args.appliance_id} not found.")
    # Re-checked at apply: a group can be renamed between preview and apply.
    group_problem = await _assign_role_group_problem(db, args)
    if group_problem is not None:
        raise ValueError(group_problem)
    row.assigned_roles = list(args.roles)
    if args.dns_group_id:
        dns_group = await db.get(DNSServerGroup, UUID(args.dns_group_id))
        if dns_group is None:
            raise ValueError(f"DNS group {args.dns_group_id} not found.")
        row.assigned_dns_group_id = dns_group.id
    if args.dhcp_group_id:
        dhcp_group = await db.get(DHCPServerGroup, UUID(args.dhcp_group_id))
        if dhcp_group is None:
            raise ValueError(f"DHCP group {args.dhcp_group_id} not found.")
        row.assigned_dhcp_group_id = dhcp_group.id
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="appliance.role_assigned",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "roles": list(args.roles),
                "dns_group_id": args.dns_group_id,
                "dhcp_group_id": args.dhcp_group_id,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()
    return {
        "appliance_id": str(row.id),
        "hostname": row.hostname,
        "roles": list(args.roles),
    }


register(
    Operation(
        name="assign_appliance_role",
        description=(
            "Assign roles + groups to an approved appliance. "
            "Validates against advertised capabilities + the "
            "one-DNS-engine-per-box rule before applying."
        ),
        args_model=AssignApplianceRoleArgs,
        preview=_preview_assign_appliance_role,
        apply=_apply_assign_appliance_role,
        category="admin",
        required_permission=("admin", "appliance"),
    )
)


# ── toggle_firewall_policy operation (#285 Phase 3e) ──────────────


class ToggleFirewallPolicyArgs(BaseModel):
    """Args for ``toggle_firewall_policy`` — enable/disable a policy."""

    policy_id: str = Field(description="UUID of the firewall policy.")
    enabled: bool = Field(description="Desired enabled state.")


async def _preview_toggle_firewall_policy(
    db: AsyncSession, user: User, args: ToggleFirewallPolicyArgs
) -> PreviewResult:
    from app.models.firewall import FirewallPolicy  # noqa: PLC0415

    try:
        pid = UUID(args.policy_id)
    except ValueError:
        return PreviewResult(ok=False, detail=f"policy_id must be a UUID, got {args.policy_id!r}")
    p = await db.get(FirewallPolicy, pid)
    if p is None:
        return PreviewResult(ok=False, detail=f"No firewall policy with id {args.policy_id}.")
    if p.enabled == args.enabled:
        state = "enabled" if args.enabled else "disabled"
        return PreviewResult(ok=False, detail=f"Policy {p.name!r} is already {state}.")
    verb = "Enable" if args.enabled else "Disable"
    if p.scope_kind == "appliance":
        scope = f"appliance/{p.scope_appliance_id}"  # disambiguate per-appliance overrides
    elif p.scope_role:
        scope = f"{p.scope_kind}/{p.scope_role}"
    else:
        scope = p.scope_kind
    text = (
        f"{verb} firewall policy **{p.name}** (scope {scope}). Takes effect on the "
        "next supervisor heartbeat — but only renders to a node when the "
        "firewall_enabled master switch is on."
    )
    return PreviewResult(ok=True, detail=text, preview_text=text)


async def _apply_toggle_firewall_policy(
    db: AsyncSession, user: User, args: ToggleFirewallPolicyArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.models.firewall import FirewallPolicy  # noqa: PLC0415
    from app.services.appliance.firewall_merge import reset_policy_cache  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — the fleet-firewall routes
    # gate on require_permission("admin", "appliance").
    enforce_operation_permission(user, _OPERATIONS["toggle_firewall_policy"])

    p = await db.get(FirewallPolicy, UUID(args.policy_id))
    if p is None:
        return {"error": f"No firewall policy with id {args.policy_id}."}
    p.enabled = args.enabled
    p.updated_by_id = user.id
    db.add(
        AuditLog(
            action="update",
            resource_type="firewall_policy",
            resource_id=str(p.id),
            resource_display=p.name,
            user_id=user.id,
            user_display_name=user.username,
            result="success",
            changed_fields=["enabled"],
            new_value={"enabled": args.enabled},
        )
    )
    await db.commit()
    reset_policy_cache()
    return {"policy_id": str(p.id), "name": p.name, "enabled": p.enabled}


register(
    Operation(
        name="toggle_firewall_policy",
        description="Enable or disable a fleet-firewall policy.",
        args_model=ToggleFirewallPolicyArgs,
        preview=_preview_toggle_firewall_policy,
        apply=_apply_toggle_firewall_policy,
        category="admin",
        required_permission=("admin", "appliance"),
    )
)


# ── grant_temporary_access (issue #65) ─────────────────────────────────
#
# Attach a temporary, auto-expiring ``{action, resource_type,
# resource_id?}`` permission to a group. ``user_has_permission`` unions
# live time-bound grants over the static role grants, so the operator gets
# the widened access immediately and it auto-revokes at ``expires_at``.
# Superadmin-gated at apply time — minting permissions is a high-blast-radius
# write that should never ride a non-superadmin's chat session.


class GrantTemporaryAccessArgs(BaseModel):
    """Args for the ``grant_temporary_access`` operation."""

    group_id: str = Field(description="UUID of the group to grant temporary access to.")
    action: Literal["read", "write", "delete", "admin", "*"] = Field(
        description="Permission action. 'admin' implies read/write/delete on the type.",
    )
    resource_type: str = Field(
        description=(
            "Resource type the grant applies to (e.g. 'subnet', 'dns_zone', "
            "'dhcp_scope'). '*' matches any type. See docs/PERMISSIONS.md."
        )
    )
    resource_id: str | None = Field(
        default=None,
        description=(
            "Optional UUID to scope the grant to a single instance. Omit for "
            "the whole resource_type."
        ),
    )
    expires_in_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="How long the grant stays live, in hours (1 – 720; default 24).",
    )
    reason: str = Field(
        default="",
        description="Why the access is being granted — recorded in the audit log.",
    )


async def _preview_grant_temporary_access(
    db: AsyncSession, user: User, args: GrantTemporaryAccessArgs
) -> PreviewResult:
    from app.core.permissions import is_effective_superadmin  # noqa: PLC0415
    from app.models.auth import Group  # noqa: PLC0415

    if not is_effective_superadmin(user):
        return PreviewResult(
            ok=False,
            detail=(
                "Granting temporary access mints RBAC permissions, so it's "
                "restricted to superadmin users."
            ),
        )
    try:
        gid = UUID(args.group_id)
    except (ValueError, AttributeError):
        return PreviewResult(ok=False, detail=f"Invalid group_id: {args.group_id!r}")
    group = await db.get(Group, gid)
    if group is None:
        return PreviewResult(ok=False, detail=f"No group with id {args.group_id}.")
    expires = datetime.now(UTC) + timedelta(hours=args.expires_in_hours)
    scope = f"/{args.resource_id}" if args.resource_id else " (any instance)"
    preview_text = (
        f"Grant **{args.action}** on **{args.resource_type}**{scope} "
        f"to group **{group.name}** until {expires.isoformat()} "
        f"({args.expires_in_hours}h). Auto-revokes on expiry."
    )
    return PreviewResult(ok=True, detail="ready", preview_text=preview_text)


async def _apply_grant_temporary_access(
    db: AsyncSession, user: User, args: GrantTemporaryAccessArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.core.permissions import is_effective_superadmin  # noqa: PLC0415
    from app.models.auth import Group  # noqa: PLC0415
    from app.models.time_bound_grant import TimeBoundGrant  # noqa: PLC0415

    if not is_effective_superadmin(user):
        raise ValueError("Granting temporary access is restricted to superadmin users.")
    group = await db.get(Group, UUID(args.group_id))
    if group is None:
        raise ValueError(f"No group with id {args.group_id}.")
    resource_id = (args.resource_id or "").strip() or None
    expires = datetime.now(UTC) + timedelta(hours=args.expires_in_hours)
    grant = TimeBoundGrant(
        group_id=group.id,
        action=args.action,
        resource_type=args.resource_type,
        resource_id=resource_id,
        expires_at=expires,
        reason=args.reason,
        granted_by_user_id=user.id,
    )
    db.add(grant)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="permission_change",
        resource_type="time_bound_grant",
        resource_id=str(grant.id),
        resource_display=(
            f"Granted {args.action} on {args.resource_type}"
            f"{('/' + resource_id) if resource_id else ''} to group {group.name}"
        ),
        new_value={
            "group_id": str(group.id),
            "action": args.action,
            "resource_type": args.resource_type,
            "resource_id": resource_id,
            "expires_at": expires.isoformat(),
            "reason": args.reason,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(grant)
    return {
        "id": str(grant.id),
        "group_id": str(group.id),
        "action": args.action,
        "resource_type": args.resource_type,
        "resource_id": resource_id,
        "expires_at": expires.isoformat(),
    }


register(
    Operation(
        name="grant_temporary_access",
        description=(
            "Grant a group a temporary, auto-expiring RBAC permission "
            "(issue #65). Superadmin only. Always route via "
            "propose_grant_temporary_access — the operator clicks Apply to "
            "mint the grant."
        ),
        args_model=GrantTemporaryAccessArgs,
        preview=_preview_grant_temporary_access,
        apply=_apply_grant_temporary_access,
        category="admin",
    )
)


# ── approve / reject change request (#62 two-person spine) ─────────────
#
# The change-request approval flow is itself an Operation so the Copilot
# can surface "approve change request X" as a propose→Apply card. The
# propose tool only persists a proposal (read-only); the human operator
# who clicks Apply in the chat drawer becomes the *approver*, and the
# server-side two-person invariants in apply() still fire — the model can
# never self-approve. The whole spine (self-approval block, approver !=
# requester, approver holds {approve, change_request} AND the underlying
# op's required_permission, stale-state re-preview, execute-under-approver)
# lives in services/approvals/service.py and is shared verbatim with the
# REST router so there is exactly one implementation of the invariants.
#
# required_permission=("approve", "change_request") is the apply endpoint's
# authoritative RBAC backstop (#400, C2); the deeper checks (self-approval,
# underlying-op permission, stale state) run inside the shared orchestrator.


class ApproveChangeRequestArgs(BaseModel):
    """Args for the ``approve_change_request`` operation."""

    change_request_id: str = Field(description="UUID of the pending change request to approve.")
    note: str | None = Field(
        default=None,
        description="Optional decision note recorded on the change request.",
    )


class RejectChangeRequestArgs(BaseModel):
    """Args for the ``reject_change_request`` operation."""

    change_request_id: str = Field(description="UUID of the pending change request to reject.")
    note: str | None = Field(
        default=None,
        description="Optional decision note recorded on the change request.",
    )


def _parse_cr_id(raw: str) -> UUID | None:
    try:
        return UUID(str(raw))
    except (ValueError, AttributeError):
        return None


async def _preview_approve_change_request(
    db: AsyncSession, user: User, args: ApproveChangeRequestArgs
) -> PreviewResult:
    """Surface every two-person failure mode as ``ok=False`` so the propose
    tool returns ``proposal_rejected`` rather than queuing a doomed proposal.
    Read-only — mirrors the early checks the shared orchestrator re-runs."""
    from app.core.permissions import (  # noqa: PLC0415
        RESOURCE_TYPE_CHANGE_REQUEST,
        user_has_permission,
    )
    from app.services.approvals.service import get_change_request  # noqa: PLC0415

    cr_id = _parse_cr_id(args.change_request_id)
    if cr_id is None:
        return PreviewResult(
            ok=False, detail=f"Invalid change request id: {args.change_request_id!r}"
        )
    cr = await get_change_request(db, cr_id)
    if cr is None:
        return PreviewResult(ok=False, detail=f"Change request {args.change_request_id} not found.")
    if cr.state != "pending":
        return PreviewResult(
            ok=False, detail=f"Change request is not pending (state={cr.state!r})."
        )
    if cr.expires_at < datetime.now(UTC):
        return PreviewResult(ok=False, detail="Change request has expired.")
    # #5 fail CLOSED: a deleted requester (requested_by_user_id NULL) is
    # refused, not silently approvable — mirrors approve_change_request.
    if cr.requested_by_user_id is None:
        return PreviewResult(
            ok=False,
            detail="Requester no longer exists; cancel and recreate this change request.",
        )
    if user.id == cr.requested_by_user_id:
        return PreviewResult(ok=False, detail="You cannot approve your own change request.")
    if not user_has_permission(user, "approve", RESOURCE_TYPE_CHANGE_REQUEST):
        return PreviewResult(
            ok=False, detail="Permission denied: need 'approve' on 'change_request'."
        )
    op = get_operation(cr.operation)
    if op is None:
        return PreviewResult(ok=False, detail=f"Operation {cr.operation!r} is not registered.")
    try:
        enforce_operation_permission(user, op)
    except OperationPermissionError as exc:
        return PreviewResult(ok=False, detail=str(exc))
    # Re-run the underlying op's preview as the stale-state guard.
    try:
        inner_args = op.args_model.model_validate(cr.args or {})
    except Exception as exc:  # noqa: BLE001
        return PreviewResult(ok=False, detail=f"Stored args no longer validate: {exc}")
    inner = await op.preview(db, user, inner_args)
    if not inner.ok:
        return PreviewResult(ok=False, detail=f"Stale change request: {inner.detail}")
    preview_text = (
        f"Approve + execute change request `{cr.id}` "
        f"({cr.operation} on {cr.resource_display}), requested by "
        f"{cr.requested_by_display}. On Apply it runs under YOUR identity "
        f"after re-validating state. Underlying preview:\n{inner.preview_text}"
    )
    return PreviewResult(ok=True, detail="ready", preview_text=preview_text)


async def _apply_approve_change_request(
    db: AsyncSession, user: User, args: ApproveChangeRequestArgs
) -> dict[str, Any]:
    """Approve + execute under the approver's identity. Delegates to the
    shared orchestrator so the two-person invariants are enforced once,
    server-side, identically to the REST router."""
    from app.services.approvals.service import (  # noqa: PLC0415
        DecisionError,
        DecisionForbidden,
        approve_change_request,
    )

    enforce_operation_permission(user, _OPERATIONS["approve_change_request"])

    cr_id = _parse_cr_id(args.change_request_id)
    if cr_id is None:
        raise ValueError(f"Invalid change request id: {args.change_request_id!r}")
    try:
        cr = await approve_change_request(db, cr_id, approver=user, request=None, note=args.note)
    except DecisionForbidden as exc:
        # Map the self-approval / missing-permission case to the op's RBAC
        # error so the apply endpoint returns a clean 403.
        raise OperationPermissionError("approve", "change_request") from exc
    except DecisionError as exc:
        raise ValueError(str(exc)) from exc
    return {
        "id": str(cr.id),
        "operation": cr.operation,
        "state": cr.state,
        "result": cr.result,
        "error": cr.error,
    }


async def _preview_reject_change_request(
    db: AsyncSession, user: User, args: RejectChangeRequestArgs
) -> PreviewResult:
    from app.core.permissions import (  # noqa: PLC0415
        RESOURCE_TYPE_CHANGE_REQUEST,
        user_has_permission,
    )
    from app.services.approvals.service import get_change_request  # noqa: PLC0415

    cr_id = _parse_cr_id(args.change_request_id)
    if cr_id is None:
        return PreviewResult(
            ok=False, detail=f"Invalid change request id: {args.change_request_id!r}"
        )
    cr = await get_change_request(db, cr_id)
    if cr is None:
        return PreviewResult(ok=False, detail=f"Change request {args.change_request_id} not found.")
    if cr.state != "pending":
        return PreviewResult(
            ok=False, detail=f"Change request is not pending (state={cr.state!r})."
        )
    if cr.requested_by_user_id is not None and user.id == cr.requested_by_user_id:
        return PreviewResult(
            ok=False, detail="You cannot reject your own request — cancel it instead."
        )
    if not user_has_permission(user, "approve", RESOURCE_TYPE_CHANGE_REQUEST):
        return PreviewResult(
            ok=False, detail="Permission denied: need 'approve' on 'change_request'."
        )
    preview_text = (
        f"Reject change request `{cr.id}` "
        f"({cr.operation} on {cr.resource_display}), requested by "
        f"{cr.requested_by_display}. The operation will NOT run."
    )
    return PreviewResult(ok=True, detail="ready", preview_text=preview_text)


async def _apply_reject_change_request(
    db: AsyncSession, user: User, args: RejectChangeRequestArgs
) -> dict[str, Any]:
    from app.services.approvals.service import (  # noqa: PLC0415
        DecisionError,
        DecisionForbidden,
        reject_change_request,
    )

    enforce_operation_permission(user, _OPERATIONS["reject_change_request"])

    cr_id = _parse_cr_id(args.change_request_id)
    if cr_id is None:
        raise ValueError(f"Invalid change request id: {args.change_request_id!r}")
    try:
        cr = await reject_change_request(db, cr_id, approver=user, request=None, note=args.note)
    except DecisionForbidden as exc:
        raise OperationPermissionError("approve", "change_request") from exc
    except DecisionError as exc:
        raise ValueError(str(exc)) from exc
    return {"id": str(cr.id), "operation": cr.operation, "state": cr.state}


register(
    Operation(
        name="approve_change_request",
        description=(
            "Approve a pending two-person change request (#62). Re-runs the "
            "underlying operation's preview as a stale-state guard, then "
            "executes it under the approver's identity. Always route via "
            "propose_approve_change_request — the human operator clicks Apply "
            "and becomes the approver; the model can never self-approve. "
            "Server enforces approver != requester + the underlying op's "
            "permission."
        ),
        args_model=ApproveChangeRequestArgs,
        preview=_preview_approve_change_request,
        apply=_apply_approve_change_request,
        category="ops",
        required_permission=("approve", "change_request"),
    )
)


register(
    Operation(
        name="reject_change_request",
        description=(
            "Reject a pending two-person change request (#62). The underlying "
            "operation does NOT run. Always route via "
            "propose_reject_change_request. Server enforces rejecter != "
            "requester + {approve, change_request}."
        ),
        args_model=RejectChangeRequestArgs,
        preview=_preview_reject_change_request,
        apply=_apply_reject_change_request,
        category="ops",
        required_permission=("approve", "change_request"),
    )
)


# ── New-device watch operations (issue #459) ─────────────────────────────────


class AcknowledgeDeviceArgs(BaseModel):
    """Args for the ``acknowledge_device`` operation."""

    sighting_id: UUID = Field(description="UUID of the ip_mac_history sighting to acknowledge")


async def _preview_acknowledge_device(
    db: AsyncSession, user: User, args: AcknowledgeDeviceArgs
) -> PreviewResult:
    from app.models.ipam import IpMacHistory  # noqa: PLC0415

    row = await db.get(IpMacHistory, args.sighting_id)
    if row is None:
        return PreviewResult(ok=False, detail=f"Sighting {args.sighting_id} not found")
    ip = await db.get(IPAddress, row.ip_address_id)
    where = str(ip.address) if ip else "an IP"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=f"Acknowledge new device {row.mac_address} on {where} "
        f"(currently '{row.classification}') — it stops raising the new-device alert.",
    )


async def _apply_acknowledge_device(
    db: AsyncSession, user: User, args: AcknowledgeDeviceArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.services.ipam.new_device import acknowledge_sighting  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["acknowledge_device"])
    row = await acknowledge_sighting(db, args.sighting_id, user)
    if row is None:
        raise ValueError(f"Sighting {args.sighting_id} not found")
    write_audit(
        db,
        user=user,
        action="acknowledged",
        resource_type="ip_mac_observation",
        resource_id=f"{row.ip_address_id}:{row.mac_address}",
        resource_display=str(row.mac_address),
        new_value={"mac_address": str(row.mac_address), "via": "ai_proposal"},
    )
    await db.commit()
    return {"sighting_id": str(row.id), "classification": row.classification}


register(
    Operation(
        name="acknowledge_device",
        description=(
            "Acknowledge (dismiss) a new-device sighting so it stops raising the "
            "new_mac_seen alert. Always route via propose_acknowledge_device."
        ),
        args_model=AcknowledgeDeviceArgs,
        preview=_preview_acknowledge_device,
        apply=_apply_acknowledge_device,
        category="ipam",
        required_permission=("write", "ip_address"),
    )
)


class AllowlistMacArgs(BaseModel):
    """Args for the ``allowlist_mac`` operation."""

    mac_address: str | None = Field(default=None, description="Exact MAC to trust")
    oui_prefix: str | None = Field(
        default=None, description="OUI prefix (e.g. '00:50:56' or '005056') to trust a whole vendor"
    )
    note: str = Field(default="", description="Why this MAC/vendor is trusted")


async def _preview_allowlist_mac(
    db: AsyncSession, user: User, args: AllowlistMacArgs
) -> PreviewResult:
    from app.services.ipam.new_device import normalize_oui_prefix  # noqa: PLC0415

    prefix = normalize_oui_prefix(args.oui_prefix)
    if not args.mac_address and not prefix:
        return PreviewResult(ok=False, detail="Provide a mac_address or an oui_prefix")
    target = args.mac_address or f"OUI {prefix}"
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=f"Trust {target} — it (and matching sightings) become 'known' "
        f"and never raise a new-device alert.",
    )


async def _apply_allowlist_mac(
    db: AsyncSession, user: User, args: AllowlistMacArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.services.ipam.new_device import add_allowlist_entry  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["allowlist_mac"])
    try:
        row, reclassified = await add_allowlist_entry(
            db,
            mac_address=args.mac_address,
            oui_prefix=args.oui_prefix,
            note=args.note,
            user=user,
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="mac_allowlist",
        resource_id=str(row.id),
        resource_display=str(row.mac_address or row.oui_prefix),
        new_value={
            "mac_address": str(row.mac_address) if row.mac_address else None,
            "oui_prefix": row.oui_prefix,
            "reclassified_count": reclassified,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    return {"id": str(row.id), "reclassified_count": reclassified}


register(
    Operation(
        name="allowlist_mac",
        description=(
            "Add a MAC (or OUI prefix) to the trusted allowlist so it never "
            "raises a new-device alert and matching sightings become 'known'. "
            "Always route via propose_allowlist_mac."
        ),
        args_model=AllowlistMacArgs,
        preview=_preview_allowlist_mac,
        apply=_apply_allowlist_mac,
        category="ipam",
        required_permission=("write", "ip_address"),
    )
)


class BlockMacArgs(BaseModel):
    """Args for the ``block_mac`` operation."""

    mac_address: str = Field(description="MAC to block from getting a DHCP lease")
    group_id: UUID | None = Field(
        default=None, description="DHCP server group to block in (default: every group)"
    )
    reason: str = Field(default="other", description="Block reason code")
    description: str = Field(default="", description="Free-form note")


async def _block_target_groups(db: AsyncSession, args: BlockMacArgs) -> list[UUID]:
    from app.models.dhcp import DHCPServerGroup  # noqa: PLC0415

    if args.group_id is not None:
        return [args.group_id]
    return list((await db.execute(select(DHCPServerGroup.id))).scalars().all())


async def _preview_block_mac(db: AsyncSession, user: User, args: BlockMacArgs) -> PreviewResult:
    from app.models.dhcp import DHCPLease, DHCPServerGroup  # noqa: PLC0415

    if args.group_id is not None and await db.get(DHCPServerGroup, args.group_id) is None:
        return PreviewResult(ok=False, detail=f"DHCP server group {args.group_id} not found")
    groups = await _block_target_groups(db, args)
    if not groups:
        return PreviewResult(ok=False, detail="No DHCP server groups to block in")
    active = (
        await db.execute(
            select(func.count())
            .select_from(DHCPLease)
            .where(DHCPLease.mac_address == args.mac_address, DHCPLease.state == "active")
        )
    ).scalar_one()
    warn = f" Note: {active} active lease(s) currently held by this MAC." if active else ""
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=f"Block {args.mac_address} from DHCP in {len(groups)} group(s)." + warn,
    )


async def _apply_block_mac(db: AsyncSession, user: User, args: BlockMacArgs) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.core.agent_wake import collect_wake, dhcp_group_channel  # noqa: PLC0415
    from app.models.dhcp import DHCPMACBlock  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["block_mac"])
    groups = await _block_target_groups(db, args)
    if not groups:
        raise ValueError("No DHCP server groups to block in")
    already = {
        r[0]
        for r in (
            await db.execute(
                select(DHCPMACBlock.group_id).where(
                    DHCPMACBlock.mac_address == args.mac_address,
                    DHCPMACBlock.group_id.in_(groups),
                )
            )
        ).all()
    }
    blocked: list[str] = []
    for gid in groups:
        if gid in already:
            continue
        db.add(
            DHCPMACBlock(
                group_id=gid,
                mac_address=args.mac_address,
                reason=args.reason,
                description=args.description or "Blocked from new-device review (#459)",
                enabled=True,
                created_by_user_id=user.id,
                updated_by_user_id=user.id,
            )
        )
        collect_wake(dhcp_group_channel(gid))
        blocked.append(str(gid))
    if blocked:
        write_audit(
            db,
            user=user,
            action="create",
            resource_type="dhcp_mac_block",
            resource_id=args.mac_address,
            resource_display=args.mac_address,
            new_value={
                "mac_address": args.mac_address,
                "blocked_groups": len(blocked),
                "via": "ai_proposal",
            },
        )
    await db.commit()
    return {"mac_address": args.mac_address, "blocked_group_ids": blocked}


register(
    Operation(
        name="block_mac",
        description=(
            "Block a MAC from getting a DHCP lease (creates a dhcp_mac_block in "
            "one or every server group) — arpwatch with teeth. Always route via "
            "propose_block_mac."
        ),
        args_model=BlockMacArgs,
        preview=_preview_block_mac,
        apply=_apply_block_mac,
        category="dhcp",
        required_permission=("write", "dhcp_mac_block"),
    )
)


class AllowlistRARouterArgs(BaseModel):
    """Args for the ``allowlist_ra_router`` operation (issue #524)."""

    group_id: UUID = Field(description="DHCP server group the RA was seen in")
    source_ip: str | None = Field(
        default=None, description="Expected RA source IPv6 (usually a link-local fe80::…)"
    )
    source_mac: str | None = Field(default=None, description="Expected RA source MAC")
    note: str = Field(default="", description="Why this router is expected")


async def _preview_allowlist_ra_router(
    db: AsyncSession, user: User, args: AllowlistRARouterArgs
) -> PreviewResult:
    from app.models.dhcp import DHCPServerGroup  # noqa: PLC0415

    if not args.source_ip and not args.source_mac:
        return PreviewResult(ok=False, detail="Provide a source_ip or source_mac")
    grp = await db.get(DHCPServerGroup, args.group_id)
    if grp is None:
        return PreviewResult(ok=False, detail=f"DHCP server group {args.group_id} not found.")
    target = args.source_ip or args.source_mac
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            f"Add {target} to group `{grp.name}`'s expected-RA-router allowlist — "
            f"it stops classifying as a rogue RA and the rogue_ra alert auto-resolves."
        ),
    )


async def _apply_allowlist_ra_router(
    db: AsyncSession, user: User, args: AllowlistRARouterArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.models.dhcp import RAObservedRouter, RARouterAllowlist  # noqa: PLC0415

    enforce_operation_permission(user, _OPERATIONS["allowlist_ra_router"])
    if not args.source_ip and not args.source_mac:
        raise ValueError("Provide a source_ip or source_mac")

    entry = RARouterAllowlist(
        group_id=args.group_id,
        source_ip=args.source_ip or None,
        source_mac=args.source_mac or None,
        note=args.note,
        created_by_user_id=user.id,
    )
    db.add(entry)
    reclassified = 0
    if args.source_ip:
        rogue = (
            (
                await db.execute(
                    select(RAObservedRouter).where(
                        RAObservedRouter.group_id == args.group_id,
                        RAObservedRouter.source_ip == args.source_ip,
                        RAObservedRouter.classification == "rogue",
                    )
                )
            )
            .scalars()
            .all()
        )
        for r in rogue:
            r.classification = "acknowledged"
            reclassified += 1
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="ra_router_allowlist",
        resource_id=str(entry.id),
        resource_display=str(args.source_ip or args.source_mac or ""),
        new_value={
            "source_ip": args.source_ip,
            "source_mac": args.source_mac,
            "reclassified_count": reclassified,
            "via": "ai_proposal",
        },
    )
    await db.commit()
    return {"id": str(entry.id), "reclassified_count": reclassified}


register(
    Operation(
        name="allowlist_ra_router",
        description=(
            "Add an IPv6 router (by source IP or MAC) to a DHCP group's "
            "expected-RA-router allowlist so it stops classifying as a rogue RA. "
            "Always route via propose_allowlist_ra_router."
        ),
        args_model=AllowlistRARouterArgs,
        preview=_preview_allowlist_ra_router,
        apply=_apply_allowlist_ra_router,
        category="dhcp",
        required_permission=("write", "dhcp_server"),
    )
)


# ── create_lg_peer (issue #566 — BGP Looking Glass) ─────────────────────
#
# Creates a configured, receive-only bgp_lg_peer session on a collector.
# The hard safety invariant (no export policy — the collector never
# advertises back to the peer) lives in the daemon's rendered config, not
# here; this operation only validates + persists the session row.

_LG_ASN_MIN = 1
_LG_ASN_MAX = 4_294_967_295
# v1 only negotiates unicast AFI/SAFIs — VPNv4/VPNv6/EVPN are a later
# phase (issue #566 §6). Rejecting anything else here keeps a bad
# address_families value from reaching the GoBGP config renderer.
_LG_ADDRESS_FAMILIES = frozenset({"ipv4-unicast", "ipv6-unicast"})


class CreateLgPeerArgs(BaseModel):
    """Args for the ``create_lg_peer`` operation."""

    collector_id: UUID = Field(description="The looking_glass_collector this session runs on.")
    name: str = Field(description="Operator-facing label for the peer session.")
    local_asn: int = Field(description="The collector's own AS number for this session.")
    peer_asn: int = Field(description="The remote router's AS number.")
    peer_address: str = Field(description="The remote router's IP address (v4 or v6).")
    peer_router_id: UUID | None = Field(
        default=None,
        description="Optional link to an existing network_device (SNMP-polled inventory) row.",
    )
    address_families: list[str] | None = Field(
        default=None,
        description=(
            "AFI/SAFIs to negotiate. Defaults to ['ipv4-unicast']. Supported "
            "today: ipv4-unicast, ipv6-unicast (VPNv4/EVPN are a later phase)."
        ),
    )
    max_prefixes: int | None = Field(
        default=None,
        description=(
            "Hard prefix-limit cap rendered into the GoBGP peer config as a "
            "safety guard. Defaults to 10000; raise for a full-table feed."
        ),
    )
    md5_password: str | None = Field(
        default=None,
        description=(
            "Optional TCP-MD5 session password. Fernet-encrypted at rest; "
            "never returned in plaintext by any read surface."
        ),
    )
    import_filter: dict[str, Any] | None = Field(
        default=None,
        description="Route acceptance scope. Defaults to {'mode': 'accept_all'}.",
    )
    enabled: bool = Field(default=True)
    description: str = Field(default="", description="Free-form note.")


async def _validate_lg_peer_args(
    db: AsyncSession, args: CreateLgPeerArgs
) -> tuple[Any, str | None]:
    """Shared validation for preview + apply. Returns ``(collector, error)``
    — ``error`` is a human-readable rejection reason, or ``None`` when the
    args are clean. No writes."""
    from app.models.bgp_looking_glass import LookingGlassCollector  # noqa: PLC0415
    from app.models.network import NetworkDevice  # noqa: PLC0415

    collector = await db.get(LookingGlassCollector, args.collector_id)
    if collector is None:
        return None, f"Collector {args.collector_id} not found."

    for label, number in (("local_asn", args.local_asn), ("peer_asn", args.peer_asn)):
        if not (_LG_ASN_MIN <= number <= _LG_ASN_MAX):
            return None, (
                f"{label} must be between {_LG_ASN_MIN} and {_LG_ASN_MAX} (32-bit AS range)."
            )

    try:
        ipaddress.ip_address(args.peer_address)
    except ValueError:
        return None, f"Invalid peer_address {args.peer_address!r}."

    families = args.address_families or ["ipv4-unicast"]
    unsupported = [af for af in families if af not in _LG_ADDRESS_FAMILIES]
    if unsupported:
        return None, (
            f"Unsupported address_families {unsupported} — v1 only supports "
            f"{sorted(_LG_ADDRESS_FAMILIES)}."
        )

    if args.max_prefixes is not None and args.max_prefixes <= 0:
        return None, "max_prefixes must be a positive integer."

    if args.peer_router_id is not None:
        device = await db.get(NetworkDevice, args.peer_router_id)
        if device is None:
            return None, f"Network device {args.peer_router_id} not found."

    return collector, None


async def _preview_create_lg_peer(
    db: AsyncSession, user: User, args: CreateLgPeerArgs
) -> PreviewResult:
    from app.models.bgp_looking_glass import BGPLGPeer  # noqa: PLC0415

    collector, error = await _validate_lg_peer_args(db, args)
    if error is not None:
        return PreviewResult(ok=False, detail=error)

    # Conflict probe — do NOT reject in preview; surface as a hint (BGP
    # allows multiple sessions to the same address is unusual but not
    # invalid, so this stays informational like create_dhcp_static's
    # collision suffix).
    existing = (
        await db.execute(
            select(BGPLGPeer).where(
                BGPLGPeer.collector_id == args.collector_id,
                BGPLGPeer.peer_address == args.peer_address,
            )
        )
    ).scalar_one_or_none()
    suffix = ""
    if existing is not None:
        suffix = (
            f" — note: this collector already has a peer for {args.peer_address} "
            f"({existing.name!r}); this creates a second session, not a replacement"
        )

    families = args.address_families or ["ipv4-unicast"]
    max_prefixes = args.max_prefixes or 10000
    parts = [
        f"Create receive-only BGP Looking Glass peer `{args.name}` on collector "
        f"`{collector.name}`",
        f"peer_asn={args.peer_asn}",
        f"peer_address={args.peer_address}",
        f"address_families={families}",
        f"max_prefixes={max_prefixes}",
        f"md5_password={'set' if args.md5_password else 'not set'}",
    ]
    return PreviewResult(
        ok=True,
        detail="ready",
        preview_text=(
            ", ".join(parts) + suffix + ". SpatiumDDI never advertises routes "
            "back to this peer (receive-only, no export policy)."
        ),
    )


async def _apply_create_lg_peer(
    db: AsyncSession, user: User, args: CreateLgPeerArgs
) -> dict[str, Any]:
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.core.agent_wake import looking_glass_collector_channel, publish_wake  # noqa: PLC0415
    from app.core.crypto import encrypt_str  # noqa: PLC0415
    from app.models.bgp_looking_glass import BGPLGPeer  # noqa: PLC0415

    # SECURITY (#400, C2): RBAC backstop — matches the Looking Glass peers
    # router's require_resource_permission("bgp_lg_peer") write gate.
    enforce_operation_permission(user, _OPERATIONS["create_lg_peer"])

    collector, error = await _validate_lg_peer_args(db, args)
    if error is not None:
        raise ValueError(error)

    row = BGPLGPeer(
        name=args.name,
        collector_id=collector.id,
        local_asn=args.local_asn,
        peer_asn=args.peer_asn,
        peer_address=args.peer_address,
        peer_router_id=args.peer_router_id,
        address_families=args.address_families or ["ipv4-unicast"],
        max_prefixes=args.max_prefixes or 10000,
        import_filter=args.import_filter or {"mode": "accept_all"},
        enabled=args.enabled,
        description=args.description or "",
        md5_password_encrypted=encrypt_str(args.md5_password) if args.md5_password else None,
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="bgp_lg_peer",
        resource_id=str(row.id),
        resource_display=f"{args.name} ({args.peer_address})",
        new_value={
            "collector_id": str(collector.id),
            "peer_asn": args.peer_asn,
            "peer_address": args.peer_address,
            "address_families": row.address_families,
            "max_prefixes": row.max_prefixes,
            "md5_password_set": bool(args.md5_password),
            "via": "ai_proposal",
        },
    )
    await db.commit()
    await db.refresh(row)
    # Cross-cutting pattern #2 — wake the collector's ConfigBundle long-poll
    # so the new session is rendered without waiting for the belt-and-braces
    # tick. Uses publish_wake directly (not collect_wake): the /api/v1/ai
    # router has no wake_publishing dependency, so the collect_wake bucket is
    # never opened and would silently no-op — mirrors the DNS-record op above.
    await publish_wake(looking_glass_collector_channel(collector.id))
    return {
        "id": str(row.id),
        "collector_id": str(collector.id),
        "name": row.name,
        "peer_asn": row.peer_asn,
        "peer_address": args.peer_address,
        "md5_password_set": bool(row.md5_password_encrypted),
    }


register(
    Operation(
        name="create_lg_peer",
        description=(
            "Create a BGP Looking Glass peer session — a configured, "
            "receive-only BGP session on a collector. SpatiumDDI never "
            "advertises routes back to the peer (no export policy). Always "
            "route via propose_create_lg_peer — this touches the operator's "
            "live BGP config on the collector's next apply, so operator "
            "approval is required."
        ),
        args_model=CreateLgPeerArgs,
        preview=_preview_create_lg_peer,
        apply=_apply_create_lg_peer,
        category="network",
        required_permission=("write", "bgp_lg_peer"),
    )
)


# ── restart_service operation (issue #890) ─────────────────────────────
#
# Restarting a control-plane service is the broadest-blast-radius write
# in the product that isn't destructive: get the target wrong and DNS or
# DHCP goes away for the length of a rollout. So it is superadmin-gated
# at both preview and apply, and — like the REST route — the target is
# resolved against the *live* inventory rather than trusted from the
# caller, which means a hallucinated service name is a clean rejection at
# preview time instead of a string handed to a daemon.


class RestartServiceArgs(BaseModel):
    """Args for ``restart_service`` — restart one SpatiumDDI service."""

    service_id: str = Field(
        description=(
            "Service id exactly as returned by the service inventory: the "
            "compose service name (e.g. 'api', 'dns-bind9') on docker-compose, "
            "or 'Kind:name' (e.g. 'Deployment:spatiumddi-api') on Kubernetes."
        )
    )


async def _resolve_restart_target(user: User, args: RestartServiceArgs) -> tuple[Any, str | None]:
    """Shared superadmin + capability + inventory resolution.

    Returns ``(plan, None)`` on success or ``(None, reason)`` — used by
    preview and apply so the two cannot disagree about whether a restart
    is legal.
    """
    from app.core.permissions import is_effective_superadmin  # noqa: PLC0415
    from app.services import service_control  # noqa: PLC0415
    from app.services.service_control.backends import plan_action  # noqa: PLC0415

    if not is_effective_superadmin(user):
        return None, (
            "Restarting a service interrupts DNS / DHCP / API traffic, so it's "
            "restricted to superadmin users."
        )
    try:
        plan = await plan_action(args.service_id, "restart")
    except LookupError:
        return None, (
            f"No controllable service {args.service_id!r} in this deployment. "
            "List the inventory first — ids differ between docker-compose and "
            "Kubernetes."
        )
    except service_control.ServiceControlError as exc:
        return None, str(exc)
    return plan, None


async def _preview_restart_service(
    db: AsyncSession, user: User, args: RestartServiceArgs
) -> PreviewResult:
    plan, reason = await _resolve_restart_target(user, args)
    if plan is None:
        return PreviewResult(ok=False, detail=reason or "restart unavailable")
    svc = plan.service
    lines = [
        f"Restart **{svc.name}** (`{svc.id}`, {svc.kind}) — currently {svc.state}.",
    ]
    if plan.is_self:
        lines.append(
            "⚠️ This is the API container serving this session. It will drop "
            "the connection; the UI reconnects once it is back."
        )
    if svc.kind != "container":
        lines.append(
            "Kubernetes rollout restart: pods are replaced one at a time, so "
            "service continues if the workload has more than one replica."
        )
    else:
        lines.append("The container stops and starts; anything it serves is down meanwhile.")
    return PreviewResult(ok=True, detail="ready", preview_text="\n".join(lines))


async def _apply_restart_service(
    db: AsyncSession, user: User, args: RestartServiceArgs
) -> dict[str, Any]:
    from app.models.audit import AuditLog  # noqa: PLC0415
    from app.services.service_control.backends import (  # noqa: PLC0415
        apply_action,
        apply_action_detached,
    )

    plan, reason = await _resolve_restart_target(user, args)
    if plan is None:
        raise ValueError(reason or "restart unavailable")

    # Audit BEFORE signalling, and record ``accepted`` rather than
    # ``success``: a self-targeted compose restart kills this process the
    # moment the daemon accepts it, so nothing here survives to observe
    # the outcome. Same ordering and same wording as the REST route.
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action="service_restart",
            resource_type="service",
            resource_id=plan.service.id,
            resource_display=plan.service.name,
            result="accepted",
            new_value={
                "kind": plan.service.kind,
                "self_targeted": plan.is_self,
                "via": "ai_proposal",
            },
        )
    )
    await db.commit()

    if plan.is_self:
        # No response to protect here the way the REST route has, but the
        # commit above must still land before the daemon stops us.
        await apply_action_detached(plan)
    else:
        await apply_action(plan)
    return {
        "id": plan.service.id,
        "name": plan.service.name,
        "kind": plan.service.kind,
        "action": "restart",
        "status": "accepted",
        "self_targeted": plan.is_self,
    }


register(
    Operation(
        name="restart_service",
        description=(
            "Restart one SpatiumDDI service — a compose container or a "
            "Kubernetes workload rollout (issue #890). Superadmin only. "
            "Always route via propose_restart_service; the operator clicks "
            "Apply, because this interrupts live DNS / DHCP / API traffic."
        ),
        args_model=RestartServiceArgs,
        preview=_preview_restart_service,
        apply=_apply_restart_service,
        category="admin",
    )
)
