"""Per-vCenter vSphere reconciler (#4740).

For one ``VSphereTarget``:

  1. Open a REST session, read the ESXi host roster and the VM roster, and
     ask VMware Tools (through vCenter) for each powered-on VM's NICs.
  2. Compute the desired set of ``IPAddress`` rows (one per guest IP, one
     per ESXi host whose inventory name is an IP literal).
  3. Load what this target already owns (FK ``vsphere_target_id``) inside its
     IP space and apply the diff: create, update, release / delete.
  4. Persist ``last_synced_at`` / ``last_sync_error`` / counts, the
     discovery snapshot and a summary audit entry.

Same mirror semantics as the Proxmox reconciler (``services/proxmox``):

* A pre-existing operator row at a mirrored address is claimed and locked
  (``user_modified_at``); a row another integration owns is never claimed.
* A mirrored row whose source went away is deleted, unless the operator
  edited it, in which case it is released (FK cleared) and kept.
* A row sits in the subnet that encloses it. **No subnets or blocks are
  created**: the REST API reports a guest's prefix length but no network
  plan, so a guest address with no enclosing subnet in the target's IP
  space is counted (``skipped_no_subnet``) and listed in Discovery.
* An IP space in Trash stops the sync; a subnet in Trash is invisible to it,
  so nothing is written into one (restore the subnet and the next pass
  mirrors into it).
* An incomplete read (a guest call that failed, a roster at vCenter's list
  cap) skips the address pass entirely, so nothing is absence-deleted over a
  hiccup.

What is specific to vSphere: a powered-on VM whose VMware Tools is not
running has NICs but no guest data. That is **unknown, not empty**: its
previously mirrored addresses are kept untouched and the VM is listed in
Discovery with the reason, instead of being absence-deleted.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.ipam import IPAddress, Subnet
from app.models.vsphere import VSphereTarget
from app.services._mirror_hostname import normalize_desired_hostname
from app.services.dns.record_ops import retract_address_dns
from app.services.integration_ownership import (
    SpaceRelease,
    address_taken,
    addresses_in_space,
    move_stays_in_space,
    owned_addresses_in_space,
    owned_by_other_integration,
    refuse_sync_into_trashed_space,
)
from app.services.ipam.utilization import counts_toward_utilization
from app.services.vsphere.client import (
    VSphereClient,
    VSphereClientError,
    VSphereHost,
    VSphereVM,
)

logger = structlog.get_logger(__name__)

STATUS_VM = "vsphere-vm"
STATUS_HOST = "vsphere-host"
_VM_DESC_PREFIX = "vSphere VM "
_HOST_DESC_PREFIX = "vSphere host "


@dataclass(frozen=True)
class _DesiredAddress:
    address: str
    status: str  # vsphere-vm | vsphere-host
    hostname: str
    description: str
    mac: str | None = None

    def __post_init__(self) -> None:
        normalize_desired_hostname(self)


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    vcenter_version: str | None = None
    host_count: int = 0
    vm_count: int = 0
    addresses_created: int = 0
    addresses_updated: int = 0
    addresses_deleted: int = 0
    skipped_no_subnet: int = 0
    # VMs left alone this pass: powered on, VMware Tools not answering.
    held_vms: int = 0
    unreadable_vms: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    released: SpaceRelease = field(default_factory=SpaceRelease)


# ── Helpers ──────────────────────────────────────────────────────────


def _parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _find_subnet_for_ip(subnets: list[Subnet], ip: str) -> Subnet | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: Subnet | None = None
    best_prefix = -1
    for s in subnets:
        net = _parse_net(str(s.network))
        if net is None:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best = s
            best_prefix = net.prefixlen
    return best


def _description_ref(description: str | None) -> tuple[str, str] | None:
    """``("vm", "vm-42")`` / ``("host", "host-9")`` from a mirrored row's
    description, or ``None`` for a row this reconciler did not describe."""
    d = description or ""
    for kind, prefix in (("vm", _VM_DESC_PREFIX), ("host", _HOST_DESC_PREFIX)):
        if d.startswith(prefix):
            rest = d[len(prefix) :].split(" ", 1)[0]
            if rest:
                return kind, rest
    return None


async def _recompute_subnet_utilization(db: AsyncSession, subnet_id: Any) -> None:
    allocated = (
        await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == subnet_id)
            .where(counts_toward_utilization())
        )
        or 0
    )
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        return
    subnet.allocated_ips = allocated
    subnet.utilization_percent = (
        round(allocated / subnet.total_ips * 100, 2) if subnet.total_ips > 0 else 0.0
    )


# ── Desired state ────────────────────────────────────────────────────


def _compute_desired(
    target: VSphereTarget, hosts: list[VSphereHost], vms: list[VSphereVM]
) -> list[_DesiredAddress]:
    out: list[_DesiredAddress] = []
    if target.mirror_vms:
        for vm in vms:
            if vm.power_state != "POWERED_ON" or vm.guest_state != "reporting":
                continue
            for nic in vm.nics:
                for ip in nic.ips:
                    out.append(
                        _DesiredAddress(
                            address=ip,
                            status=STATUS_VM,
                            hostname=vm.name,
                            description=f"{_VM_DESC_PREFIX}{vm.vm} ({vm.power_state})",
                            mac=nic.mac,
                        )
                    )
    if target.mirror_hosts:
        for h in hosts:
            try:
                ip = str(ipaddress.ip_address(h.name.strip()))
            except ValueError:
                continue
            out.append(
                _DesiredAddress(
                    address=ip,
                    status=STATUS_HOST,
                    hostname="",
                    description=f"{_HOST_DESC_PREFIX}{h.host} ({h.connection_state})",
                )
            )
    return out


# ── Apply ────────────────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    target: VSphereTarget,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
    held_vms: set[str] | None = None,
) -> set[str]:
    """Returns the desired addresses with no enclosing subnet."""
    subnets = list(
        (await db.execute(select(Subnet).where(Subnet.space_id == target.ipam_space_id)))
        .scalars()
        .all()
    )
    space_subnet_ids = {s.id for s in subnets}

    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        desired_map.setdefault(d.address, d)

    # Phase 1 — claim operator rows at the desired addresses (this target's
    # own space only; #2577). Locked with ``user_modified_at`` so the
    # operator's edits survive.
    if desired_map:
        existing = await addresses_in_space(db, target.ipam_space_id, list(desired_map))
        for row in existing:
            if row.vsphere_target_id == target.id:
                continue
            if row.vsphere_target_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another vSphere target; not claiming"
                )
                continue
            if owned_by_other_integration(row, "vsphere_target_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.vsphere_target_id = target.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    current = {
        str(a.address): a
        for a in await owned_addresses_in_space(
            db, "vsphere_target_id", target.id, target.ipam_space_id, summary=summary
        )
    }

    dirty: set[Any] = set()
    gone: list[IPAddress] = []
    for addr, row in current.items():
        if addr in desired_map:
            continue
        ref = _description_ref(row.description)
        if ref is not None and ref[0] == "vm" and ref[1] in (held_vms or ()):
            # VMware Tools is not answering for this VM: unknown, not gone.
            continue
        dirty.add(row.subnet_id)
        if row.user_modified_at is not None:
            row.vsphere_target_id = None
            summary.addresses_updated += 1
        else:
            gone.append(row)
            summary.addresses_deleted += 1
    await retract_address_dns(db, [r.id for r in gone])
    for row in gone:
        await db.delete(row)

    skipped: set[str] = set()
    for addr, d in desired_map.items():
        subnet = _find_subnet_for_ip(subnets, d.address)
        if subnet is None:
            summary.skipped_no_subnet += 1
            skipped.add(addr)
            continue
        if addr in current:
            row = current[addr]
            changed = False
            if row.subnet_id != subnet.id:
                if not move_stays_in_space(row.subnet_id, space_subnet_ids):
                    summary.warnings.append(
                        f"address {addr}: current subnet is outside this target's "
                        f"IP space; not moving"
                    )
                    continue
                if await address_taken(db, subnet.id, d.address, exclude_id=row.id):
                    summary.warnings.append(
                        f"address {addr}: subnet {subnet.network} already has a row "
                        f"for it; not moving"
                    )
                    continue
                dirty.add(row.subnet_id)
                row.subnet_id = subnet.id
                changed = True
            if row.user_modified_at is None:
                if row.status != d.status:
                    row.status = d.status
                    changed = True
                if (row.hostname or "") != d.hostname:
                    row.hostname = d.hostname
                    changed = True
                if (row.description or "") != d.description:
                    row.description = d.description
                    changed = True
                if d.mac and (row.mac_address or "") != d.mac.lower():
                    row.mac_address = d.mac.lower()
                    changed = True
            if changed:
                dirty.add(subnet.id)
                summary.addresses_updated += 1
        else:
            if await address_taken(db, subnet.id, d.address):
                continue
            db.add(
                IPAddress(
                    subnet_id=subnet.id,
                    address=d.address,
                    status=d.status,
                    hostname=d.hostname or None,
                    description=d.description,
                    mac_address=d.mac.lower() if d.mac else None,
                    vsphere_target_id=target.id,
                )
            )
            dirty.add(subnet.id)
            summary.addresses_created += 1

    if dirty:
        await db.flush()
        for subnet_id in dirty:
            await _recompute_subnet_utilization(db, subnet_id)
    return skipped


# ── Discovery payload (UI) ───────────────────────────────────────────

_VM_HINTS = {
    "tools_not_running": (
        "VMware Tools is not running in the guest, so vCenter reports no guest "
        "addresses. Previously mirrored addresses are kept; install or start "
        "VMware Tools (open-vm-tools) to mirror new ones."
    ),
    "unreadable": "vCenter did not answer for this VM on this pass; its rows were left alone.",
    "no_nic": "VMware Tools reported no network interfaces.",
    "no_ip": "VMware Tools reported interfaces but no usable address.",
    "no_subnet": (
        "Addresses were read but no subnet in the target's IP space encloses them; "
        "create the subnet in IPAM and the next pass mirrors them."
    ),
    "powered_off": "Powered off or suspended: not mirrored.",
}


def _build_discovery_payload(
    hosts: list[VSphereHost],
    vms: list[VSphereVM],
    desired: list[_DesiredAddress],
    skipped_addresses: set[str],
    unreadable: set[str],
) -> dict[str, Any]:
    counters = {
        "vm_total": len(vms),
        "vm_reporting": 0,
        "vm_tools_not_running": 0,
        "vm_powered_off": 0,
        "vm_unreadable": 0,
        "vm_no_ip": 0,
        "host_total": len(hosts),
        "host_with_ip_name": sum(1 for d in desired if d.status == STATUS_HOST),
        "addresses_skipped_no_subnet": len(skipped_addresses),
    }
    rows: list[dict[str, Any]] = []
    for vm in vms:
        ips = [ip for nic in vm.nics for ip in nic.ips]
        issue: str | None = None
        if vm.power_state != "POWERED_ON":
            issue = "powered_off"
            counters["vm_powered_off"] += 1
        elif vm.vm in unreadable:
            issue = "unreadable"
            counters["vm_unreadable"] += 1
        elif vm.guest_state == "tools_not_running":
            issue = "tools_not_running"
            counters["vm_tools_not_running"] += 1
        elif not vm.nics:
            issue = "no_nic"
            counters["vm_no_ip"] += 1
        elif not ips:
            issue = "no_ip"
            counters["vm_no_ip"] += 1
        elif all(ip in skipped_addresses for ip in ips):
            issue = "no_subnet"
        else:
            counters["vm_reporting"] += 1
        rows.append(
            {
                "vm": vm.vm,
                "name": vm.name,
                "power_state": vm.power_state,
                "guest_state": vm.guest_state,
                "nic_count": len(vm.nics),
                "ips": ips,
                "issue": issue,
                "hint": _VM_HINTS.get(issue) if issue else None,
            }
        )
    rows.sort(key=lambda r: (r["issue"] is None, r["name"]))
    return {"summary": counters, "vms": rows, "generated_at": datetime.now(UTC).isoformat()}


# ── Entry point ──────────────────────────────────────────────────────


async def reconcile_target(db: AsyncSession, target: VSphereTarget) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)
    if await refuse_sync_into_trashed_space(db, target, summary):
        return summary

    password = ""
    if target.password_encrypted:
        try:
            password = decrypt_str(target.password_encrypted)
        except ValueError as exc:
            summary.error = f"password decrypt failed: {exc}"
            target.last_sync_error = summary.error
            target.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary

    try:
        async with VSphereClient(
            host=target.host,
            port=target.port,
            username=target.username,
            password=password,
            verify_tls=target.verify_tls,
            ca_bundle_pem=target.ca_bundle_pem or "",
        ) as client:
            version = await client.get_version()
            hosts = await client.list_hosts()
            vms = await client.list_vms()
            if target.mirror_vms:
                await client.load_guest_networking(vms)
            unreadable = set(client.unreadable_vms)
            truncated = client.truncated
    except VSphereClientError as exc:
        summary.error = str(exc)
        target.last_sync_error = summary.error
        target.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("vsphere_reconcile_fetch_failed", target=str(target.id), error=summary.error)
        return summary

    summary.vcenter_version = version
    summary.host_count = len(hosts)
    summary.vm_count = len(vms)
    summary.unreadable_vms = len(unreadable)
    summary.truncated = truncated
    held_vms = {
        v.vm for v in vms if v.power_state == "POWERED_ON" and v.guest_state == "tools_not_running"
    }
    summary.held_vms = len(held_vms)

    desired = _compute_desired(target, hosts, vms)

    skipped: set[str] = set()
    if unreadable or truncated:
        summary.warnings.append(
            "incomplete read "
            f"({len(unreadable)} VM guest read(s) failed"
            f"{', vCenter list cap reached' if truncated else ''}) — address pass "
            "skipped so nothing is deleted over a partial inventory"
        )
        logger.warning(
            "vsphere_reconcile_address_pass_skipped_incomplete_read",
            target=str(target.id),
            unreadable=sorted(unreadable),
            truncated=truncated,
        )
    else:
        skipped = await _apply_addresses(db, target, desired, summary, held_vms)

    target.last_synced_at = datetime.now(UTC)
    target.last_sync_error = None
    target.vcenter_version = summary.vcenter_version
    target.host_count = summary.host_count
    target.vm_count = summary.vm_count
    target.last_discovery = _build_discovery_payload(hosts, vms, desired, skipped, unreadable)

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="vsphere.reconcile",
            resource_type="vsphere_target",
            resource_id=str(target.id),
            resource_display=target.name,
            new_value={
                "released": summary.released.as_dict(),
                "addresses": {
                    "created": summary.addresses_created,
                    "updated": summary.addresses_updated,
                    "deleted": summary.addresses_deleted,
                    "skipped_no_subnet": summary.skipped_no_subnet,
                    "held_vms": summary.held_vms,
                    "unreadable_vms": summary.unreadable_vms,
                },
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "vsphere_reconcile_ok",
        **summary.released.log_fields(),
        target=str(target.id),
        vcenter_version=summary.vcenter_version,
        hosts=summary.host_count,
        vms=summary.vm_count,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_target"]
