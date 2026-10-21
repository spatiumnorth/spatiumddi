"""Built-in conformity policy library.

Seeded on first boot, all rows ``is_builtin=True`` and ``enabled=False``
so operators opt in (dropping a flag they don't actually use into
the periodic evaluator wastes cycles + clutters the dashboard).

Seeding rules:

* Identity is ``(framework, name)`` — once a row exists with that
  pair the seeder leaves it alone, even if the operator renamed
  / disabled / re-targeted it. This means evolving the seed file
  doesn't fight the operator's customisations.
* Adding a new policy ships immediately on the next deploy.
* Removing a seed entry does NOT delete the existing row in the
  database — the operator owns the lifecycle once the row lands.
* The ``check_args`` dict is what the per-check evaluator reads;
  schema is per-check (see ``app.services.conformity.checks``).
"""

from __future__ import annotations

import structlog
from sqlalchemy import select

from app.db import AsyncSessionLocal
from app.models.conformity import ConformityPolicy

logger = structlog.get_logger(__name__)


_BUILTIN_POLICIES: list[dict[str, object]] = [
    # ── PCI-DSS 4.0 ─────────────────────────────────────────────────
    {
        "name": "PCI subnets must be in a dedicated VRF",
        "description": (
            "Cardholder-data networks must be routed in their own VRF — "
            "no co-tenancy with non-PCI siblings. Fails when the "
            "subnet's effective VRF holds non-flagged neighbours."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "1.2.1",
        "severity": "critical",
        "target_kind": "subnet",
        "target_filter": {"classification": "pci_scope"},
        "check_kind": "in_separate_vrf",
        "check_args": {"classification": "pci_scope"},
    },
    {
        "name": "PCI subnets must have an owner (customer_id)",
        "description": (
            "Every cardholder-data subnet needs a recorded owner so the "
            "auditor can trace responsibility. Drives the customer_id "
            "FK shipped in #91."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "12.4.1",
        "severity": "warning",
        "target_kind": "subnet",
        "target_filter": {"classification": "pci_scope"},
        "check_kind": "has_field",
        "check_args": {"field": "customer_id"},
    },
    {
        "name": "PCI hosts must not expose admin ports",
        "description": (
            "Per latest nmap scan no IP in PCI scope may have 22 / 23 / "
            "3389 reachable. Soft-warns when no scan exists in the last "
            "30 days — operators see 'we don't know yet' rather than a "
            "false pass."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "1.4.4",
        "severity": "critical",
        "target_kind": "ip_address",
        "target_filter": {"classification": "pci_scope"},
        "check_kind": "no_open_ports",
        "check_args": {"ports": [22, 23, 3389], "max_age_days": 30},
    },
    {
        "name": "PCI scope changes must be alerted on",
        "description": (
            "An enabled compliance_change alert rule with classification "
            "= pci_scope must exist. Confirms the reactive signal "
            "(#105) is wired to a delivery target."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "10.7.2",
        "severity": "warning",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "alert_rule_covers",
        "check_args": {
            "rule_type": "compliance_change",
            "classification": "pci_scope",
        },
    },
    {
        "name": "PCI subnets must not contain stale IP rows",
        "description": (
            "Every IP in a cardholder-data subnet must have been seen "
            "(via nmap, DHCP, or device discovery) within the last 30 "
            "days. Catches rows that should be decommissioned."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "9.4.6",
        "severity": "warning",
        "target_kind": "subnet",
        "target_filter": {"classification": "pci_scope"},
        "check_kind": "last_seen_within",
        "check_args": {"max_age_days": 30},
    },
    # ── HIPAA ───────────────────────────────────────────────────────
    {
        "name": "HIPAA subnets must be in a dedicated VRF",
        "description": (
            "ePHI networks must be isolated at the routing layer. Fails "
            "when the effective VRF holds non-HIPAA siblings."
        ),
        "framework": "HIPAA",
        "reference": "164.312(a)(1)",
        "severity": "critical",
        "target_kind": "subnet",
        "target_filter": {"classification": "hipaa_scope"},
        "check_kind": "in_separate_vrf",
        "check_args": {"classification": "hipaa_scope"},
    },
    # ── Internet-facing ─────────────────────────────────────────────
    {
        "name": "Internet-facing scope must be alerted on",
        "description": (
            "An enabled compliance_change alert rule with classification "
            "= internet_facing must exist."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "warning",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "alert_rule_covers",
        "check_args": {
            "rule_type": "compliance_change",
            "classification": "internet_facing",
        },
    },
    # ── VoIP voice segments (issue #112 phase 2) ────────────────────
    {
        "name": "Voice subnets must not be internet-facing",
        "description": (
            "Voice-VLAN subnets reaching the public internet directly "
            "is almost always a misconfiguration — phone fleet traffic "
            "should be inside a private VRF or NAT'd through the SBC. "
            "Catches the case where an operator tagged a subnet as "
            "voice but also flipped the internet-facing classification."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "critical",
        "target_kind": "subnet",
        "target_filter": {"subnet_role": "voice"},
        "check_kind": "voice_segment_not_internet_facing",
        "check_args": {},
    },
    # ── E911 dispatchable location (issue #972) ─────────────────────
    #
    # RAY BAUM'S Act §506 puts the dispatchable-location duty on the
    # ENTERPRISE, not the carrier, so these are the first conformity
    # policies in the tree that carry a real regulatory citation rather
    # than ``framework: custom``.
    {
        "name": "Voice subnets must reach an Emergency Response Location",
        "description": (
            "Every subnet tagged as a voice segment must resolve to an "
            "ERL by some rule — its own binding, its VLAN's, or its "
            "site's default. A voice segment with no ERL at any level "
            "means a 911 call from it carries no dispatchable location, "
            "which is the RAY BAUM'S §506 gap. The site default counts: "
            "the front door is a poor answer and it is still a "
            "dispatchable location, where a policy demanding room-level "
            "bindings would fail every site on day one and be turned off."
        ),
        "framework": "RAY BAUM'S Act",
        "reference": "47 CFR 9.16(b)",
        "severity": "critical",
        "target_kind": "subnet",
        "target_filter": {"subnet_role": "voice"},
        "check_kind": "e911_voice_subnet_unbound",
        "check_args": {},
    },
    {
        "name": "In-use Emergency Response Locations are provider-validated",
        "description": (
            "Every ERL something is bound to carries an address-"
            "validation verdict from the operator's E911 provider "
            "against the MSAG / NG911 LVF. SpatiumDDI records the "
            "verdict and never decides it, so this asks whether anybody "
            "has confirmed the addresses — the question nobody asks "
            "until a call fails to route. A REJECTED verdict fails "
            "harder than a missing one: somebody checked and the answer "
            "was no. Unbound ERLs are skipped, so drafts do not bury the "
            "ones in use."
        ),
        "framework": "RAY BAUM'S Act",
        "reference": "47 CFR 9.16(b)",
        "severity": "critical",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "e911_erl_validated",
        "check_args": {},
    },
    {
        "name": "Switch-port ERL bindings sit on devices still being polled",
        "description": (
            "A port-level ERL binding is only as good as the FDB / LLDP "
            "data behind it. When the switch stops being polled the "
            "resolver ALREADY degrades every lookup for that port to a "
            "coarser answer, silently from the operator's point of view. "
            "This is the difference between 'our room-level locations "
            "work' and 'they stopped working in March'."
        ),
        "framework": "RAY BAUM'S Act",
        "reference": "47 CFR 9.16(b)",
        "severity": "warning",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "e911_port_binding_evidence_fresh",
        "check_args": {},
    },
    # ── Multicast hygiene (issue #126) ──────────────────────────────
    {
        "name": "No multicast group address collisions within an IPSpace",
        "description": (
            "Every multicast group address is unique within its parent "
            "IPSpace. Two groups sharing an address indicate a "
            "misconfiguration — the registry treats (space_id, address) "
            "as the stream identity and duplicates surface as silent "
            "ambiguity in the IPAM tree. Rule fails per-group when the "
            "scan finds a sibling sharing its address; auto-resolves "
            "when one of the two is renamed or deleted."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "warning",
        "target_kind": "multicast_group",
        "target_filter": {},
        "check_kind": "no_multicast_collision",
        "check_args": {},
    },
    # ── Platform integrity ──────────────────────────────────────────
    {
        "name": "Audit log is reachable and append-only",
        "description": (
            "Confirms the audit_log table is queryable. SpatiumDDI's "
            "DB trigger guards against DELETE — this check is the "
            "presence signal that gets cited in the auditor PDF."
        ),
        "framework": "SOC2",
        "reference": "CC7.1",
        "severity": "info",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "audit_log_immutable",
        "check_args": {},
    },
    {
        "name": "No appliance exposes LAN-wide k3s control-plane ports",
        "description": (
            "Network segmentation — no SpatiumDDI appliance node may accept "
            "the k3s control-plane ports (etcd 2379/2380, kubelet 10250) from "
            "the whole LAN; #285 scopes them to cluster peers. Fails on a "
            "node confirmed still on the legacy LAN-wide base; a stale or "
            "unverified node reports warn (unknown, never a PASS and never a "
            "connectivity-FAIL), and a deployment with no reporting appliance "
            "is not applicable."
        ),
        "framework": "PCI-DSS 4.0",
        "reference": "1.2.1",
        "severity": "critical",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "no_lanwide_control_plane_ports",
        "check_args": {"stale_minutes": 30},
    },
    # ── AV / Audio-Video-over-IP (issue #540) ───────────────────────
    {
        "name": "AV flows stay inside their declared multicast range",
        "description": (
            "Every AV flow (Dante / AES67 / SMPTE 2110 / NDI) sits inside a "
            "reserved range declared for its protocol. Static multicast "
            "assignment is the AoIP best practice, so a flow outside its "
            "declared range is address drift worth catching. Not applicable "
            "until the operator declares a range for that protocol — with "
            "nothing declared there is nothing to check against."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "warning",
        "target_kind": "multicast_group",
        "target_filter": {},
        "check_kind": "av_flow_outside_reserved_range",
        "check_args": {},
    },
    {
        "name": "AV flows record their PTP clock domain",
        "description": (
            "Advisory. PTP misconfiguration is the most common AoIP failure "
            "mode, and the clock domain is the first thing asked for when "
            "audio drops. Warns rather than fails — a missing domain is "
            "undocumented state, not a broken network."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "info",
        "target_kind": "multicast_group",
        "target_filter": {},
        "check_kind": "av_flow_no_ptp_domain",
        "check_args": {},
    },
    # ── BACnet/IP building automation (issue #541) ──────────────────
    {
        "name": "Exactly one BACnet BBMD per subnet",
        "description": (
            "BACnet broadcasts do not cross IP routers, so each subnet in a "
            "multi-subnet BACnet/IP internetwork needs exactly one Broadcast "
            "Management Device. Zero leaves that subnet's devices invisible "
            "across the internetwork; two or more duplicate broadcast "
            "traffic and I-Am responses. Subnets with no BACnet devices are "
            "not applicable."
        ),
        "framework": "custom",
        "reference": "ASHRAE 135 Annex J",
        "severity": "warning",
        "target_kind": "subnet",
        "target_filter": {},
        "check_kind": "bbmd_one_per_subnet",
        "check_args": {},
    },
    {
        "name": "BACnet device instance numbers are unique",
        "description": (
            "Device instance numbers must be unique across the entire BACnet "
            "internetwork. A database constraint already enforces this, so a "
            "finding means rows arrived by a path that bypassed the ORM — a "
            "restore from an older backup, or direct SQL."
        ),
        "framework": "custom",
        "reference": "ASHRAE 135",
        "severity": "critical",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "bacnet_duplicate_device_instance",
        "check_args": {},
    },
    {
        "name": "BACnet devices report a plausible vendor id",
        "description": (
            "Advisory. Vendor id 0 is legitimately ASHRAE itself, but on a "
            "real plant a controller reporting 0 or nothing is usually "
            "misconfigured, cloned, or counterfeit."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "info",
        "target_kind": "platform",
        "target_filter": {},
        "check_kind": "bacnet_vendor_id_unknown",
        "check_args": {},
    },
    # ── Industrial / OT segmentation (issue #542) ───────────────────
    {
        "name": "OT devices match their subnet's Purdue level",
        "description": (
            "Purdue-model segmentation exists so a Level-1 controller does "
            "not live in a Level-4 enterprise subnet. Fails when a device's "
            "recorded level differs from the level its subnet is zoned for. "
            "Not applicable when either level is unrecorded — unknown is "
            "missing documentation, not a violation."
        ),
        "framework": "custom",
        "reference": "ISA-95 / Purdue Enterprise Reference Architecture",
        "severity": "warning",
        "target_kind": "ip_address",
        "target_filter": {},
        "check_kind": "ot_device_crosses_purdue_boundary",
        "check_args": {},
    },
    {
        "name": "Subnets with OT devices declare an OT zone",
        "description": (
            "Advisory. Without a zone row the Purdue-boundary check has "
            "nothing to compare against, so this is what explains an empty "
            "segmentation report."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "info",
        "target_kind": "subnet",
        "target_filter": {},
        "check_kind": "ot_zone_missing_purdue_level",
        "check_args": {},
    },
    # ── Fragile-device probe safety (issue #722) ────────────────────
    {
        "name": "Subnets with fragile devices are marked do-not-probe",
        "description": (
            "Medical- and OT-device vendors instruct sites not to scan their "
            "VLANs, and fragile IP stacks genuinely fault under a sweep. Fails "
            "when a subnet carries registered OT devices, DICOM application "
            "entities, or BMC / IPMI addresses but is not covered by the "
            "do-not-probe flag — meaning discovery sweeps, nmap and the "
            "reachability tools will still target it. Suppression inherited "
            "from a parent block or space counts as covered."
        ),
        "framework": "custom",
        "reference": None,
        "severity": "warning",
        "target_kind": "subnet",
        "target_filter": {},
        "check_kind": "fragile_subnet_probed",
        "check_args": {},
    },
]


async def seed_builtin_conformity_policies() -> None:
    """Insert built-in policies on first start. Idempotent.

    Match key is ``(framework, name)`` so renaming a row in the
    seed list creates a fresh row alongside the operator's old one
    rather than silently overwriting their settings.
    """
    async with AsyncSessionLocal() as session:
        for spec in _BUILTIN_POLICIES:
            existing = await session.scalar(
                select(ConformityPolicy).where(
                    ConformityPolicy.framework == spec["framework"],
                    ConformityPolicy.name == spec["name"],
                )
            )
            if existing is not None:
                continue
            session.add(
                ConformityPolicy(
                    name=spec["name"],
                    description=spec["description"],
                    framework=spec["framework"],
                    reference=spec["reference"],
                    severity=spec["severity"],
                    target_kind=spec["target_kind"],
                    target_filter=spec["target_filter"],
                    check_kind=spec["check_kind"],
                    check_args=spec["check_args"],
                    is_builtin=True,
                    enabled=False,
                    eval_interval_hours=24,
                )
            )
        await session.commit()


__all__ = ["seed_builtin_conformity_policies"]
