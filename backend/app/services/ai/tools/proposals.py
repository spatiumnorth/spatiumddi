"""Operator Copilot write-tool proposals (issue #90 Phase 2).

A ``propose_*`` tool is the LLM-facing entry point for a write
operation. It takes the operation's args, runs :func:`preview` to
validate + describe the change, persists an
:class:`AIOperationProposal` row, and returns a special tool-result
payload the chat surface understands as a "render an Apply / Discard
card" signal.

Crucially these tools never *apply* the mutation. Apply only runs
through ``POST /api/v1/ai/proposals/{id}/apply`` — the operator's
explicit click in the UI (or a second LLM-mediated round-trip via a
future ``apply_proposal`` tool, not yet shipping).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIOperationProposal
from app.models.auth import User
from app.services.ai import operations
from app.services.ai.operations import (
    AcknowledgeDeviceArgs,
    AllocateMulticastGroupsArgs,
    AllocateSubnetArgs,
    AllowlistMacArgs,
    ArchiveSessionArgs,
    BlockMacArgs,
    CreateAddressSetArgs,
    CreateAlertRuleArgs,
    CreateDHCPStaticArgs,
    CreateDNSRecordArgs,
    CreateDNSZoneArgs,
    CreateIPAddressArgs,
    CreateMulticastGroupArgs,
    RunNmapScanArgs,
    WakeHostArgs,
)
from app.services.ai.tools.base import register_tool


# The tool result shape the frontend pattern-matches on. Stable
# contract — drawer.tsx looks for the ``kind == "proposal"`` key and
# renders an Apply / Discard card with the proposal_id wired into a
# POST /apply / POST /discard call.
def _proposal_result(proposal: AIOperationProposal, *, preview_text: str) -> dict[str, Any]:
    return {
        "kind": "proposal",
        "proposal_id": str(proposal.id),
        "operation": proposal.operation,
        "preview": preview_text,
        "expires_at": proposal.expires_at.isoformat() if proposal.expires_at else None,
        # Hint to the LLM — keep it short so the model echoes
        # something appropriate to the operator.
        "instruction": (
            "A proposal has been prepared. Tell the operator they need "
            "to review and click Apply to commit, or Discard to cancel."
        ),
    }


async def _persist_proposal(
    db: AsyncSession,
    *,
    user: User,
    operation: str,
    args: dict[str, Any],
    preview_text: str,
) -> AIOperationProposal:
    """Persist a fresh proposal row + commit. Re-used by every
    ``propose_*`` tool below.
    """
    row = AIOperationProposal(
        # session_id is set by the orchestrator (which knows the
        # active session). The tool itself doesn't have that
        # context; the orchestrator can patch it after the fact if
        # we want session-scoped listing — for Phase 2 we keep it
        # null and rely on user_id + created_at for grouping.
        session_id=None,
        user_id=user.id,
        operation=operation,
        args=args,
        preview_text=preview_text,
        expires_at=operations.expires_at_default(),
    )
    db.add(row)
    await db.flush()
    await db.commit()
    await db.refresh(row)
    return row


# ── propose_create_ip_address ─────────────────────────────────────────────


@register_tool(
    name="propose_create_ip_address",
    permission=("write", "ip_address"),
    description=(
        "Prepare an IP-address allocation proposal. The operator must "
        "explicitly click Apply (or you must call apply_proposal with "
        "the returned proposal_id, which is not yet enabled) for the "
        "mutation to land. Returns a kind='proposal' payload — surface "
        "the preview to the operator and wait for their decision. "
        "Never call this twice for the same change without operator "
        "instruction."
    ),
    args_model=CreateIPAddressArgs,
    writes=False,  # The propose tool itself is read-only; apply is the write.
    category="ipam",
)
async def propose_create_ip_address(
    db: AsyncSession, user: User, args: CreateIPAddressArgs
) -> dict[str, Any]:
    op = operations.get_operation("create_ip_address")
    if op is None:
        return {"error": "Operation 'create_ip_address' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "create_ip_address",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="create_ip_address",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── propose_allocate_subnet ───────────────────────────────────────────


@register_tool(
    name="propose_allocate_subnet",
    permission=("write", "subnet"),
    description=(
        "Prepare a proposal to carve the next free child subnet of a "
        "given prefix length out of an IP block (e.g. 'allocate a /24 "
        "from block X'). The operator must explicitly click Apply for "
        "the subnet to be created. Returns a kind='proposal' payload — "
        "surface the previewed CIDR to the operator and wait for their "
        "decision. Never call this twice for the same request without "
        "operator instruction."
    ),
    args_model=AllocateSubnetArgs,
    writes=False,  # The propose tool itself is read-only; apply is the write.
    category="ipam",
)
async def propose_allocate_subnet(
    db: AsyncSession, user: User, args: AllocateSubnetArgs
) -> dict[str, Any]:
    op = operations.get_operation("allocate_subnet")
    if op is None:
        return {"error": "Operation 'allocate_subnet' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "allocate_subnet",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="allocate_subnet",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── propose_run_nmap_scan ─────────────────────────────────────────────


@register_tool(
    name="propose_run_nmap_scan",
    permission=("write", "manage_nmap_scans"),
    module="tools.nmap",
    description=(
        "Prepare an nmap scan proposal. The operator must explicitly "
        "click Apply for the scan to actually run — nmap touches the "
        "network so silent execution is never appropriate. Use this "
        "for any operator question that requires *new* port / "
        "service / OS data; for *existing* scan history use "
        "list_nmap_scans + get_nmap_scan_results instead. Returns "
        "kind='proposal' — surface the preview to the operator and "
        "wait for their decision. Never call this twice for the "
        "same target without operator instruction."
    ),
    args_model=RunNmapScanArgs,
    writes=False,  # The propose tool is read-only; apply is the write.
    category="network",
)
async def propose_run_nmap_scan(
    db: AsyncSession, user: User, args: RunNmapScanArgs
) -> dict[str, Any]:
    op = operations.get_operation("run_nmap_scan")
    if op is None:
        return {"error": "Operation 'run_nmap_scan' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "run_nmap_scan",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="run_nmap_scan",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── propose_wake_host ─────────────────────────────────────────────────


@register_tool(
    name="propose_wake_host",
    permission=("read", "use_network_tools"),
    description=(
        "Prepare a Wake-on-LAN proposal for an IP. The operator must "
        "click Apply to actually send the magic packet — WoL touches the "
        "network. Resolve the IP first with find_ip and pass its id as "
        "address_id. Returns kind='proposal' — surface the preview and "
        "wait for the operator's decision."
    ),
    args_model=WakeHostArgs,
    writes=False,  # The propose tool is read-only; apply is the send.
    category="network",
)
async def propose_wake_host(db: AsyncSession, user: User, args: WakeHostArgs) -> dict[str, Any]:
    op = operations.get_operation("wake_host")
    if op is None:
        return {"error": "Operation 'wake_host' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "wake_host",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="wake_host",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── Tier 5 propose_* tools (issue #101) ───────────────────────────────
#
# Each one mirrors the existing pattern: tool itself is read-only
# (writes=False — the actual mutation happens at /apply time after
# operator approval); the underlying registered Operation enforces
# the preview + apply contract; ``_persist_proposal`` writes the
# AIOperationProposal row that the chat drawer renders as an Approve
# / Reject card.
#
# All four ship default-disabled so an operator who hasn't reviewed
# the implications doesn't accidentally hand the LLM keys to their
# DNS / DHCP / alert / chat tables. Enable per-tool via Settings →
# AI → Tool Catalog (the catalog page now confirm-modals before
# turning on any propose_* tool — see frontend treatment of the
# ``propose_`` name prefix).


async def _propose_via(
    *,
    db: AsyncSession,
    user: User,
    operation_name: str,
    args: Any,
) -> dict[str, Any]:
    """Shared boilerplate — look up the Operation, run preview, persist
    proposal on success, surface the rejection on failure."""
    op = operations.get_operation(operation_name)
    if op is None:
        return {"error": f"Operation {operation_name!r} is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": operation_name,
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation=operation_name,
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── propose_create_address_set (issue #103) ───────────────────────────


@register_tool(
    name="propose_create_address_set",
    permission=("admin", "address_set"),
    description=(
        "Prepare an address-set creation proposal. Operator must click "
        "Approve in the chat drawer to apply. An address set is a named, "
        "RBAC-scoped slice of a subnet (a contiguous range or an explicit "
        "host list) used to delegate edit of just that slice without "
        "subnet-wide write. Pass name, subnet_id, range_kind "
        "('contiguous' with start_address/end_address, or 'explicit' with "
        "explicit_addresses). Returns a kind='proposal' card; never call "
        "twice for the same change."
    ),
    args_model=CreateAddressSetArgs,
    writes=False,
    category="ipam",
    # Default-on (NN #13): no secrets, no broad blast radius, no off-prem
    # call — matches sibling propose_create_ip_address / propose_allocate
    # _subnet. The op still requires admin on address_set + explicit Apply.
    default_enabled=True,
    module="ipam.address_sets",
)
async def propose_create_address_set(
    db: AsyncSession, user: User, args: CreateAddressSetArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_address_set", args=args)


# ── propose_create_dns_record ─────────────────────────────────────────


@register_tool(
    name="propose_create_dns_record",
    permission=("write", "dns_record"),
    description=(
        "Prepare a DNS record creation proposal. Operator must click "
        "Approve in the chat drawer to apply — DNS edits propagate to "
        "live BIND9 / Windows DNS servers. Use when the operator says "
        "'create an A record for foo pointing at 10.0.0.5' or similar. "
        "Pass zone_id (UUID), name (relative — '@' for apex), "
        "record_type, value; ttl + priority are optional. Returns a "
        "kind='proposal' card; never call twice for the same change."
    ),
    args_model=CreateDNSRecordArgs,
    writes=False,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def propose_create_dns_record(
    db: AsyncSession, user: User, args: CreateDNSRecordArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_dns_record", args=args)


# ── propose_create_dns_zone (issue #127 Phase 4e) ─────────────────────


@register_tool(
    name="propose_create_dns_zone",
    permission=("write", "dns_zone"),
    description=(
        "Prepare a new DNS zone proposal. Pass name (FQDN — trailing "
        "dot added automatically) plus either group_id (UUID of the "
        "DNS server group) or driver_hint (one of 'bind9', "
        "'powerdns', 'windows_dns'). When the operator asks for "
        "DNSSEC, set dnssec_enabled=true and driver_hint='powerdns' — "
        "online signing only works on the PowerDNS driver. "
        "zone_type defaults to 'primary' / kind defaults to "
        "'forward'. Operator must click Approve to apply — zone "
        "creates propagate to live nameservers."
    ),
    args_model=CreateDNSZoneArgs,
    writes=False,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def propose_create_dns_zone(
    db: AsyncSession, user: User, args: CreateDNSZoneArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_dns_zone", args=args)


# ── propose_create_multicast_group (issue #126 Phase 4) ──────────────


@register_tool(
    name="propose_create_multicast_group",
    permission=("write", "multicast"),
    description=(
        "Prepare a multicast group registry entry. Pass space_id "
        "(UUID of the parent IPSpace), address (must be inside "
        "224.0.0.0/4 IPv4 or ff00::/8 IPv6), and name. Optional: "
        "application label, domain_id (PIM domain), rtp_payload_type. "
        "Use when the operator says 'create a multicast group for "
        "Cam7 at 239.5.7.42 in the studio space'. Operator must "
        "click Approve in the chat drawer; preview soft-warns when "
        "the address collides with an existing group."
    ),
    args_model=CreateMulticastGroupArgs,
    writes=False,
    category="multicast",
    default_enabled=False,
    module="network.multicast",
)
async def propose_create_multicast_group(
    db: AsyncSession, user: User, args: CreateMulticastGroupArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_multicast_group", args=args)


# ── propose_allocate_multicast_group (Phase 4 Wave 2) ────────────────


@register_tool(
    name="propose_allocate_multicast_group",
    permission=("write", "multicast"),
    description=(
        "Prepare a bulk multicast-group allocation proposal — stamps "
        "N sequential addresses with a name template in one shot. "
        "Pass space_id, count (1..256), start_address (must sit "
        "inside the IANA multicast ranges), and name_template using "
        "{n} / {n:03d} / {n:x} / {oct1}-{oct4} tokens. Optional: "
        "application label, domain_id, template_start. Use when the "
        "operator says 'allocate 16 streams starting at 239.10.0.0 "
        "named cam-{n:02d}'. Operator must click Approve in the "
        "chat drawer; preview shows the planned addresses inline "
        "and refuses if any are already taken in the target space."
    ),
    args_model=AllocateMulticastGroupsArgs,
    writes=False,
    category="multicast",
    default_enabled=False,
    module="network.multicast",
)
async def propose_allocate_multicast_group(
    db: AsyncSession, user: User, args: AllocateMulticastGroupsArgs
) -> dict[str, Any]:
    return await _propose_via(
        db=db, user=user, operation_name="allocate_multicast_groups", args=args
    )


# ── propose_create_dhcp_static ────────────────────────────────────────


@register_tool(
    name="propose_create_dhcp_static",
    permission=("write", "dhcp_static"),
    description=(
        "Prepare a DHCP static reservation proposal. Operator must "
        "click Approve to apply — the reservation propagates to the "
        "Kea / Windows DHCP backend. Pass scope_id (UUID), ip_address "
        "(must lie inside the scope), mac_address; hostname + "
        "description are optional. Use when the operator says 'pin "
        "11:22:33:44:55:66 to 10.0.0.7 in the corp scope'."
    ),
    args_model=CreateDHCPStaticArgs,
    writes=False,
    category="dhcp",
    default_enabled=False,
    module="core.dhcp",
)
async def propose_create_dhcp_static(
    db: AsyncSession, user: User, args: CreateDHCPStaticArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_dhcp_static", args=args)


# ── propose_create_alert_rule ─────────────────────────────────────────


@register_tool(
    name="propose_create_alert_rule",
    permission="superadmin",
    description=(
        "Prepare a subnet-utilization alert rule proposal. Pass name, "
        "threshold_percent (1-100), severity (info / warning / "
        "critical), and an optional description. Other rule_type "
        "values keep their UI authoring path; this proposer is "
        "scoped to subnet-utilization which is the most common "
        "operator request. Returns a kind='proposal' card; operator "
        "clicks Approve to actually create the rule."
    ),
    args_model=CreateAlertRuleArgs,
    writes=False,
    category="ops",
    default_enabled=False,
)
async def propose_create_alert_rule(
    db: AsyncSession, user: User, args: CreateAlertRuleArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_alert_rule", args=args)


# ── propose_archive_session ───────────────────────────────────────────


@register_tool(
    name="propose_archive_session",
    permission="self",
    description=(
        "Prepare a chat-session archive proposal. Hides the named "
        "session from the History panel's default view without "
        "deleting it; the row stays restorable. Operator can only "
        "archive their own sessions — preview rejects cross-user "
        "attempts. Use when the operator says 'archive this chat' or "
        "'hide my old debugging sessions'."
    ),
    args_model=ArchiveSessionArgs,
    writes=False,
    category="ops",
    default_enabled=False,
)
async def propose_archive_session(
    db: AsyncSession, user: User, args: ArchiveSessionArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="archive_session", args=args)


# ── MCP coverage catch-up (#280 / #304) ───────────────────────────────
#
# Each tool below mirrors a sibling read tool's category + module so the
# write proposal is gated identically. All ship default-disabled —
# operators opt in via Settings → AI → Tool Catalog after reviewing the
# blast radius. Backup writes are intentionally absent (restore needs an
# uploaded archive + passphrase + a typed confirm phrase that an MCP
# apply can't supply); the backup read tools remain the supported
# surface.

from app.services.ai.operations_writes import (  # noqa: E402
    CommitDHCPImportArgs,
    CommitDNSImportArgs,
    CommitNetboxImportArgs,
    CreateConformityPolicyArgs,
    CreateMulticastDomainArgs,
    CreateWebhookArgs,
    DeleteMulticastDomainArgs,
    EvaluateConformityPolicyArgs,
    SignZoneDNSSECArgs,
    TestWebhookArgs,
    UnsignZoneDNSSECArgs,
    UpdateConformityPolicyArgs,
    UpdateMulticastDomainArgs,
    UpdateNTPSettingsArgs,
    UpdateSNMPSettingsArgs,
    UpdateSyslogSettingsArgs,
    UpdateWebhookArgs,
)

# ── Conformity (#105 / #106) ──────────────────────────────────────────


@register_tool(
    name="propose_create_conformity_policy",
    permission=("admin", "conformity"),
    description=(
        "Prepare a custom conformity policy. Pass name, target_kind "
        "(platform/subnet/ip_address/dns_zone/dhcp_scope), check_kind "
        "(from the conformity check catalog), and optional framework / "
        "severity / check_args. Operator clicks Approve to create it."
    ),
    args_model=CreateConformityPolicyArgs,
    writes=False,
    category="compliance",
    default_enabled=False,
    module="compliance.conformity",
)
async def propose_create_conformity_policy(
    db: AsyncSession, user: User, args: CreateConformityPolicyArgs
) -> dict[str, Any]:
    return await _propose_via(
        db=db, user=user, operation_name="create_conformity_policy", args=args
    )


@register_tool(
    name="propose_update_conformity_policy",
    permission=("admin", "conformity"),
    description=(
        "Prepare a conformity-policy update. Pass policy_id plus the "
        "fields to change. Built-in policies only accept enabled / "
        "severity / eval_interval_hours / description / fail_alert_rule. "
        "Operator clicks Approve."
    ),
    args_model=UpdateConformityPolicyArgs,
    writes=False,
    category="compliance",
    default_enabled=False,
    module="compliance.conformity",
)
async def propose_update_conformity_policy(
    db: AsyncSession, user: User, args: UpdateConformityPolicyArgs
) -> dict[str, Any]:
    return await _propose_via(
        db=db, user=user, operation_name="update_conformity_policy", args=args
    )


@register_tool(
    name="propose_evaluate_conformity_policy",
    permission=("admin", "conformity"),
    description=(
        "Prepare an on-demand conformity evaluation. Pass policy_id; "
        "apply runs the check now and returns the pass/fail rollup. Use "
        "when the operator asks to 'check PCI compliance now'."
    ),
    args_model=EvaluateConformityPolicyArgs,
    writes=False,
    category="compliance",
    default_enabled=False,
    module="compliance.conformity",
)
async def propose_evaluate_conformity_policy(
    db: AsyncSession, user: User, args: EvaluateConformityPolicyArgs
) -> dict[str, Any]:
    return await _propose_via(
        db=db, user=user, operation_name="evaluate_conformity_policy", args=args
    )


# ── Webhooks (superadmin) ─────────────────────────────────────────────


@register_tool(
    name="propose_create_webhook",
    permission="superadmin",
    description=(
        "Prepare a typed-event webhook subscription. Pass name + url "
        "(https recommended); optional event_types filter. A signing "
        "secret is auto-generated and revealed once on apply. Superadmin "
        "+ Approve required — deliveries make off-prem HTTP calls."
    ),
    args_model=CreateWebhookArgs,
    writes=False,
    category="webhooks",
    default_enabled=False,
)
async def propose_create_webhook(
    db: AsyncSession, user: User, args: CreateWebhookArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_webhook", args=args)


@register_tool(
    name="propose_update_webhook",
    permission="superadmin",
    description=(
        "Prepare a webhook-subscription update. Pass subscription_id plus "
        "the fields to change (name / url / enabled / event_types / "
        "timeouts). The signing secret is left untouched. Superadmin + "
        "Approve."
    ),
    args_model=UpdateWebhookArgs,
    writes=False,
    category="webhooks",
    default_enabled=False,
)
async def propose_update_webhook(
    db: AsyncSession, user: User, args: UpdateWebhookArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="update_webhook", args=args)


@register_tool(
    name="propose_test_webhook",
    permission="superadmin",
    description=(
        "Prepare a webhook test. Pass subscription_id; apply pushes a "
        "synthetic test.ping through the real signing + delivery path "
        "and returns the HTTP status. No DB write, but it does make an "
        "off-prem call, so it's Approve-gated. Superadmin only."
    ),
    args_model=TestWebhookArgs,
    writes=False,
    category="webhooks",
    default_enabled=False,
)
async def propose_test_webhook(
    db: AsyncSession, user: User, args: TestWebhookArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="test_webhook", args=args)


# ── DNSSEC sign / unsign (#49 / #127) ─────────────────────────────────


@register_tool(
    name="propose_sign_zone_dnssec",
    permission=("write", "dns_zone"),
    description=(
        "Prepare a DNSSEC-signing proposal for a zone. Pass group_id + "
        "zone_id; optional policy_id. BIND9 / PowerDNS only. Operator "
        "clicks Approve — signing propagates to live nameservers and the "
        "parent registrar's DS must be updated afterwards."
    ),
    args_model=SignZoneDNSSECArgs,
    writes=False,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def propose_sign_zone_dnssec(
    db: AsyncSession, user: User, args: SignZoneDNSSECArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="sign_zone_dnssec", args=args)


@register_tool(
    name="propose_unsign_zone_dnssec",
    permission=("write", "dns_zone"),
    description=(
        "Prepare a DNSSEC-unsign proposal. Pass group_id + zone_id. "
        "Clears keys + DS; validating resolvers SERVFAIL until the "
        "parent DS is removed. Operator clicks Approve."
    ),
    args_model=UnsignZoneDNSSECArgs,
    writes=False,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def propose_unsign_zone_dnssec(
    db: AsyncSession, user: User, args: UnsignZoneDNSSECArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="unsign_zone_dnssec", args=args)


# ── Multicast domain CRUD (#126) ──────────────────────────────────────


@register_tool(
    name="propose_create_multicast_domain",
    permission=("write", "multicast"),
    description=(
        "Prepare a multicast PIM domain. Pass name + pim_mode "
        "(sparse/dense/ssm/bidir/none); optional vrf_id, rendezvous "
        "point, ssm_range. Operator clicks Approve."
    ),
    args_model=CreateMulticastDomainArgs,
    writes=False,
    category="multicast",
    default_enabled=False,
    module="network.multicast",
)
async def propose_create_multicast_domain(
    db: AsyncSession, user: User, args: CreateMulticastDomainArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_multicast_domain", args=args)


@register_tool(
    name="propose_update_multicast_domain",
    permission=("write", "multicast"),
    description=(
        "Prepare a multicast-domain update. Pass domain_id plus the "
        "fields to change (name / pim_mode / rendezvous point / "
        "ssm_range / notes). Operator clicks Approve."
    ),
    args_model=UpdateMulticastDomainArgs,
    writes=False,
    category="multicast",
    default_enabled=False,
    module="network.multicast",
)
async def propose_update_multicast_domain(
    db: AsyncSession, user: User, args: UpdateMulticastDomainArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="update_multicast_domain", args=args)


@register_tool(
    name="propose_delete_multicast_domain",
    permission=("delete", "multicast"),
    description=(
        "Prepare a multicast-domain deletion. Pass domain_id. Groups "
        "that reference it have their domain link cleared (not deleted). "
        "Operator clicks Approve."
    ),
    args_model=DeleteMulticastDomainArgs,
    writes=False,
    category="multicast",
    default_enabled=False,
    module="network.multicast",
)
async def propose_delete_multicast_domain(
    db: AsyncSession, user: User, args: DeleteMulticastDomainArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="delete_multicast_domain", args=args)


# ── SNMP / NTP appliance host config (#153 / #154) ────────────────────


@register_tool(
    name="propose_update_snmp_settings",
    permission="superadmin",
    description=(
        "Prepare an SNMP host-config update. Pass enabled + version "
        "(v2c/v3); optional community (stored encrypted), "
        "allowed_sources CIDRs, sys_contact/location. Superadmin + "
        "Approve — the community string is a secret."
    ),
    args_model=UpdateSNMPSettingsArgs,
    writes=False,
    category="admin",
    default_enabled=False,
)
async def propose_update_snmp_settings(
    db: AsyncSession, user: User, args: UpdateSNMPSettingsArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="update_snmp_settings", args=args)


@register_tool(
    name="propose_update_ntp_settings",
    permission="superadmin",
    description=(
        "Prepare an NTP / chrony host-config update. Pass source_mode "
        "(pool/servers/mixed); optional pool_servers, allow_clients, "
        "allow_client_networks. Superadmin + Approve."
    ),
    args_model=UpdateNTPSettingsArgs,
    writes=False,
    category="admin",
    default_enabled=False,
)
async def propose_update_ntp_settings(
    db: AsyncSession, user: User, args: UpdateNTPSettingsArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="update_ntp_settings", args=args)


@register_tool(
    name="propose_update_syslog_settings",
    permission="superadmin",
    description=(
        "Prepare an rsyslog forwarding host-config update. Pass enabled "
        "+ optional targets (each host/port/protocol (udp/tcp/tls)/format "
        "(rfc5424/rfc3164/json), with ca_cert_pem for TLS), filter, "
        "buffer_disk. Superadmin + Approve — TLS targets carry a secret CA "
        "PEM and the change ships logs off-prem."
    ),
    args_model=UpdateSyslogSettingsArgs,
    writes=False,
    category="admin",
    # Default-disabled (NN #13): handles a secret CA PEM + ships logs
    # off-prem. module=None — plain host-config, not a feature module.
    default_enabled=False,
    module=None,
)
async def propose_update_syslog_settings(
    db: AsyncSession, user: User, args: UpdateSyslogSettingsArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="update_syslog_settings", args=args)


# ── DNS / DHCP config import — live-pull commit (#128 / #129) ─────────


@register_tool(
    name="propose_commit_dns_import",
    permission="superadmin",
    description=(
        "Prepare a DNS config import from a live source. source must be "
        "'windows_dns' (pass server_id of a registered windows_dns "
        "server) or 'powerdns' (pass api_url + api_key). target_group_id "
        "is where zones land. File uploads (bind9) must use the UI. "
        "Preview shows zone/record counts + conflicts (skipped on "
        "apply); operator clicks Approve to commit."
    ),
    args_model=CommitDNSImportArgs,
    writes=False,
    category="dns",
    default_enabled=False,
    module="dns.import",
)
async def propose_commit_dns_import(
    db: AsyncSession, user: User, args: CommitDNSImportArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="commit_dns_import", args=args)


@register_tool(
    name="propose_commit_dhcp_import",
    permission="superadmin",
    description=(
        "Prepare a DHCP config import from a live Windows DHCP server. "
        "Pass source='windows_dhcp', server_id, target_group_id; "
        "optional ipam_space_id + ipam_block_id to auto-create matching "
        "IPAM subnets. Kea/ISC file uploads must use the UI. Operator "
        "clicks Approve to commit."
    ),
    args_model=CommitDHCPImportArgs,
    writes=False,
    category="dhcp",
    default_enabled=False,
    module="dhcp.import",
)
async def propose_commit_dhcp_import(
    db: AsyncSession, user: User, args: CommitDHCPImportArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="commit_dhcp_import", args=args)


# ── NetBox IPAM import — live-pull one-shot commit (#36) ──────────────


@register_tool(
    name="propose_commit_netbox_import",
    permission="superadmin",
    description=(
        "Prepare a one-shot NetBox import into IPAM. Pass base_url + "
        "token (+ verify_tls, space_strategy 'per_vrf'/'single', optional "
        "target_space_id and scope filters vrf_id / tenant_id / status / "
        "family / within_include). Preview shows entity counts + conflicts "
        "(conflicts are SKIPPED on apply); operator clicks Approve to "
        "commit. Superadmin; makes an off-prem pull and creates IPAM rows."
    ),
    args_model=CommitNetboxImportArgs,
    writes=False,
    category="ipam",
    default_enabled=False,
    module="ipam.import.netbox",
)
async def propose_commit_netbox_import(
    db: AsyncSession, user: User, args: CommitNetboxImportArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="commit_netbox_import", args=args)


# ── New-device watch proposals (issue #459) ──────────────────────────────────


@register_tool(
    name="propose_acknowledge_device",
    permission=("write", "ip_address"),
    description=(
        "Prepare a proposal to acknowledge (dismiss) a new-device sighting so it "
        "stops raising the new_mac_seen alert. Pass the sighting_id from "
        "find_new_devices. Operator must click Approve. Returns a kind='proposal' "
        "card; never call twice for the same change."
    ),
    args_model=AcknowledgeDeviceArgs,
    writes=False,
    category="ipam",
    default_enabled=True,
    module="security.new_device_watch",
)
async def propose_acknowledge_device(
    db: AsyncSession, user: User, args: AcknowledgeDeviceArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="acknowledge_device", args=args)


@register_tool(
    name="propose_allowlist_mac",
    permission=("write", "ip_address"),
    description=(
        "Prepare a proposal to add a MAC (or OUI prefix like '00:50:56' for a "
        "whole vendor) to the trusted allowlist so it never raises a new-device "
        "alert and matching sightings become 'known'. Operator must click "
        "Approve. Returns a kind='proposal' card; never call twice."
    ),
    args_model=AllowlistMacArgs,
    writes=False,
    category="ipam",
    default_enabled=True,
    module="security.new_device_watch",
)
async def propose_allowlist_mac(
    db: AsyncSession, user: User, args: AllowlistMacArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="allowlist_mac", args=args)


@register_tool(
    name="propose_block_mac",
    permission=("write", "dhcp_mac_block"),
    description=(
        "Prepare a proposal to block a MAC from getting a DHCP lease (creates a "
        "dhcp_mac_block in one or every server group) — arpwatch with teeth. Pass "
        "mac_address and optionally group_id. Operator must click Approve. "
        "Returns a kind='proposal' card; never call twice."
    ),
    args_model=BlockMacArgs,
    writes=False,
    category="dhcp",
    default_enabled=True,
    module="security.new_device_watch",
)
async def propose_block_mac(db: AsyncSession, user: User, args: BlockMacArgs) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="block_mac", args=args)
