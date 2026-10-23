"""Which Subnet columns a split / merge carries onto its result (#2414).

Split and merge build NEW subnet rows. A fixed column copy used to leave
every column it did not name at the model default, so a PCI / HIPAA /
internet-facing / do-not-probe subnet came back unscoped and probed by the
discovery sweep. The column set lives here, once, so both services (and
their previews) agree.

Deliberately NOT carried (the result is a different subnet, not the same
one): ``network`` / ``name`` / ``description`` / ``gateway`` (each service
handles those), the utilisation counters, ``last_discovery_at``, the
integration-owner foreign keys (a reconciler owns the row it mirrored, not
its offspring), ``kubernetes_semantics`` with them, and the NetBox import
provenance.
"""

from __future__ import annotations

from typing import Any

# Columns copied verbatim: split children take the parent's value; merge
# takes the target's (and reports sources that disagree).
CARRIED_COLUMNS: tuple[str, ...] = (
    "kind",
    "dns_split_horizon",
    "auto_profile_on_dhcp_lease",
    "auto_profile_preset",
    "auto_profile_refresh_days",
    "discovery_enabled",
    "discovery_interval_minutes",
    "show_free_ranges",
    "decom_date",
    "subnet_role",
    "bgp_should_advertise",
    "customer_id",
    "site_id",
    "applied_template_id",
)

# Safe-union flags: a merge result carries the flag when ANY source has it.
# Dropping a compliance scope or a do-not-probe on merge is the unsafe
# direction; adding one is reversible by the operator.
UNION_FLAGS: tuple[str, ...] = (
    "pci_scope",
    "hipaa_scope",
    "internet_facing",
    "do_not_probe",
)

# Merge sources that disagree on these are refused: they say who owns the
# subnet / where it lives, and silently picking one is a wrong answer.
HARD_MERGE_COLUMNS: tuple[str, ...] = ("kind", "customer_id", "site_id")

# Columns that identify a subnet as mirrored by an integration or imported.
NOT_CARRIED_PROVENANCE: tuple[str, ...] = (
    "kubernetes_cluster_id",
    "docker_host_id",
    "proxmox_node_id",
    "tailscale_tenant_id",
    "unifi_controller_id",
    "cloud_endpoint_id",
    "opnsense_router_id",
    "netbird_instance_id",
    "panos_firewall_id",
    "fortinet_firewall_id",
    "meraki_org_id",
    "import_source",
)


def split_inherited(parent: Any) -> dict[str, Any]:
    """Compliance / discovery / ownership settings a split child inherits."""
    out: dict[str, Any] = {c: getattr(parent, c) for c in CARRIED_COLUMNS}
    for c in UNION_FLAGS:
        out[c] = getattr(parent, c)
    out["do_not_probe_reason"] = parent.do_not_probe_reason
    return out


def merged_carried(sources: list[Any], target: Any) -> dict[str, Any]:
    """Carried settings for a merge result: target's values, flags unioned."""
    out: dict[str, Any] = {c: getattr(target, c) for c in CARRIED_COLUMNS}
    for c in UNION_FLAGS:
        out[c] = any(bool(getattr(s, c)) for s in sources)
    reasons: list[str] = []
    for s in sources:
        r = (s.do_not_probe_reason or "").strip()
        if r and r not in reasons:
            reasons.append(r)
    out["do_not_probe_reason"] = "; ".join(reasons)
    return out


def merge_conflicts_and_warnings(sources: list[Any]) -> tuple[list[tuple[str, str]], list[str]]:
    """``(conflicts, warnings)`` for a merge's source set.

    Conflicts are ``(column, detail)`` for the hard columns; warnings name
    every other disagreement and how it resolves.
    """
    conflicts: list[tuple[str, str]] = []
    warnings: list[str] = []
    target = sources[0]
    for c in HARD_MERGE_COLUMNS:
        vals = {repr(getattr(s, c)) for s in sources}
        if len(vals) > 1:
            conflicts.append(
                (
                    c,
                    f"Sources disagree on {c}: {', '.join(sorted(vals))}. "
                    "Bring them into agreement before merging.",
                )
            )
    for c in UNION_FLAGS:
        vals = [bool(getattr(s, c)) for s in sources]
        if any(vals) and not all(vals):
            warnings.append(
                f"Sources disagree on {c}; the merged subnet will have {c} = true "
                "because at least one source does."
            )
    for c in CARRIED_COLUMNS:
        if c in HARD_MERGE_COLUMNS:
            continue
        vals = {repr(getattr(s, c)) for s in sources}
        if len(vals) > 1:
            warnings.append(
                f"Sources disagree on {c}: {', '.join(sorted(vals))}. The merged "
                f"subnet takes the target's value ({getattr(target, c)!r})."
            )
    if any(getattr(s, c) for s in sources for c in NOT_CARRIED_PROVENANCE):
        warnings.append(
            "At least one source is owned by an integration or was imported; the "
            "merged subnet is a new row and does not carry that ownership or "
            "import provenance."
        )
    return conflicts, warnings
