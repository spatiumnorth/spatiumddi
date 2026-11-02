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

from app.services.integration_ownership import INTEGRATION_OWNERSHIP_FKS

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
    # The opt-out from the auto reverse zone (#2735): dropping it makes the
    # first named address create a zone the operator declined (#2978).
    "skip_reverse_zone",
)

# Merge sources that disagree on these are refused: they say who owns the
# subnet / where it lives, and silently picking one is a wrong answer.
HARD_MERGE_COLUMNS: tuple[str, ...] = ("kind", "customer_id", "site_id")

# Columns a merge takes from the target without any special handling. Sources
# that disagree on one get a preview warning naming each value and the one
# kept, so the operator sees what Confirm merge discards (#3326).
TARGET_WINS_COLUMNS: tuple[str, ...] = (
    "tags",
    "custom_fields",
    "vxlan_id",
    "domain_name",
    "dns_servers",
    "dns_group_ids",
    "dns_additional_zone_ids",
    "ipv6_allocation_policy",
)

# Of those, the id lists whose order means nothing. ``dns_servers`` is not one:
# its order is the resolver order handed to clients.
_UNORDERED_LIST_COLUMNS: frozenset[str] = frozenset({"dns_group_ids", "dns_additional_zone_ids"})

# A warning names each value; a custom-fields dict can be large, so each shown
# value is cut to this many characters.
_SHOWN_VALUE_MAX = 120

# Columns that identify a subnet as mirrored by an integration or imported.
NOT_CARRIED_PROVENANCE: tuple[str, ...] = (
    *sorted(INTEGRATION_OWNERSHIP_FKS),
    "import_source",
)


def _comparable(column: str, value: Any) -> Any:
    """``value`` as compared for a disagreement: empty and unset are one answer
    (None vs {} vs []), and an unordered id list compares as a set."""
    if not value:
        return None
    if column in _UNORDERED_LIST_COLUMNS and isinstance(value, list):
        return sorted(str(v) for v in value)
    return value


def _shown(column: str, value: Any) -> str:
    """A bounded, stable rendering of ``value`` for a warning."""
    value = _comparable(column, value)
    if isinstance(value, dict):
        value = dict(sorted(value.items()))
    text = repr(value)
    if len(text) > _SHOWN_VALUE_MAX:
        text = text[: _SHOWN_VALUE_MAX - 3] + "..."
    return text


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
    for c in TARGET_WINS_COLUMNS:
        norm = [_comparable(c, getattr(s, c)) for s in sources]
        if all(v == norm[0] for v in norm):
            continue
        shown = sorted({_shown(c, getattr(s, c)) for s in sources})
        warnings.append(
            f"Sources disagree on {c}: {', '.join(shown)}. The merged subnet "
            f"takes the target's value ({_shown(c, getattr(target, c))}); the "
            "other sources' values are not kept."
        )
    if any(getattr(s, c) for s in sources for c in NOT_CARRIED_PROVENANCE):
        warnings.append(
            "At least one source is owned by an integration or was imported; the "
            "merged subnet is a new row and does not carry that ownership or "
            "import provenance."
        )
    return conflicts, warnings
